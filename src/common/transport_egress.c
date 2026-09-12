#include "transport_egress.h"

#include "portable_sockets.h"
#include "transport_udp.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define TRANSPORT_EGRESS_BATCH 64U

bool transport_egress_init(transport_egress_t *egress, size_t max_packets,
                           size_t max_bytes) {
  if (!egress || max_packets == 0 || max_bytes == 0)
    return false;
  memset(egress, 0, sizeof(*egress));
  egress->packets = calloc(max_packets, sizeof(*egress->packets));
  if (!egress->packets)
    return false;
  egress->capacity = max_packets;
  egress->max_bytes = max_bytes;
  return true;
}

void transport_egress_destroy(transport_egress_t *egress) {
  if (!egress)
    return;
  for (size_t i = 0; i < egress->count; i++) {
    size_t slot = (egress->head + i) % egress->capacity;
    free(egress->packets[slot].data);
  }
  egress->packets_dropped += egress->count;
  free(egress->packets);
  memset(egress, 0, sizeof(*egress));
}

bool transport_egress_can_accept(const transport_egress_t *egress,
                                 size_t packets, size_t bytes) {
  return egress && packets <= egress->capacity - egress->count &&
         bytes <= egress->max_bytes - egress->bytes;
}

static bool queue_remaining(transport_egress_t *egress,
                            const struct sockaddr *destination,
                            socklen_t destination_len,
                            const struct iovec *datagrams, size_t first,
                            size_t count) {
  size_t bytes = 0;
  for (size_t i = first; i < count; i++) {
    if (datagrams[i].iov_len > SIZE_MAX - bytes)
      return false;
    bytes += datagrams[i].iov_len;
  }
  if (!transport_egress_can_accept(egress, count - first, bytes)) {
    egress->packets_dropped += count - first;
    return false;
  }

  size_t queued = 0;
  for (size_t i = first; i < count; i++) {
    uint8_t *copy = malloc(datagrams[i].iov_len);
    if (!copy) {
      while (queued > 0) {
        size_t tail = (egress->head + egress->count - 1U) % egress->capacity;
        egress->bytes -= egress->packets[tail].size;
        free(egress->packets[tail].data);
        memset(&egress->packets[tail], 0, sizeof(egress->packets[tail]));
        egress->count--;
        queued--;
      }
      egress->packets_dropped += count - first;
      return false;
    }
    memcpy(copy, datagrams[i].iov_base, datagrams[i].iov_len);
    size_t tail = (egress->head + egress->count) % egress->capacity;
    transport_egress_packet_t *packet = &egress->packets[tail];
    packet->destination_len = destination_len;
    memcpy(&packet->destination, destination, destination_len);
    packet->data = copy;
    packet->size = datagrams[i].iov_len;
    egress->count++;
    egress->bytes += packet->size;
    queued++;
  }
  egress->packets_queued += queued;
  egress->bytes_queued += bytes;
  if (egress->count > egress->peak_count)
    egress->peak_count = egress->count;
  if (egress->bytes > egress->peak_bytes)
    egress->peak_bytes = egress->bytes;
  return true;
}

bool transport_egress_submit(transport_egress_t *egress, int fd,
                             const struct sockaddr *destination,
                             socklen_t destination_len,
                             const struct iovec *datagrams, size_t count) {
  if (!egress || fd < 0 || !destination || (!datagrams && count > 0) ||
      destination_len > sizeof(struct sockaddr_storage))
    return false;
  if (count == 0)
    return true;

  size_t first = 0;
  if (egress->count == 0) {
    ssize_t sent = transport_udp_send_batch(fd, destination, destination_len,
                                            datagrams, count);
    if (sent < 0) {
      egress->send_errors++;
      int error = SOCKET_ERROR_CODE;
      if (error != SOCKET_EAGAIN && error != SOCKET_EWOULDBLOCK &&
          error != SOCKET_EINTR)
        return false;
      egress->would_block++;
    } else {
      first = (size_t)sent;
      for (size_t i = 0; i < first; i++) {
        egress->packets_sent++;
        egress->bytes_sent += datagrams[i].iov_len;
      }
      if (first < count)
        egress->would_block++;
    }
  }
  return first == count || queue_remaining(egress, destination, destination_len,
                                           datagrams, first, count);
}

bool transport_egress_flush(transport_egress_t *egress, int fd) {
  if (!egress || fd < 0)
    return false;
  bool success = true;
  size_t budget = TRANSPORT_EGRESS_BATCH;
  while (egress->count > 0 && budget > 0) {
    struct iovec datagrams[TRANSPORT_EGRESS_BATCH];
    size_t batch = egress->count < budget ? egress->count : budget;
    transport_egress_packet_t *first = &egress->packets[egress->head];
    size_t compatible = 0;
    while (compatible < batch) {
      size_t slot = (egress->head + compatible) % egress->capacity;
      transport_egress_packet_t *packet = &egress->packets[slot];
      if (packet->destination_len != first->destination_len ||
          memcmp(&packet->destination, &first->destination,
                 first->destination_len) != 0)
        break;
      datagrams[compatible].iov_base = packet->data;
      datagrams[compatible].iov_len = packet->size;
      compatible++;
    }

    ssize_t sent = transport_udp_send_batch(
        fd, (const struct sockaddr *)&first->destination,
        first->destination_len, datagrams, compatible);
    if (sent < 0) {
      int error = SOCKET_ERROR_CODE;
      if (error == SOCKET_EAGAIN || error == SOCKET_EWOULDBLOCK ||
          error == SOCKET_EINTR) {
        egress->would_block++;
        return success;
      }
      egress->send_errors++;
      /* A hard error applies to the first unsent datagram. Retaining it
       * forever would block unrelated connections sharing this socket.
       * QUIC/FEC recovery owns retransmission of the dropped datagram. */
      egress->packets_dropped++;
      egress->bytes -= first->size;
      free(first->data);
      memset(first, 0, sizeof(*first));
      egress->head = (egress->head + 1U) % egress->capacity;
      egress->count--;
      budget--;
      success = false;
      continue;
    }
    if (sent == 0) {
      egress->would_block++;
      return success;
    }
    for (size_t i = 0; i < (size_t)sent; i++) {
      transport_egress_packet_t *packet = &egress->packets[egress->head];
      egress->packets_sent++;
      egress->bytes_sent += packet->size;
      egress->bytes -= packet->size;
      free(packet->data);
      memset(packet, 0, sizeof(*packet));
      egress->head = (egress->head + 1U) % egress->capacity;
      egress->count--;
      budget--;
    }
    if ((size_t)sent < compatible) {
      egress->would_block++;
      return success;
    }
  }
  return success;
}
