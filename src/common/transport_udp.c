#include "transport_udp.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define TRANSPORT_UDP_MAX_BATCH 64U
#define TRANSPORT_UDP_GSO_BUFFER_SIZE 65536U

#ifdef __linux__
#include <netinet/udp.h>

#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif

static bool try_gso(int fd, const struct sockaddr *destination,
                    socklen_t destination_len, const struct iovec *datagrams,
                    size_t count) {
  if (count < 2 || datagrams[0].iov_len == 0 ||
      datagrams[0].iov_len > UINT16_MAX)
    return false;
  size_t segment_size = datagrams[0].iov_len;
  size_t total_size = 0;
  for (size_t i = 0; i < count; i++) {
    /* GSO cannot preserve an empty datagram or a tail larger than its segment
     * size. Use sendmmsg for those batches rather than splitting or dropping
     * an application datagram. */
    if (datagrams[i].iov_len == 0 || datagrams[i].iov_len > segment_size ||
        (i + 1U < count && datagrams[i].iov_len != segment_size) ||
        datagrams[i].iov_len > SIZE_MAX - total_size)
      return false;
    total_size += datagrams[i].iov_len;
  }
  if (total_size > TRANSPORT_UDP_GSO_BUFFER_SIZE)
    return false;
  uint8_t buffer[TRANSPORT_UDP_GSO_BUFFER_SIZE];
  size_t offset = 0;
  for (size_t i = 0; i < count; i++) {
    memcpy(buffer + offset, datagrams[i].iov_base, datagrams[i].iov_len);
    offset += datagrams[i].iov_len;
  }

  struct iovec iov = {.iov_base = buffer, .iov_len = total_size};
  uint8_t control[CMSG_SPACE(sizeof(uint16_t))] = {0};
  struct msghdr message = {.msg_name = (void *)destination,
                           .msg_namelen = destination_len,
                           .msg_iov = &iov,
                           .msg_iovlen = 1,
                           .msg_control = control,
                           .msg_controllen = sizeof(control)};
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
  cmsg->cmsg_level = SOL_UDP;
  cmsg->cmsg_type = UDP_SEGMENT;
  cmsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));
  uint16_t value = (uint16_t)segment_size;
  memcpy(CMSG_DATA(cmsg), &value, sizeof(value));

  ssize_t sent;
  do {
    sent = sendmsg(fd, &message, 0);
  } while (sent < 0 && errno == EINTR);
  return sent == (ssize_t)total_size;
}
#endif

ssize_t transport_udp_send_batch(int fd, const struct sockaddr *destination,
                                 socklen_t destination_len,
                                 const struct iovec *datagrams, size_t count) {
  if (fd < 0 || !destination || (!datagrams && count > 0)) {
    errno = EINVAL;
    return -1;
  }
  if (count == 0)
    return 0;
  if (count > TRANSPORT_UDP_MAX_BATCH) {
    errno = E2BIG;
    return -1;
  }

#ifdef __linux__
  if (try_gso(fd, destination, destination_len, datagrams, count))
    return (ssize_t)count;

  struct mmsghdr messages[TRANSPORT_UDP_MAX_BATCH];
  struct iovec iovs[TRANSPORT_UDP_MAX_BATCH];
  memset(messages, 0, sizeof(messages));
  for (size_t i = 0; i < count; i++) {
    iovs[i] = datagrams[i];
    messages[i].msg_hdr.msg_name = (void *)destination;
    messages[i].msg_hdr.msg_namelen = destination_len;
    messages[i].msg_hdr.msg_iov = &iovs[i];
    messages[i].msg_hdr.msg_iovlen = 1;
  }
  size_t sent_count = 0;
  while (sent_count < count) {
    int sent = sendmmsg(fd, messages + sent_count,
                        (unsigned int)(count - sent_count), 0);
    if (sent > 0) {
      sent_count += (size_t)sent;
      continue;
    }
    if (sent < 0 && errno == EINTR)
      continue;
    if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
      return (ssize_t)sent_count;
    return sent_count > 0 ? (ssize_t)sent_count : -1;
  }
  return (ssize_t)sent_count;
#else
  size_t sent_count = 0;
  for (size_t i = 0; i < count; i++) {
    ssize_t sent;
    do {
      sent = sendto(fd, datagrams[i].iov_base, datagrams[i].iov_len, 0,
                    destination, destination_len);
    } while (sent < 0 && errno == EINTR);
    if (sent < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return (ssize_t)sent_count;
      return sent_count > 0 ? (ssize_t)sent_count : -1;
    }
    if ((size_t)sent != datagrams[i].iov_len) {
      errno = EIO;
      return sent_count > 0 ? (ssize_t)sent_count : -1;
    }
    sent_count++;
  }
  return (ssize_t)sent_count;
#endif
}
