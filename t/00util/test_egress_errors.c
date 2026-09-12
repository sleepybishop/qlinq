#include "transport_egress.h"
#include "transport_udp.h"
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

static int failure;
static size_t calls;
static bool inspect_payloads;
static size_t send_allowance, next_sequence, expected_size;

/* A deterministic socket boundary: no privileges or timing assumptions. */
ssize_t transport_udp_send_batch(int fd, const struct sockaddr *destination,
                                 socklen_t destination_len,
                                 const struct iovec *datagrams, size_t count) {
  (void)fd;
  (void)destination_len;
  calls++;
  if (failure == EAGAIN)
    return 0;
  if (failure == EINTR ||
      (failure == ENETUNREACH &&
       ((const struct sockaddr_in *)destination)->sin_port == htons(1))) {
    errno = failure;
    return -1;
  }
  if (inspect_payloads) {
    if (count > send_allowance)
      count = send_allowance;
    for (size_t i = 0; i < count; ++i) {
      assert(datagrams[i].iov_len == expected_size);
      const uint8_t *bytes = datagrams[i].iov_base;
      for (size_t j = 0; j < expected_size; ++j)
        assert(bytes[j] == (uint8_t)(next_sequence + j * 13));
      next_sequence++;
    }
    send_allowance -= count;
  }
  return (ssize_t)count;
}

static void submit_sequence(transport_egress_t *egress,
                            const struct sockaddr_in *destination,
                            size_t sequence, size_t size) {
  uint8_t bytes[64];
  assert(size <= sizeof(bytes));
  for (size_t i = 0; i < size; ++i)
    bytes[i] = (uint8_t)(sequence + i * 13);
  struct iovec vec = {.iov_base = bytes, .iov_len = size};
  assert(transport_egress_submit(egress, 1,
                                 (const struct sockaddr *)destination,
                                 sizeof(*destination), &vec, 1));
  /* Queuing must copy the caller's storage. The stub checks original bytes
   * when the queued payload eventually reaches the socket boundary. */
  memset(bytes, 0, sizeof(bytes));
}

static void test_queue_pressure(bool byte_pressure) {
  transport_egress_t egress;
  const size_t capacity = 128;
  const size_t size = byte_pressure ? 64 : 32;
  const size_t accepted = byte_pressure ? 64 : capacity;
  const size_t byte_limit = byte_pressure ? 4096 : 8192;
  struct sockaddr_in destination = {.sin_family = AF_INET,
                                    .sin_port = htons(2)};
  assert(transport_egress_init(&egress, capacity, byte_limit));
  failure = EAGAIN;
  inspect_payloads = false;
  for (size_t i = 0; i < accepted; ++i)
    submit_sequence(&egress, &destination, i, size);
  assert(egress.count == accepted && egress.bytes == accepted * size);
  uint8_t extra[64] = {0};
  struct iovec vec = {.iov_base = extra, .iov_len = size};
  assert(!transport_egress_submit(&egress, 1, (struct sockaddr *)&destination,
                                  sizeof(destination), &vec, 1));
  assert(egress.packets_dropped == 1 && egress.count == accepted &&
         egress.bytes == accepted * size && egress.peak_count == accepted &&
         egress.peak_bytes == accepted * size);
  uint8_t *originals[128];
  for (size_t i = 0; i < accepted; ++i)
    originals[i] = egress.packets[i].data;
  for (size_t retry = 0; retry < 32; ++retry) {
    assert(transport_egress_flush(&egress, 1));
    assert(egress.count == accepted && egress.bytes == accepted * size);
    for (size_t i = 0; i < accepted; ++i)
      assert(egress.packets[i].data == originals[i]);
  }
  failure = 0;
  inspect_payloads = true;
  expected_size = size;
  next_sequence = 0;
  send_allowance = 3;
  assert(transport_egress_flush(&egress, 1));
  assert(next_sequence == 3 && egress.count == accepted - 3 &&
         egress.bytes == (accepted - 3) * size && egress.head == 3);
  for (size_t i = accepted; i < accepted + 3; ++i)
    submit_sequence(&egress, &destination, i, size);
  assert(egress.count == accepted && egress.bytes == accepted * size);
  send_allowance = SIZE_MAX;
  while (egress.count)
    assert(transport_egress_flush(&egress, 1));
  assert(next_sequence == accepted + 3 && !egress.bytes &&
         egress.packets_sent == accepted + 3 && egress.packets_dropped == 1 &&
         egress.peak_count == accepted && egress.peak_bytes == accepted * size);
  for (size_t i = 0; i < egress.capacity; ++i)
    assert(!egress.packets[i].data);
  /* Refill at the wrapped head, then abandon every retained payload. */
  failure = EAGAIN;
  inspect_payloads = false;
  for (size_t i = 0; i < accepted; ++i)
    submit_sequence(&egress, &destination, i, size);
  printf("egress pressure: limit=%s entries=%zu payload_bytes=%zu "
         "array_bytes=%zu blocked_retries=32 exact_sent=%zu\n",
         byte_pressure ? "bytes" : "count", egress.peak_count,
         egress.peak_bytes, egress.capacity * sizeof(*egress.packets),
         next_sequence);
  transport_egress_destroy(&egress);
  assert(!egress.packets && !egress.count && !egress.bytes && !egress.capacity);
}

int main(void) {
  test_queue_pressure(false);
  test_queue_pressure(true);
  transport_egress_t egress;
  assert(transport_egress_init(&egress, 128, 4096));
  struct sockaddr_in bad = {.sin_family = AF_INET, .sin_port = htons(1)};
  struct sockaddr_in good = {.sin_family = AF_INET, .sin_port = htons(2)};
  char bytes[] = "packet";
  struct iovec vec = {.iov_base = bytes, .iov_len = sizeof(bytes)};
  failure = EAGAIN;
  assert(transport_egress_submit(&egress, 1, (struct sockaddr *)&bad,
                                 sizeof(bad), &vec, 1));
  assert(transport_egress_submit(&egress, 1, (struct sockaddr *)&good,
                                 sizeof(good), &vec, 1));
  assert(egress.count == 2);
  failure = EINTR;
  assert(transport_egress_flush(&egress, 1));
  assert(egress.count == 2 && egress.packets_dropped == 0);
  failure = ENETUNREACH;
  assert(!transport_egress_flush(&egress, 1));
  assert(egress.count == 0 && egress.bytes == 0);
  assert(egress.packets_dropped == 1 && egress.packets_sent == 1);
  assert(egress.send_errors == 1 && egress.bytes_sent == sizeof(bytes));
  failure = EAGAIN;
  for (size_t i = 0; i < 100; i++)
    assert(transport_egress_submit(&egress, 1, (struct sockaddr *)&bad,
                                   sizeof(bad), &vec, 1));
  failure = ENETUNREACH;
  calls = 0;
  assert(!transport_egress_flush(&egress, 1));
  assert(calls == 64 && egress.count == 36);
  assert(!transport_egress_flush(&egress, 1));
  assert(egress.count == 0 && egress.packets_dropped == 101);
  transport_egress_destroy(&egress);
  puts("===EGRESS ERRORS OK===");
  return 0;
}
