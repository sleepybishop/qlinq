#include "transport_egress.h"
#include "transport_udp.h"
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>

static int failure;
static size_t calls;

/* A deterministic socket boundary: no privileges or timing assumptions. */
ssize_t transport_udp_send_batch(int fd, const struct sockaddr *destination,
                                 socklen_t destination_len,
                                 const struct iovec *datagrams, size_t count) {
  (void)fd;
  (void)destination_len;
  (void)datagrams;
  calls++;
  if (failure == EAGAIN)
    return 0;
  if (failure == EINTR ||
      (failure == ENETUNREACH &&
       ((const struct sockaddr_in *)destination)->sin_port == htons(1))) {
    errno = failure;
    return -1;
  }
  return (ssize_t)count;
}

int main(void) {
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
