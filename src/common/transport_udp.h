#ifndef QLINQ_TRANSPORT_UDP_H
#define QLINQ_TRANSPORT_UDP_H

#include <stddef.h>
#include <sys/socket.h>
#include <sys/uio.h>

/* Returns the number of complete datagrams sent. On a short result, retry
 * only the unsent suffix; an error can occur after partial progress. Returns -1
 * only when no datagram was sent and a hard socket error occurred. */
ssize_t transport_udp_send_batch(int fd, const struct sockaddr *destination,
                                 socklen_t destination_len,
                                 const struct iovec *datagrams, size_t count);

#endif
