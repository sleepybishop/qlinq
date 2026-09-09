#ifndef QLINQ_TRANSPORT_UDP_H
#define QLINQ_TRANSPORT_UDP_H

#include <stddef.h>
#include <sys/socket.h>
#include <sys/uio.h>

/* Returns the number of complete datagrams sent. A short result means the
 * socket would block. Returns -1 only when no datagram was sent and a hard
 * socket error occurred. */
ssize_t transport_udp_send_batch(int fd, const struct sockaddr *destination,
                                 socklen_t destination_len,
                                 const struct iovec *datagrams, size_t count);

/* Single datagram with an explicit source address/interface, including on a
 * wildcard-bound socket. Same complete-datagram return convention as above. */
ssize_t transport_udp_send_from(int fd, const struct sockaddr *destination,
                                const struct sockaddr *source,
                                unsigned interface_index,
                                const struct iovec *datagram);

#endif
