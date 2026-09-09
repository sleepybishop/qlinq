#ifndef QLINQ_TRANSPORT_PATHS_H
#define QLINQ_TRANSPORT_PATHS_H

#include "pathflow.h"

#include "quicly.h"

#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>

#define TRANSPORT_MAX_QUIC_PATHS 64U

/* Match the same interface identity as link lookup (IPv6 scope included;
 * transport ports do not identify a physical link). */
bool transport_path_matches_local(const quicly_path_stats_t *stats,
                                  const struct sockaddr_storage *local);

/* Both lookup helpers return SIZE_MAX when no QUIC path matches. */
size_t transport_path_find_by_addresses(quicly_conn_t *quic,
                                        const struct sockaddr *local,
                                        const struct sockaddr *remote);
size_t transport_path_find_by_link(quicly_conn_t *quic,
                                   const struct sockaddr_storage *local_addrs,
                                   size_t num_local_addrs, size_t link_index);
/* Return the matching path and the statistics already read during lookup.
 * Statistics are valid only when the return value is not SIZE_MAX. */
size_t transport_path_get_stats_by_link(
    quicly_conn_t *quic, const struct sockaddr_storage *local_addrs,
    size_t num_local_addrs, size_t link_index, quicly_path_stats_t *stats);
size_t transport_path_select_physical(const path_t *paths, size_t num_paths,
                                      size_t packet_index);
/* Prefer an exact local source address, then a wildcard socket of that family.
 */
size_t
transport_path_socket_for_source(const struct sockaddr_storage *local_addrs,
                                 size_t num_local_addrs,
                                 const struct sockaddr *source);
/* Resolve a usable QUIC path to its physical socket and remote endpoint. */
size_t transport_path_socket_for_peer(
    quicly_conn_t *quic, const struct sockaddr_storage *local_addrs,
    size_t num_local_addrs, struct sockaddr_storage *destination);

#endif
