#include "transport_paths.h"

#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

static bool sockaddr_endpoint_equal(const struct sockaddr *a,
                                    const struct sockaddr *b) {
  if (!a || !b || a->sa_family != b->sa_family)
    return false;
  if (a->sa_family == AF_INET) {
    const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
    const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;
    return a4->sin_port == b4->sin_port &&
           a4->sin_addr.s_addr == b4->sin_addr.s_addr;
  }
  if (a->sa_family == AF_INET6) {
    const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
    const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
    return a6->sin6_port == b6->sin6_port &&
           a6->sin6_scope_id == b6->sin6_scope_id &&
           memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(a6->sin6_addr)) == 0;
  }
  return false;
}

static bool sockaddr_address_equal(const struct sockaddr *a,
                                   const struct sockaddr *b) {
  if (!a || !b || a->sa_family != b->sa_family)
    return false;
  if (a->sa_family == AF_INET)
    return ((const struct sockaddr_in *)a)->sin_addr.s_addr ==
           ((const struct sockaddr_in *)b)->sin_addr.s_addr;
  if (a->sa_family == AF_INET6) {
    const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
    const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
    return a6->sin6_scope_id == b6->sin6_scope_id &&
           memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(a6->sin6_addr)) == 0;
  }
  return false;
}

bool transport_path_matches_local(const quicly_path_stats_t *stats,
                                  const struct sockaddr_storage *local) {
  return stats && local &&
         sockaddr_address_equal(&stats->local.sa,
                                (const struct sockaddr *)local);
}

size_t transport_path_find_by_addresses(quicly_conn_t *quic,
                                        const struct sockaddr *local,
                                        const struct sockaddr *remote) {
  if (!quic || !local || !remote)
    return SIZE_MAX;
  for (size_t p = 0; p < TRANSPORT_MAX_QUIC_PATHS; p++) {
    quicly_path_stats_t stats;
    if (quicly_get_path_stats(quic, p, &stats) == 0 &&
        sockaddr_endpoint_equal(&stats.local.sa, local) &&
        sockaddr_endpoint_equal(&stats.remote.sa, remote))
      return p;
  }
  return SIZE_MAX;
}

size_t transport_path_find_by_link(quicly_conn_t *quic,
                                   const struct sockaddr_storage *local_addrs,
                                   size_t num_local_addrs, size_t link_index) {
  quicly_path_stats_t stats;
  return transport_path_get_stats_by_link(quic, local_addrs, num_local_addrs,
                                          link_index, &stats);
}

size_t transport_path_get_stats_by_link(
    quicly_conn_t *quic, const struct sockaddr_storage *local_addrs,
    size_t num_local_addrs, size_t link_index, quicly_path_stats_t *stats) {
  if (!quic || !local_addrs || !stats || link_index >= num_local_addrs)
    return SIZE_MAX;
  for (size_t p = 0; p < TRANSPORT_MAX_QUIC_PATHS; p++) {
    if (quicly_get_path_stats(quic, p, stats) == 0 &&
        transport_path_matches_local(stats, &local_addrs[link_index]))
      return p;
  }
  return SIZE_MAX;
}

size_t transport_path_select_physical(const path_t *paths, size_t num_paths,
                                      size_t packet_index) {
  if (!paths || num_paths == 0)
    return 0;
  size_t accumulated = 0;
  for (size_t i = 0; i < num_paths; i++) {
    accumulated += paths[i].x;
    if (packet_index < accumulated)
      return i;
  }
  return 0;
}

size_t
transport_path_socket_for_source(const struct sockaddr_storage *local_addrs,
                                 size_t num_local_addrs,
                                 const struct sockaddr *source) {
  if (!local_addrs || !source)
    return SIZE_MAX;
  size_t wildcard = SIZE_MAX;
  for (size_t i = 0; i < num_local_addrs; i++) {
    const struct sockaddr *local = (const struct sockaddr *)&local_addrs[i];
    if (sockaddr_address_equal(local, source))
      return i;
    if (local->sa_family != source->sa_family)
      continue;
    if ((local->sa_family == AF_INET &&
         ((const struct sockaddr_in *)local)->sin_addr.s_addr ==
             htonl(INADDR_ANY)) ||
        (local->sa_family == AF_INET6 &&
         IN6_IS_ADDR_UNSPECIFIED(
             &((const struct sockaddr_in6 *)local)->sin6_addr)))
      wildcard = i;
  }
  return wildcard;
}

size_t transport_path_socket_for_peer(
    quicly_conn_t *quic, const struct sockaddr_storage *local_addrs,
    size_t num_local_addrs, struct sockaddr_storage *destination) {
  if (!quic || !destination)
    return SIZE_MAX;
  for (size_t path = 0; path < TRANSPORT_MAX_QUIC_PATHS; path++) {
    quicly_path_stats_t stats;
    if (!quicly_is_path_available(quic, path) ||
        quicly_get_path_stats(quic, path, &stats) != 0)
      continue;
    size_t socket = transport_path_socket_for_source(
        local_addrs, num_local_addrs, &stats.local.sa);
    if (socket == SIZE_MAX)
      continue;
    memset(destination, 0, sizeof(*destination));
    memcpy(destination, &stats.remote.sa, quicly_get_socklen(&stats.remote.sa));
    return socket;
  }
  return SIZE_MAX;
}
