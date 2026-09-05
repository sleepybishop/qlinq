/* transport_quicly.c */

#include "fec.h"
#include "ifmon.h"
#include "pathflow.h"
#include "portable_sockets.h"
#include "transport.h"
#include "transport_config.h"
#include "transport_egress.h"
#include "transport_fec_state.h"
#include "transport_internal.h"
#include "transport_memory.h"
#include "transport_paths.h"
#include "transport_protocol.h"
#include "transport_publish.h"
#include "transport_repair.h"
#include "transport_scheduler.h"
#include "transport_stream.h"
#include "transport_subscriptions.h"
#include "transport_tls.h"
#include "transport_tracks.h"
#include "transport_udp.h"
#include "transport_wire.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#include <net/if.h>
#endif
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/sendstate.h"
#include "quicly/streambuf.h"

uint64_t transport_get_time_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

void transport_release_assembler(transport_t *t, frame_assembler_t *assembler) {
  if (!t || !assembler)
    return;
  size_t bytes = transport_assembler_capacity_bytes(assembler);
  if (bytes <= t->assembler_memory_bytes)
    t->assembler_memory_bytes -= bytes;
  else
    t->assembler_memory_bytes = 0;
  transport_assembler_release(assembler);
}

bool transport_grow_assembler(transport_t *t, frame_assembler_t *assembler,
                              uint16_t symbols, uint16_t symbol_size) {
  if (!t || !assembler)
    return false;
  size_t old_bytes = transport_assembler_capacity_bytes(assembler);
  size_t new_bytes = transport_assembler_required_bytes(symbols, symbol_size);
  if (assembler->capacity_symbols > symbols ||
      assembler->capacity_symbol_size > symbol_size) {
    uint16_t actual_symbols = assembler->capacity_symbols > symbols
                                  ? assembler->capacity_symbols
                                  : symbols;
    uint16_t actual_symbol_size = assembler->capacity_symbol_size > symbol_size
                                      ? assembler->capacity_symbol_size
                                      : symbol_size;
    new_bytes =
        transport_assembler_required_bytes(actual_symbols, actual_symbol_size);
  }
  size_t used_without_old = old_bytes <= t->assembler_memory_bytes
                                ? t->assembler_memory_bytes - old_bytes
                                : t->assembler_memory_bytes;
  /* Growth allocates replacement buffers before copying and freeing the old
   * ones. Reserve that transient allocation too; rejecting growth must leave
   * an incomplete object's symbols intact. Reusing capacity allocates nothing.
   */
  bool needs_allocation = !assembler->buffers ||
                          assembler->capacity_symbols < symbols ||
                          assembler->capacity_symbol_size < symbol_size;
  size_t additional_bytes = needs_allocation ? new_bytes : 0;
  if (t->assembler_memory_bytes > t->limits.max_assembler_memory_bytes ||
      additional_bytes >
          t->limits.max_assembler_memory_bytes - t->assembler_memory_bytes) {
    t->stats.resource_limit_errors++;
    return false;
  }
  if (!transport_assembler_grow(assembler, symbols, symbol_size))
    return false;
  t->assembler_memory_bytes =
      used_without_old + transport_assembler_capacity_bytes(assembler);
  return true;
}

bool transport_owner_ok(transport_t *t) {
  if (!t)
    return false;
  if (pthread_equal(t->owner_thread, pthread_self()))
    return !t->log_callback_active;
  atomic_fetch_add_explicit(&t->cross_thread_violations, 1,
                            memory_order_relaxed);
  return false;
}

void transport_emit_event(transport_t *t, const transport_event_t *event) {
  if (!t || !event)
    return;
  t->callback_depth++;
  t->stats.events_emitted++;
  t->callback(t->user_data, event);
  t->callback_depth--;
}

void transport_log(transport_t *t, transport_log_level_t level,
                   const char *component, uint32_t connection_id,
                   size_t path_index, const char *format, ...) {
  if (!t || !component || !format)
    return;
  char message[512];
  va_list args;
  va_start(args, format);
  (void)vsnprintf(message, sizeof(message), format, args);
  va_end(args);
  transport_log_event_t event = {.level = level,
                                 .component = component,
                                 .connection_id = connection_id,
                                 .path_index = path_index,
                                 .message = message};
  if (t->log_callback) {
    t->log_callback_active = true;
    t->log_callback(t->log_user_data, &event);
    t->log_callback_active = false;
  } else if (level >= TRANSPORT_LOG_WARNING) {
    const char *name = level == TRANSPORT_LOG_ERROR ? "error" : "warning";
    if (connection_id != 0 && path_index != SIZE_MAX)
      fprintf(stderr, "qlinq[%s] %s conn=%" PRIu32 " path=%zu: %s\n", component,
              name, connection_id, path_index, message);
    else if (connection_id != 0)
      fprintf(stderr, "qlinq[%s] %s conn=%" PRIu32 ": %s\n", component, name,
              connection_id, message);
    else if (path_index != SIZE_MAX)
      fprintf(stderr, "qlinq[%s] %s path=%zu: %s\n", component, name,
              path_index, message);
    else
      fprintf(stderr, "qlinq[%s] %s: %s\n", component, name, message);
  }
}

static bool transport_has_connection(const transport_t *t,
                                     const transport_conn_t *conn);

static void accumulate_egress_stats(transport_t *t,
                                    const transport_egress_t *egress,
                                    bool dropping_pending) {
  if (!t || !egress)
    return;
  t->stats.udp_packets_sent += egress->packets_sent;
  t->stats.udp_bytes_sent += egress->bytes_sent;
  t->stats.udp_would_block += egress->would_block;
  t->stats.udp_send_errors += egress->send_errors;
  t->stats.egress_packets_queued += egress->packets_queued;
  t->stats.egress_bytes_queued += egress->bytes_queued;
  t->stats.egress_packets_dropped +=
      egress->packets_dropped + (dropping_pending ? egress->count : 0U);
  if (egress->peak_count > t->stats.egress_peak_packets)
    t->stats.egress_peak_packets = egress->peak_count;
  if (egress->peak_bytes > t->stats.egress_peak_bytes)
    t->stats.egress_peak_bytes = egress->peak_bytes;
}

bool transport_queue_datagram(transport_conn_t *conn, size_t path_index,
                              ptls_iovec_t datagram) {
  quicly_path_stats_t path_stats;
  if (!conn || !conn->quic || path_index >= TRANSPORT_MAX_QUIC_PATHS ||
      quicly_get_path_stats(conn->quic, path_index, &path_stats) != 0 ||
      quicly_get_num_datagram_frames_path(conn->quic, path_index) >=
          QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY)
    return false;
  size_t before = quicly_get_num_datagram_frames_path(conn->quic, path_index);
  quicly_send_datagram_frames_path(conn->quic, path_index, &datagram, 1);
  size_t after = quicly_get_num_datagram_frames_path(conn->quic, path_index);
  conn->queued_datagrams[path_index] = (uint16_t)after;
  return after == before + 1U;
}

typedef struct {
  uint32_t index;
  char name[64];
  struct sockaddr_storage addr;
  socklen_t addr_len;
  int is_added;
} ifmon_pipe_msg_t;

static void copy_interface_name(char destination[64], const char *name) {
  if (!destination || !name)
    return;
  strncpy(destination, name, 63);
  destination[63] = '\0';
}

static quicly_error_t
qlinq_path_scheduler_send(quicly_path_scheduler_t *scheduler,
                          quicly_conn_t *quic,
                          quicly_send_context_t *send_context) {
  (void)scheduler;
  transport_conn_t *conn = *(transport_conn_t **)quicly_get_data(quic);
  if (!conn || !conn->transport)
    return 0;
  transport_t *t = conn->transport;
  for (size_t offset = 0; offset < TRANSPORT_MAX_QUIC_PATHS; offset++) {
    size_t path = (conn->round_robin_path + offset) % TRANSPORT_MAX_QUIC_PATHS;
    if (!quicly_is_path_available(quic, path))
      continue;
    bool has_socket = false;
    for (size_t physical = 0; physical < t->num_fds; physical++) {
      if (transport_path_find_by_link(quic, t->local_addrs, t->num_fds,
                                      physical) == path) {
        has_socket = true;
        break;
      }
    }
    if (!has_socket)
      continue;
    size_t packets_sent = 0;
    quicly_error_t ret =
        quicly_send_on_path(quic, send_context, path, &packets_sent);
    if (ret != 0)
      return ret;
    if (packets_sent != 0) {
      conn->round_robin_path = (path + 1U) % TRANSPORT_MAX_QUIC_PATHS;
      break;
    }
  }
  return 0;
}

static quicly_path_scheduler_t qlinq_path_scheduler = {
    qlinq_path_scheduler_send};

static bool ifmon_address_matches(const ifmon_addr_t *address,
                                  const struct sockaddr_storage *local) {
  if (!address || !local || address->family != local->ss_family)
    return false;
  if (address->family == AF_INET)
    return address->ip.v4.s_addr ==
           ((const struct sockaddr_in *)local)->sin_addr.s_addr;
  if (address->family == AF_INET6)
    return memcmp(&address->ip.v6,
                  &((const struct sockaddr_in6 *)local)->sin6_addr,
                  sizeof(address->ip.v6)) == 0;
  return false;
}

static void resolve_configured_interfaces(transport_t *t) {
  ifmon_list_t interfaces = {0};
  uint8_t scratchpad[IFMON_SCRATCHPAD_SIZE];
  if (!t || ifmon_list_get(&interfaces, scratchpad, sizeof(scratchpad)) != 0)
    return;
  for (size_t path = 0; path < t->num_fds; path++) {
    for (int i = 0; i < interfaces.count; i++) {
      const ifmon_iface_t *iface = &interfaces.ifaces[i];
      for (int a = 0; a < iface->addr_count; a++) {
        if (!ifmon_address_matches(&iface->addrs[a], &t->local_addrs[path]))
          continue;
        t->local_ifindices[path] = iface->index;
        copy_interface_name(t->local_ifnames[path], iface->name);
        break;
      }
      if (t->local_ifindices[path] != 0)
        break;
    }
  }
}

static void bind_to_device(int fd, uint32_t index) {
  if (index == 0)
    return;
#if defined(__linux__)
  char ifname[IF_NAMESIZE];
  if (if_indextoname(index, ifname)) {
    if (strncmp(ifname, "veth", 4) == 0)
      return;
    setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
  }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
#ifndef IP_BOUND_IF
#define IP_BOUND_IF 25
#endif
#ifndef IPV6_BOUND_IF
#define IPV6_BOUND_IF 125
#endif
  unsigned int idx = index;
  setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx));
  setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, sizeof(idx));
#elif defined(_WIN32)
  DWORD idx = index;
  setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF, (const char *)&idx, sizeof(idx));
  setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_IF, (const char *)&idx,
             sizeof(idx));
#endif
}

static void on_ifmon_update(const ifmon_update_t *update, void *userdata) {
  transport_t *t = userdata;

  if (update->is_initial) {
    /* For now, ignore initial snapshot since we bind via config->bind_hosts */
    return;
  }

  for (int i = 0; i < update->added_count; i++) {
    uint32_t idx = update->added[i];
    for (int j = 0; j < update->interfaces->count; j++) {
      if (update->interfaces->ifaces[j].index == idx) {
        const ifmon_iface_t *iface = &update->interfaces->ifaces[j];
        for (int k = 0; k < iface->addr_count; k++) {
          const ifmon_addr_t *a = &iface->addrs[k];
          ifmon_pipe_msg_t msg = {0};
          msg.index = idx;
          copy_interface_name(msg.name, iface->name);
          msg.is_added = 1;
          if (a->family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&msg.addr;
            sin->sin_family = AF_INET;
            sin->sin_addr = a->ip.v4;
            msg.addr_len = sizeof(*sin);
          } else {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&msg.addr;
            sin6->sin6_family = AF_INET6;
            sin6->sin6_addr = a->ip.v6;
            msg.addr_len = sizeof(*sin6);
          }
          ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
          (void)w;
        }
        break;
      }
    }
  }

  for (int i = 0; i < update->removed_count; i++) {
    ifmon_pipe_msg_t msg = {0};
    msg.index = update->removed[i];
    msg.is_added = 0;
    msg.addr.ss_family = AF_UNSPEC;
    ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
    (void)w;
  }

  for (int i = 0; i < update->modified_count; i++) {
    const ifmon_iface_diff_t *diff = &update->modified[i];

    if (diff->link_state_changed) {
      for (int k = 0; k < update->interfaces->count; k++) {
        const ifmon_iface_t *iface = &update->interfaces->ifaces[k];
        if (iface->index == diff->index) {
          for (int a_idx = 0; a_idx < iface->addr_count; a_idx++) {
            const ifmon_addr_t *a = &iface->addrs[a_idx];
            ifmon_pipe_msg_t msg = {0};
            msg.index = diff->index;
            copy_interface_name(msg.name, iface->name);
            msg.is_added = diff->is_up ? 1 : 0;
            if (a->family == AF_INET) {
              struct sockaddr_in *sin = (struct sockaddr_in *)&msg.addr;
              sin->sin_family = AF_INET;
              sin->sin_addr = a->ip.v4;
              msg.addr_len = sizeof(*sin);
            } else {
              struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&msg.addr;
              sin6->sin6_family = AF_INET6;
              sin6->sin6_addr = a->ip.v6;
              msg.addr_len = sizeof(*sin6);
            }
            ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
            (void)w;
          }
          break;
        }
      }
    }

    for (int j = 0; j < diff->addrs_added_count; j++) {
      const ifmon_addr_t *a = &diff->addrs_added[j];
      ifmon_pipe_msg_t msg = {0};
      msg.index = diff->index;
      msg.is_added = 1;
      for (int k = 0; k < update->interfaces->count; k++) {
        if (update->interfaces->ifaces[k].index == diff->index) {
          copy_interface_name(msg.name, update->interfaces->ifaces[k].name);
          break;
        }
      }
      if (a->family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&msg.addr;
        sin->sin_family = AF_INET;
        sin->sin_addr = a->ip.v4;
        msg.addr_len = sizeof(*sin);
      } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&msg.addr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = a->ip.v6;
        msg.addr_len = sizeof(*sin6);
      }
      ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
      (void)w;
    }

    for (int j = 0; j < diff->addrs_removed_count; j++) {
      const ifmon_addr_t *a = &diff->addrs_removed[j];
      ifmon_pipe_msg_t msg = {0};
      msg.index = diff->index;
      msg.is_added = 0;
      for (int k = 0; k < update->interfaces->count; k++) {
        if (update->interfaces->ifaces[k].index == diff->index) {
          copy_interface_name(msg.name, update->interfaces->ifaces[k].name);
          break;
        }
      }
      if (a->family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&msg.addr;
        sin->sin_family = AF_INET;
        sin->sin_addr = a->ip.v4;
        msg.addr_len = sizeof(*sin);
      } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&msg.addr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = a->ip.v6;
        msg.addr_len = sizeof(*sin6);
      }
      ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
      (void)w;
    }
  }
}

static bool set_fd_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static int open_unicast_socket(int family) {
  int fd = socket(family, SOCK_DGRAM, 0);
  if (fd >= 0 && family == AF_INET6) {
    /* A wildcard IPv6 path must not claim a separately configured IPv4 path's
     * port. Each physical socket and its address matching stay family-specific.
     */
    int v6_only = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof(v6_only)) !=
        0) {
      CLOSE_SOCKET(fd);
      return -1;
    }
  }
  return fd;
}

static void configure_socket_buffers(transport_t *t, int fd) {
  int buf_size = 2 * 1024 * 1024; /* 2mb buffer size */
  if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) != 0)
    transport_log(t, TRANSPORT_LOG_WARNING, "udp", 0, SIZE_MAX,
                  "unable to enlarge send buffer: %s", strerror(errno));
  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) != 0)
    transport_log(t, TRANSPORT_LOG_WARNING, "udp", 0, SIZE_MAX,
                  "unable to enlarge receive buffer: %s", strerror(errno));
}

#define QLINQ_PATH_OPEN_RETRY_MS 100U

static bool path_endpoint_families_match(const transport_t *t,
                                         size_t local_index,
                                         size_t remote_index) {
  return local_index < t->num_fds && remote_index < t->num_remote_addrs &&
         t->local_addrs[local_index].ss_family ==
             t->remote_addrs[remote_index].ss_family;
}

static bool path_interface_allowed(const transport_t *t, const char *name) {
  if (t->num_path_interface_names == 0)
    return true;
  for (size_t i = 0; i < t->num_path_interface_names; i++) {
    if (strcmp(t->path_interface_names[i], name) == 0)
      return true;
  }
  return false;
}

static void remove_connection_physical_slot(transport_t *t,
                                            size_t removed_index) {
  size_t count = t->is_server ? t->conn_count : (t->client_conn ? 1U : 0U);
  for (size_t c = 0; c < count; c++) {
    transport_conn_t *conn = t->is_server ? t->conns[c] : t->client_conn;
    if (!conn)
      continue;
    for (size_t i = removed_index; i + 1 < t->num_fds; i++) {
      conn->path_states[i] = conn->path_states[i + 1];
      conn->min_owd_ns[i] = conn->min_owd_ns[i + 1];
      conn->owd_initialized[i] = conn->owd_initialized[i + 1];
      conn->telemetry_path[i] = conn->telemetry_path[i + 1];
      conn->latest_owd_fp[i] = conn->latest_owd_fp[i + 1];
      conn->last_telemetry_s_ns[i] = conn->last_telemetry_s_ns[i + 1];
      conn->last_telemetry_r_ns[i] = conn->last_telemetry_r_ns[i + 1];
      conn->path_state_overridden[i] = conn->path_state_overridden[i + 1];
    }
    size_t last = t->num_fds - 1U;
    memset(&conn->path_states[last], 0, sizeof(conn->path_states[last]));
    conn->min_owd_ns[last] = 0;
    conn->owd_initialized[last] = false;
    conn->telemetry_path[last] = 0;
    conn->latest_owd_fp[last] = 0;
    conn->last_telemetry_s_ns[last] = 0;
    conn->last_telemetry_r_ns[last] = 0;
    conn->path_state_overridden[last] = false;
  }
}

static size_t select_remote_for_added_local(const transport_t *t,
                                            size_t local_index) {
  if (t->num_remote_addrs == 0)
    return SIZE_MAX;
  if (t->num_remote_addrs == 1)
    return path_endpoint_families_match(t, local_index, 0) ? 0 : SIZE_MAX;

  for (size_t remote_index = 0; remote_index < t->num_remote_addrs;
       remote_index++) {
    if (!path_endpoint_families_match(t, local_index, remote_index))
      continue;
    bool assigned = false;
    for (size_t i = 0; i < t->num_fds; i++) {
      if (i != local_index && t->local_remote_indices[i] == remote_index) {
        assigned = true;
        break;
      }
    }
    if (!assigned)
      return remote_index;
  }
  return SIZE_MAX;
}

static void try_open_pending_paths(transport_t *t, transport_conn_t *conn,
                                   uint64_t now) {
  if (!t || !conn || t->is_server || !conn->quic_ready)
    return;

  for (size_t local_index = 0; local_index < t->num_fds; local_index++) {
    if (!t->path_open_pending[local_index] ||
        now < t->path_open_retry_at[local_index])
      continue;
    size_t remote_index = t->local_remote_indices[local_index];
    if (!path_endpoint_families_match(t, local_index, remote_index)) {
      t->path_open_pending[local_index] = false;
      continue;
    }

    struct sockaddr *local = (struct sockaddr *)&t->local_addrs[local_index];
    struct sockaddr *remote = (struct sockaddr *)&t->remote_addrs[remote_index];
    if (transport_path_find_by_addresses(conn->quic, local, remote) !=
        SIZE_MAX) {
      t->path_open_pending[local_index] = false;
      continue;
    }

    quicly_error_t ret = quicly_open_path(conn->quic, remote, local);
    if (ret == 0) {
      t->path_open_pending[local_index] = false;
    } else if (ret == QUICLY_ERROR_PACKET_IGNORED) {
      /* The peer may not have supplied a path ID or CID yet. */
      t->path_open_retry_at[local_index] = now + QLINQ_PATH_OPEN_RETRY_MS;
    } else {
      transport_log(t, TRANSPORT_LOG_ERROR, "path", conn->id, local_index,
                    "unable to open QUIC path: %" PRId64, (int64_t)ret);
      t->path_open_pending[local_index] = false;
    }
  }
}

static void destroy_connection_subscriptions(transport_conn_t *conn) {
  transport_subscriptions_destroy(&conn->send_subscriptions);
  transport_subscriptions_destroy(&conn->receive_subscriptions);
}

static bool init_connection_subscriptions(transport_conn_t *conn,
                                          size_t capacity) {
  if (transport_subscriptions_init(&conn->send_subscriptions, capacity) &&
      transport_subscriptions_init(&conn->receive_subscriptions, capacity))
    return true;
  destroy_connection_subscriptions(conn);
  return false;
}

static bool start_client_connection(transport_t *t) {
  if (!t || t->is_server || t->num_remote_addrs == 0 || t->num_fds == 0 ||
      t->client_conn)
    return false;

  transport_conn_t *conn = calloc(1, sizeof(*conn));
  if (!conn)
    return false;
  conn->transport = t;
  conn->id = t->next_conn_id++;
  if (!init_connection_subscriptions(
          conn, t->limits.max_subscriptions_per_connection)) {
    free(conn);
    return false;
  }

  int ret = quicly_connect(&conn->quic, &t->quic_ctx, t->server_name,
                           (struct sockaddr *)&t->remote_addrs[0],
                           (struct sockaddr *)&t->local_addrs[0], &t->next_cid,
                           ptls_iovec_init(NULL, 0), NULL, NULL, NULL);
  if (ret != 0 || !conn->quic) {
    destroy_connection_subscriptions(conn);
    free(conn);
    return false;
  }
  /* Never reuse the client master CID. Reuse would let delayed packets from a
   * prior session authenticate against a replacement connection after a peer
   * restart. */
  t->next_cid.master_id++;
  *quicly_get_data(conn->quic) = conn;
  if (quicly_open_stream(conn->quic, &conn->stream, 0) != 0 || !conn->stream) {
    quicly_free(conn->quic);
    destroy_connection_subscriptions(conn);
    free(conn);
    return false;
  }

  t->client_conn = conn;
  for (size_t i = 1; i < t->num_fds; i++) {
    t->path_open_pending[i] = true;
    t->path_open_retry_at[i] = 0;
  }
  return true;
}

static void schedule_client_reconnect(transport_t *t, int64_t now_ms) {
  if (!t || t->is_server || !t->reconnect_enabled || t->shutting_down)
    return;
  t->reconnect_at_ms = now_ms + t->reconnect_current_delay_ms;
  if (t->reconnect_current_delay_ms < t->reconnect_max_delay_ms) {
    uint64_t next = (uint64_t)t->reconnect_current_delay_ms * 2U;
    t->reconnect_current_delay_ms = next > t->reconnect_max_delay_ms
                                        ? t->reconnect_max_delay_ms
                                        : (uint32_t)next;
  }
}

transport_t *transport_create(const transport_config_t *config) {
  if (!config || !config->callback || config->port == 0 ||
      config->num_bind_hosts == 0 ||
      config->num_bind_hosts > TRANSPORT_MAX_PATHS ||
      config->num_path_interface_names > TRANSPORT_MAX_PATHS ||
      config->num_remote_hosts > TRANSPORT_MAX_PATHS ||
      config->simulated_loss_rate > 100 ||
      (config->num_remote_hosts != 0 &&
       (config->reconnect_initial_delay_ms != 0
            ? config->reconnect_initial_delay_ms
            : TRANSPORT_DEFAULT_RECONNECT_INITIAL_DELAY_MS) >
           (config->reconnect_max_delay_ms != 0
                ? config->reconnect_max_delay_ms
                : TRANSPORT_DEFAULT_RECONNECT_MAX_DELAY_MS)) ||
      config->simulated_flexicast_feedback_loss_rate > 100 ||
      (!config->verify_peer && !config->allow_insecure_peer)) {
    if (config && config->callback && config->port != 0 &&
        config->num_bind_hosts > 0 &&
        config->num_bind_hosts <= TRANSPORT_MAX_PATHS &&
        config->num_path_interface_names <= TRANSPORT_MAX_PATHS &&
        config->num_remote_hosts <= TRANSPORT_MAX_PATHS &&
        config->simulated_loss_rate <= 100 &&
        config->simulated_flexicast_feedback_loss_rate <= 100)
      fprintf(stderr,
              "transport: peer verification requires verify_peer or explicit "
              "allow_insecure_peer\n");
    return NULL;
  }
  for (size_t i = 0; i < config->num_bind_hosts; i++) {
    if (!config->bind_hosts[i])
      return NULL;
  }
  for (size_t i = 0; i < config->num_path_interface_names; i++) {
    if (!config->path_interface_names[i] ||
        strlen(config->path_interface_names[i]) >=
            sizeof(((transport_t *)0)->path_interface_names[0]))
      return NULL;
  }
  for (size_t i = 0; i < config->num_remote_hosts; i++) {
    if (!config->remote_hosts[i])
      return NULL;
  }

  transport_limits_t limits;
  char limits_error[160];
  if (!transport_limits_resolve(&config->limits, &limits, limits_error,
                                sizeof(limits_error))) {
    fprintf(stderr, "transport: invalid limits: %s\n", limits_error);
    return NULL;
  }

  transport_t *t = calloc(1, sizeof(transport_t));
  if (!t) {
    fprintf(stderr, "transport: failed to allocate transport state\n");
    return NULL;
  }

  for (size_t i = 0; i < TRANSPORT_MAX_PATHS; i++) {
    t->fds[i] = -1;
    t->local_remote_indices[i] = SIZE_MAX;
  }
  for (size_t i = 0; i < 2; i++)
    t->flexicast_fds[i] = -1;
  t->owner_thread = pthread_self();
  atomic_init(&t->cross_thread_violations, 0);
  t->limits = limits;
  t->flexicast_enabled = config->enable_flexicast;
  if (config->repair_mode != TRANSPORT_REPAIR_MODE_AUTO &&
      config->repair_mode != TRANSPORT_REPAIR_MODE_INDEXED &&
      config->repair_mode != TRANSPORT_REPAIR_MODE_RATELESS) {
    free(t);
    return NULL;
  }
  t->repair_mode = config->repair_mode;
  if (config->flexicast_cc_mode != TRANSPORT_FLEXICAST_CC_MULTICAST &&
      config->flexicast_cc_mode != TRANSPORT_FLEXICAST_CC_ADAPTIVE) {
    free(t);
    return NULL;
  }
  if (config->flexicast_repair_route != TRANSPORT_FLEXICAST_REPAIR_SHARED &&
      config->flexicast_repair_route != TRANSPORT_FLEXICAST_REPAIR_UNICAST) {
    free(t);
    return NULL;
  }
  if ((config->flexicast_cc_minimum_rate != 0 &&
       config->flexicast_cc_maximum_rate != 0 &&
       config->flexicast_cc_minimum_rate > config->flexicast_cc_maximum_rate) ||
      (config->flexicast_cc_startup_rate != 0 &&
       config->flexicast_cc_minimum_rate != 0 &&
       config->flexicast_cc_startup_rate < config->flexicast_cc_minimum_rate) ||
      (config->flexicast_cc_startup_rate != 0 &&
       config->flexicast_cc_maximum_rate != 0 &&
       config->flexicast_cc_startup_rate > config->flexicast_cc_maximum_rate)) {
    fprintf(stderr, "transport: invalid Flexicast congestion-control rates\n");
    free(t);
    return NULL;
  }
  t->flexicast_cc_mode = config->flexicast_cc_mode;
  t->flexicast_cc_startup_rate = config->flexicast_cc_startup_rate;
  t->flexicast_cc_minimum_rate = config->flexicast_cc_minimum_rate;
  t->flexicast_cc_maximum_rate = config->flexicast_cc_maximum_rate;
  t->flexicast_cc_aggregate_rate_limit =
      config->flexicast_cc_aggregate_rate_limit;
  t->flexicast_cc_feedback_timeout_ms =
      config->flexicast_cc_feedback_timeout_ms;
  t->flexicast_repair_route = config->flexicast_repair_route;
  t->repair_feedback_nonce = config->repair_feedback_seed;
  if (t->repair_feedback_nonce == 0)
    ptls_openssl_random_bytes(&t->repair_feedback_nonce,
                              sizeof(t->repair_feedback_nonce));
  if (t->repair_feedback_nonce == 0)
    t->repair_feedback_nonce = UINT64_C(0x9e3779b97f4a7c15);
  t->repair_shadow_deadline_ms =
      config->repair_shadow_deadline_ms != 0
          ? config->repair_shadow_deadline_ms
          : TRANSPORT_REPAIR_PLANNER_DEFAULT_DEADLINE_MS;
  if (config->repair_shadow_log_file) {
    t->repair_shadow_log = fopen(config->repair_shadow_log_file, "ab");
    if (!t->repair_shadow_log) {
      fprintf(stderr, "transport: unable to open repair shadow log '%s': %s\n",
              config->repair_shadow_log_file, strerror(errno));
      free(t);
      return NULL;
    }
    setvbuf(t->repair_shadow_log, NULL, _IOLBF, 0);
  }
  t->next_conn_id = 1;
  t->ifmon_pipe[0] = -1;
  t->ifmon_pipe[1] = -1;

  t->conns = calloc(t->limits.max_connections, sizeof(*t->conns));
  if (!t->conns) {
    if (t->repair_shadow_log)
      fclose(t->repair_shadow_log);
    free(t);
    return NULL;
  }
  if (t->flexicast_enabled && !transport_flexicast_registry_init(
                                  &t->flexicast, TRANSPORT_FLEXICAST_MAX_FLOWS,
                                  t->limits.max_connections)) {
    free(t->conns);
    if (t->repair_shadow_log)
      fclose(t->repair_shadow_log);
    free(t);
    return NULL;
  }
  for (size_t i = 0; i < config->num_bind_hosts; i++) {
    if (!transport_egress_init(&t->egress[i],
                               t->limits.max_egress_packets_per_socket,
                               t->limits.max_egress_bytes_per_socket)) {
      transport_destroy(t);
      return NULL;
    }
  }

  if (!transport_arena_init(&t->arena, 16U * 1024U * 1024U)) {
    transport_log(t, TRANSPORT_LOG_ERROR, "memory", 0, SIZE_MAX,
                  "failed to allocate packet arena");
    for (size_t i = 0; i < TRANSPORT_MAX_PATHS; i++)
      transport_egress_destroy(&t->egress[i]);
    transport_flexicast_registry_destroy(&t->flexicast);
    free(t->conns);
    if (t->repair_shadow_log)
      fclose(t->repair_shadow_log);
    free(t);
    return NULL;
  }

  t->callback = config->callback;
  t->user_data = config->user_data;
  t->log_callback = config->log_callback;
  t->log_user_data = config->log_user_data;
  t->is_server = (config->num_remote_hosts == 0);
  t->reconnect_enabled = !t->is_server && config->reconnect_enabled;
  t->reconnect_initial_delay_ms =
      config->reconnect_initial_delay_ms != 0
          ? config->reconnect_initial_delay_ms
          : TRANSPORT_DEFAULT_RECONNECT_INITIAL_DELAY_MS;
  t->reconnect_max_delay_ms = config->reconnect_max_delay_ms != 0
                                  ? config->reconnect_max_delay_ms
                                  : TRANSPORT_DEFAULT_RECONNECT_MAX_DELAY_MS;
  t->reconnect_current_delay_ms = t->reconnect_initial_delay_ms;
  t->fec_assembler_timeout_ms = config->fec_assembler_timeout_ms != 0
                                    ? config->fec_assembler_timeout_ms
                                    : QLINQ_FEC_ASSEMBLER_TIMEOUT_MS;
  t->simulated_loss_rate = config->simulated_loss_rate;
  t->num_path_interface_names = config->num_path_interface_names;
  for (size_t i = 0; i < t->num_path_interface_names; i++)
    copy_interface_name(t->path_interface_names[i],
                        config->path_interface_names[i]);
  if (config->allow_insecure_peer)
    transport_log(t, TRANSPORT_LOG_WARNING, "tls", 0, SIZE_MAX,
                  "peer certificate verification is disabled");
  if (config->simulated_loss_rate != 0)
    transport_log(t, TRANSPORT_LOG_WARNING, "simulation", 0, SIZE_MAX,
                  "simulated packet loss is enabled");
  t->simulated_flexicast_feedback_loss_rate =
      config->simulated_flexicast_feedback_loss_rate;

  t->last_pathflow_update = ptls_get_time.cb(&ptls_get_time);

  if (pipe(t->ifmon_pipe) == 0) {
    if (set_fd_nonblocking(t->ifmon_pipe[0]) &&
        set_fd_nonblocking(t->ifmon_pipe[1])) {
      (void)ifmon_watch_start(&t->ifmon_w, on_ifmon_update, t);
    } else {
      CLOSE_SOCKET(t->ifmon_pipe[0]);
      CLOSE_SOCKET(t->ifmon_pipe[1]);
      t->ifmon_pipe[0] = -1;
      t->ifmon_pipe[1] = -1;
    }
  } else {
    t->ifmon_pipe[0] = -1;
    t->ifmon_pipe[1] = -1;
  }

  /* setup cryptographic context */
  t->tls_ctx.random_bytes = ptls_openssl_random_bytes;
  t->tls_ctx.get_time = &ptls_get_time;
  t->tls_ctx.key_exchanges = ptls_openssl_key_exchanges;
  t->tls_ctx.cipher_suites = ptls_openssl_cipher_suites;

  transport_protocol_setup(t);
  t->verifier_initialized = false;

  t->quic_ctx = quicly_spec_context;
  if (config->initial_rtt_ms != 0)
    t->quic_ctx.loss.default_initial_rtt = config->initial_rtt_ms;
  if (config->handshake_timeout_rtt_multiplier != 0)
    t->quic_ctx.handshake_timeout_rtt_multiplier =
        config->handshake_timeout_rtt_multiplier;

  /* Setup CID encryptor to support active connection migration */
  char cid_key[16];
  ptls_openssl_random_bytes(cid_key, sizeof(cid_key));
  t->quic_ctx.cid_encryptor = quicly_new_default_cid_encryptor(
      &ptls_openssl_quiclb, &ptls_openssl_aes128ecb, &ptls_openssl_sha256,
      ptls_iovec_init(cid_key, sizeof(cid_key)));

  t->quic_ctx.tls = &t->tls_ctx;
  quicly_amend_ptls_context(t->quic_ctx.tls);
  t->quic_ctx.stream_open = &t->stream_open;
  t->quic_ctx.receive_datagram_frame = &t->receive_datagram;
  t->quic_ctx.receive_flexicast_frame = &t->receive_flexicast;
  t->quic_ctx.receive_flexicast_ack = &t->receive_flexicast_ack;

  /* Never select a validated QUIC path after its owning physical socket has
   * been removed. Datagram scheduling applies the same invariant. */
  t->quic_ctx.path_scheduler = &qlinq_path_scheduler;

  t->quic_ctx.initcwnd_packets = 100;
  t->quic_ctx.initial_egress_max_udp_payload_size =
      t->limits.max_udp_payload_size;
  t->quic_ctx.transport_params.max_datagram_frame_size =
      t->limits.max_udp_payload_size;
  if (config->quic_idle_timeout_ms != 0)
    t->quic_ctx.transport_params.max_idle_timeout =
        config->quic_idle_timeout_ms;
  /* The parser consumes complete frames. Its receive window must include
   * both headers as well as the largest advertised application record. */
  t->quic_ctx.transport_params.max_stream_data.uni =
      t->limits.max_reliable_object_size + QLINQ_WIRE_FRAME_HEADER_SIZE +
      QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE;
  if (t->quic_ctx.transport_params.max_stream_data.bidi_local <
      t->quic_ctx.transport_params.max_stream_data.uni)
    t->quic_ctx.transport_params.max_stream_data.bidi_local =
        t->quic_ctx.transport_params.max_stream_data.uni;
  t->quic_ctx.transport_params.max_streams_uni = 100;
  t->quic_ctx.transport_params.max_streams_bidi = 100;

  t->quic_ctx.transport_params.active_connection_id_limit = 8;
  t->quic_ctx.transport_params.initial_max_path_id = TRANSPORT_MAX_PATHS;
  t->quic_ctx.transport_params.flexicast_support.ipv4 = t->flexicast_enabled;
  t->quic_ctx.transport_params.flexicast_support.ipv6 = t->flexicast_enabled;

  t->num_fds = config->num_bind_hosts;
  t->num_remote_addrs = config->num_remote_hosts;

  for (size_t i = 0; i < t->num_fds; i++) {
    if (strchr(config->bind_hosts[i], ':')) {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&t->local_addrs[i];
      sin6->sin6_family = AF_INET6;
      if (inet_pton(AF_INET6, config->bind_hosts[i], &sin6->sin6_addr) != 1) {
        transport_log(t, TRANSPORT_LOG_ERROR, "config", 0, i,
                      "invalid IPv6 bind address: %s", config->bind_hosts[i]);
        transport_destroy(t);
        return NULL;
      }
      sin6->sin6_port = t->is_server ? htons(config->port) : 0;
      t->local_addrs_len[i] = sizeof(struct sockaddr_in6);
      t->fds[i] = open_unicast_socket(AF_INET6);
    } else {
      struct sockaddr_in *sin = (struct sockaddr_in *)&t->local_addrs[i];
      sin->sin_family = AF_INET;
      if (inet_pton(AF_INET, config->bind_hosts[i], &sin->sin_addr) != 1) {
        transport_log(t, TRANSPORT_LOG_ERROR, "config", 0, i,
                      "invalid IPv4 bind address: %s", config->bind_hosts[i]);
        transport_destroy(t);
        return NULL;
      }
      sin->sin_port = t->is_server ? htons(config->port) : 0;
      t->local_addrs_len[i] = sizeof(struct sockaddr_in);
      t->fds[i] = open_unicast_socket(AF_INET);
    }
    if (t->fds[i] < 0) {
      transport_log(t, TRANSPORT_LOG_ERROR, "udp", 0, i,
                    "socket creation failed: %s", strerror(errno));
      transport_destroy(t);
      return NULL;
    }

    /* Unicast endpoints must own their local UDP tuple exclusively. On Linux,
     * SO_REUSEADDR also permits bind(port=0) to reuse an occupied ephemeral
     * port: a later endpoint then steals an earlier endpoint's QUIC replies.
     * Only the separate multicast receive sockets need address reuse. */

    if (bind(t->fds[i], (struct sockaddr *)&t->local_addrs[i],
             t->local_addrs_len[i]) != 0) {
      transport_log(t, TRANSPORT_LOG_ERROR, "udp", 0, i,
                    "bind failed for %s:%u: %s", config->bind_hosts[i],
                    config->port, strerror(errno));
      transport_destroy(t);
      return NULL;
    }

    configure_socket_buffers(t, t->fds[i]);

    if (!set_fd_nonblocking(t->fds[i])) {
      transport_log(t, TRANSPORT_LOG_ERROR, "udp", 0, i,
                    "failed to make socket nonblocking: %s", strerror(errno));
      transport_destroy(t);
      return NULL;
    }
  }
  resolve_configured_interfaces(t);

  if (!transport_flexicast_configure(t, config->flexicast_group,
                                     config->flexicast_group_port,
                                     config->flexicast_interface)) {
    transport_destroy(t);
    return NULL;
  }

  if (t->is_server || (config->cert_file && config->key_file)) {
    if (transport_tls_load_certificate_and_key(&t->tls_ctx, &t->sign_cert,
                                               config->cert_file,
                                               config->key_file) != 0) {
      transport_log(t, TRANSPORT_LOG_ERROR, "tls", 0, SIZE_MAX,
                    "failed to load TLS identity");
      transport_destroy(t);
      return NULL;
    }
  }

  if (config->verify_peer) {
    X509_STORE *store = NULL;
    if (config->ca_file) {
      store = X509_STORE_new();
      if (X509_STORE_load_locations(store, config->ca_file, NULL) != 1) {
        transport_log(t, TRANSPORT_LOG_ERROR, "tls", 0, SIZE_MAX,
                      "failed to load CA certificates from %s",
                      config->ca_file);
        X509_STORE_free(store);
        transport_destroy(t);
        return NULL;
      }
    }

    /* ptls_openssl_init_verify_certificate will take its own reference to store
     * (if provided), or load the system default certificates if store is NULL
     */
    if (ptls_openssl_init_verify_certificate(&t->verifier, store) != 0) {
      transport_log(t, TRANSPORT_LOG_ERROR, "tls", 0, SIZE_MAX,
                    "failed to initialize certificate verifier");
      if (store) {
        X509_STORE_free(store);
      }
      transport_destroy(t);
      return NULL;
    }
    if (store) {
      X509_STORE_free(store); /* drop our local reference */
    }

    t->tls_ctx.verify_certificate = &t->verifier.super;
    t->verifier_initialized = true;

    if (t->is_server) {
      t->tls_ctx.require_client_authentication = 1;
    }
  } else {
    transport_tls_init_insecure_verifier(&t->verifier);
    t->tls_ctx.verify_certificate = &t->verifier.super;
    t->verifier_initialized = false;
  }

  if (!t->is_server) {
    if (strlen(config->remote_hosts[0]) >= sizeof(t->server_name)) {
      transport_log(t, TRANSPORT_LOG_ERROR, "config", 0, SIZE_MAX,
                    "remote host name exceeds implementation limit");
      transport_destroy(t);
      return NULL;
    }
    strcpy(t->server_name, config->remote_hosts[0]);
    for (size_t i = 0; i < t->num_remote_addrs; i++) {
      if (strchr(config->remote_hosts[i], ':')) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&t->remote_addrs[i];
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(config->port);
        if (inet_pton(AF_INET6, config->remote_hosts[i], &sin6->sin6_addr) !=
            1) {
          transport_log(t, TRANSPORT_LOG_ERROR, "config", 0, i,
                        "invalid IPv6 remote address: %s",
                        config->remote_hosts[i]);
          transport_destroy(t);
          return NULL;
        }
        t->remote_addrs_len[i] = sizeof(struct sockaddr_in6);
      } else {
        struct sockaddr_in *sin = (struct sockaddr_in *)&t->remote_addrs[i];
        sin->sin_family = AF_INET;
        sin->sin_port = htons(config->port);
        if (inet_pton(AF_INET, config->remote_hosts[i], &sin->sin_addr) != 1) {
          transport_log(t, TRANSPORT_LOG_ERROR, "config", 0, i,
                        "invalid IPv4 remote address: %s",
                        config->remote_hosts[i]);
          transport_destroy(t);
          return NULL;
        }
        t->remote_addrs_len[i] = sizeof(struct sockaddr_in);
      }
    }

    if (t->num_remote_addrs > 1 && t->num_fds > t->num_remote_addrs) {
      transport_log(t, TRANSPORT_LOG_ERROR, "config", 0, SIZE_MAX,
                    "multiple remote hosts require at least one remote for "
                    "each configured bind host");
      transport_destroy(t);
      return NULL;
    }
    for (size_t i = 0; i < t->num_fds; i++) {
      size_t remote_index = t->num_remote_addrs == 1 ? 0 : i;
      if (!path_endpoint_families_match(t, i, remote_index)) {
        transport_log(t, TRANSPORT_LOG_ERROR, "config", 0, i,
                      "remote host %zu uses a different address family",
                      remote_index);
        transport_destroy(t);
        return NULL;
      }
      t->local_remote_indices[i] = remote_index;
    }

    if (!start_client_connection(t)) {
      transport_log(t, TRANSPORT_LOG_ERROR, "connection", 0, SIZE_MAX,
                    "failed to create initial client connection");
      transport_destroy(t);
      return NULL;
    }
  }

  /* make socket nonblocking is handled in the loop */
  return t;
}

void transport_destroy(transport_t *t) {
  if (!t)
    return;
  if (!transport_owner_ok(t))
    return;
  if (t->callback_depth != 0) {
    t->stats.callback_destroy_rejections++;
    return;
  }

  if (t->ifmon_pipe[0] >= 0) {
    ifmon_watch_stop(&t->ifmon_w);
  }
  if (t->ifmon_pipe[0] >= 0) {
    CLOSE_SOCKET(t->ifmon_pipe[0]);
    CLOSE_SOCKET(t->ifmon_pipe[1]);
  }

  for (size_t i = 0; i < t->num_fds; i++) {
    if (t->fds[i] >= 0) {
      CLOSE_SOCKET(t->fds[i]);
    }
  }
  transport_flexicast_dispose(t);
  for (size_t i = 0; i < 2; i++)
    if (t->flexicast_fds[i] >= 0)
      CLOSE_SOCKET(t->flexicast_fds[i]);
  for (size_t i = 0; i < TRANSPORT_MAX_PATHS; i++)
    transport_egress_destroy(&t->egress[i]);

  if (t->is_server) {
    for (size_t i = 0; i < t->conn_count; i++) {
      transport_conn_t *conn = t->conns[i];
      quicly_free(conn->quic);
      for (size_t a = 0; a < t->limits.max_assemblers_per_connection; a++)
        transport_release_assembler(t, &conn->assemblers[a]);
      destroy_connection_subscriptions(conn);
      free(conn);
    }
  } else if (t->client_conn) {
    transport_conn_t *conn = t->client_conn;
    quicly_free(conn->quic);
    for (size_t a = 0; a < t->limits.max_assemblers_per_connection; a++)
      transport_release_assembler(t, &conn->assemblers[a]);
    destroy_connection_subscriptions(conn);
    free(conn);
  }

  transport_sent_cache_destroy(&t->sent_cache);
  transport_fec_cache_destroy(&t->fec_cache);

  transport_arena_destroy(&t->arena);

  if (t->quic_ctx.cid_encryptor != NULL) {
    quicly_free_default_cid_encryptor(t->quic_ctx.cid_encryptor);
  }

  if (t->fec_buf) {
    free(t->fec_buf);
  }

  if (t->verifier_initialized) {
    ptls_openssl_dispose_verify_certificate(&t->verifier);
  }

  if (t->tls_ctx.sign_certificate) {
    ptls_openssl_dispose_sign_certificate(&t->sign_cert);
  }
  for (size_t i = 0; i < t->tls_ctx.certificates.count; i++)
    free(t->tls_ctx.certificates.list[i].base);
  free(t->tls_ctx.certificates.list);

  free(t->conns);
  if (t->repair_shadow_log)
    fclose(t->repair_shadow_log);
  free(t);
}

static uint64_t mix_repair_feedback(uint64_t value) {
  value ^= value >> 30;
  value *= UINT64_C(0xbf58476d1ce4e5b9);
  value ^= value >> 27;
  value *= UINT64_C(0x94d049bb133111eb);
  return value ^ (value >> 31);
}

/* Flexicast receivers cannot overhear one another's encrypted control streams.
 * Spread their requests long enough for the first shared repair datagram to
 * suppress most of the cohort, while keeping ordinary unicast recovery at the
 * original prompt delay. */
static int64_t repair_feedback_delay_ms(const transport_conn_t *conn,
                                        bool shared_delivery, uint8_t alias,
                                        uint64_t group_id, uint64_t object_id,
                                        uint16_t attempt) {
  if (!shared_delivery)
    return QLINQ_FEC_NACK_DELAY_MS;
  uint64_t value = conn->transport->repair_feedback_nonce;
  value ^= group_id + UINT64_C(0x9e3779b97f4a7c15);
  value ^= object_id * UINT64_C(0xd6e8feb86659fd93);
  value ^= (uint64_t)alias << 48;
  value ^= (uint64_t)attempt * UINT64_C(0xa0761d6478bd642f);
  uint64_t span =
      QLINQ_FEC_MULTICAST_NACK_BACKOFF_MAX_MS - QLINQ_FEC_NACK_DELAY_MS + 1U;
  return QLINQ_FEC_NACK_DELAY_MS + (int64_t)(mix_repair_feedback(value) % span);
}

void transport_tick(transport_t *t) {
  if (!transport_owner_ok(t))
    return;
  if (t->tick_active) {
    t->stats.recursive_tick_rejections++;
    return;
  }
  t->tick_active = true;

  for (size_t i = 0; i < t->num_fds; i++)
    (void)transport_egress_flush(&t->egress[i], t->fds[i]);

  int64_t now_nack_ms = transport_get_time_ms();
  if (!t->is_server && !t->client_conn && t->reconnect_enabled &&
      !t->shutting_down && now_nack_ms >= t->reconnect_at_ms) {
    t->stats.reconnect_attempts++;
    t->reconnect_in_progress = true;
    if (!start_client_connection(t)) {
      t->stats.reconnect_failed++;
      t->reconnect_in_progress = false;
      schedule_client_reconnect(t, now_nack_ms);
      transport_log(t, TRANSPORT_LOG_WARNING, "connection", 0, SIZE_MAX,
                    "reconnect attempt failed; retry scheduled");
    }
  }

  /* Expiration releases memory and reports loss even when the receiver-wide
   * NACK budget is exhausted. It must not be gated by request admission. */
  size_t active_conns = t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
  for (size_t c = 0; c < active_conns; c++) {
    transport_conn_t *conn = t->is_server ? t->conns[c] : t->client_conn;
    if (!conn || !conn->quic ||
        quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING)
      continue;
    for (size_t i = 0; i < t->limits.max_assemblers_per_connection; i++) {
      frame_assembler_t *asm_slot = &conn->assemblers[i];
      if (asm_slot->total_symbols == 0)
        continue;
      if (now_nack_ms - asm_slot->last_activity_time_ms >=
          t->fec_assembler_timeout_ms) {
        moq_track_id_t resolved_track;
        if (transport_subscriptions_find_by_alias(&conn->receive_subscriptions,
                                                  asm_slot->track_id,
                                                  &resolved_track) == 0) {
          transport_event_t ev = {.type = TRANSPORT_EVENT_OBJECT_LOST,
                                  .conn = conn,
                                  .track_id = resolved_track,
                                  .object = {.track_id = resolved_track,
                                             .group_id = asm_slot->group_id,
                                             .object_id = asm_slot->object_id}};
          t->stats.fec_objects_lost++;
          transport_emit_event(t, &ev);
        }
        transport_release_assembler(t, asm_slot);
        continue;
      }
    }
  }

    for (size_t alias = 0; alias <= UINT8_MAX && object_nack_budget > 0;
         alias++) {
      transport_object_gap_state_t *gap = &conn->object_gaps[alias];
      if (gap->pending_mask != 0) {
        for (uint32_t bit = 0; bit < 32 && object_nack_budget > 0; bit++) {
          if ((gap->pending_mask & (1U << bit)) == 0)
            continue;
          uint64_t object_id = gap->pending_base + bit;
          if (now_nack_ms - gap->detected_at_ms <
              repair_feedback_delay_ms(conn, gap->shared_delivery,
                                       (uint8_t)alias, gap->group_id, object_id,
                                       0))
            continue;
          if (transport_protocol_send_nack(conn, (uint8_t)alias, gap->group_id,
                                           object_id, NULL, 0, true)) {
            /* Keep the object pending until a shared repair symbol arrives.
             * The source-wide failsafe may defer an otherwise valid request,
             * and NACK control streams do not acknowledge repair admission. */
            gap->detected_at_ms = now_nack_ms;
            object_nack_budget--;
            t->recovery_conn_cursor = (c + 1U) % active_conns;
          } else {
            break;
          }
        }
      }

      for (size_t window_index = 0;
           window_index < QLINQ_RECOVERY_MAX_WINDOWS && object_nack_budget > 0;
           window_index++) {
        transport_recovery_window_t *window =
            &gap->recovery_windows[window_index];
        if (!window->active || window->missing_mask == 0)
          continue;
        for (uint32_t attempt = 0; attempt < QLINQ_RECOVERY_WINDOW_OBJECTS;
             attempt++) {
          uint32_t bit =
              (window->cursor + attempt) % QLINQ_RECOVERY_WINDOW_OBJECTS;
          if ((window->missing_mask & (1U << bit)) == 0)
            continue;
          uint64_t object_id = window->first_object_id + bit;
          if (object_id > window->final_object_id)
            continue;
          int64_t recovery_delay = QLINQ_FEC_COMPLETION_RETRY_MS;
          if (gap->shared_delivery)
            recovery_delay += repair_feedback_delay_ms(
                conn, true, (uint8_t)alias, window->group_id, object_id,
                window->cursor);
          if (now_nack_ms - window->last_request_ms < recovery_delay)
            continue;
          bool assembling = false;
          for (size_t i = 0; i < t->limits.max_assemblers_per_connection; i++) {
            frame_assembler_t *assembler = &conn->assemblers[i];
            if (assembler->total_symbols > 0 && assembler->track_id == alias &&
                assembler->group_id == window->group_id &&
                assembler->object_id == object_id) {
              assembling = true;
              break;
            }
          }
          if (assembling)
            continue;
          aggregate_wait = transport_repair_limiter_wait_ms(
              &t->aggregate_nack_limiter,
              t->limits.max_aggregate_nack_requests_per_second, now_nack_ms);
          if (aggregate_wait != 0)
            goto aggregate_nack_exhausted;
          if (transport_protocol_send_nack(conn, (uint8_t)alias,
                                           window->group_id, object_id, NULL, 0,
                                           true)) {
            window->cursor =
                (uint8_t)((bit + 1U) % QLINQ_RECOVERY_WINDOW_OBJECTS);
            window->last_request_ms = now_nack_ms;
            object_nack_budget--;
            t->recovery_conn_cursor = (c + 1U) % active_conns;
          }
          break;
        }
      }
    }

    for (size_t i = 0; i < t->limits.max_assemblers_per_connection; i++) {
      frame_assembler_t *asm_slot = &conn->assemblers[i];
      if (asm_slot->total_symbols == 0)
        continue;

      if (!asm_slot->decoded &&
          now_nack_ms - asm_slot->first_symbol_time_ms >=
              repair_feedback_delay_ms(conn, asm_slot->shared_delivery,
                                       asm_slot->track_id, asm_slot->group_id,
                                       asm_slot->object_id,
                                       asm_slot->nack_attempt) &&
          (!asm_slot->nack_sent ||
           now_nack_ms - asm_slot->last_nack_time_ms >=
               repair_feedback_delay_ms(conn, asm_slot->shared_delivery,
                                        asm_slot->track_id, asm_slot->group_id,
                                        asm_slot->object_id,
                                        asm_slot->nack_attempt))) {
        moq_track_id_t resolved_track;
        if (transport_subscriptions_find_by_alias(&conn->receive_subscriptions,
                                                  asm_slot->track_id,
                                                  &resolved_track) != 0 ||
            !(resolved_track.flags & MOQ_TRACK_FLAG_FEC_RATELESS))
          continue; /* Fixed RS-FEC does not send NACKs */
        transport_repair_mode_t repair_mode =
            transport_get_effective_repair_mode(t, conn, &resolved_track);
        uint16_t missing_count = 0;
        const uint16_t *missing = NULL;
        if (repair_mode == TRANSPORT_REPAIR_MODE_RATELESS) {
          missing_count = asm_slot->received_count < asm_slot->data_symbols
                              ? (uint16_t)(asm_slot->data_symbols -
                                           asm_slot->received_count)
                              : 1U;
          if (missing_count > TRANSPORT_REPAIR_MAX_SYMBOLS)
            missing_count = TRANSPORT_REPAIR_MAX_SYMBOLS;
        } else {
          for (uint16_t s = 0; s < asm_slot->total_symbols; s++) {
            if (!asm_slot->received_mask[s] &&
                missing_count < TRANSPORT_REPAIR_MAX_SYMBOLS) {
              asm_slot->missing_indices[missing_count++] = s;
            }
          }
          missing = asm_slot->missing_indices;
        }
        if (missing_count > 0) {
          aggregate_wait = transport_repair_limiter_wait_ms(
              &t->aggregate_nack_limiter,
              t->limits.max_aggregate_nack_requests_per_second, now_nack_ms);
          if (aggregate_wait != 0)
            goto aggregate_nack_exhausted;
          if (transport_protocol_send_nack(
                  conn, asm_slot->track_id, asm_slot->group_id,
                  asm_slot->object_id, missing, missing_count, false)) {
            asm_slot->nack_sent = true;
            asm_slot->last_nack_time_ms = now_nack_ms;
            if (asm_slot->nack_attempt != UINT16_MAX)
              asm_slot->nack_attempt++;
          }
        }
      }
    }
  }

  goto recovery_sweep_done;

aggregate_nack_exhausted:
  t->aggregate_nack_retry_at_ms =
      aggregate_wait == UINT64_MAX ||
              aggregate_wait > (uint64_t)(INT64_MAX - now_nack_ms)
          ? INT64_MAX
          : now_nack_ms + (int64_t)aggregate_wait;

recovery_sweep_done:
  /* Check for FEC grouping buffer timeout (3 milliseconds) */
  if (t->fec_buf_len > 0) {
    uint64_t now = ptls_get_time.cb(&ptls_get_time);
    if ((now - t->fec_first_pkt_time) >= 3) {
      (void)transport_publish_flush_grouped(t);
    }
  }

  /* process ifmon events */
  if (t->ifmon_pipe[0] >= 0) {
    ifmon_pipe_msg_t msg;
    while (read(t->ifmon_pipe[0], &msg, sizeof(msg)) == sizeof(msg)) {
      if (msg.is_added) {
        if (!path_interface_allowed(t, msg.name))
          continue;
        if (t->num_fds < TRANSPORT_MAX_PATHS) {
          /* Deduplicate: Check if this IP is already bound */
          int is_duplicate = 0;
          for (size_t i = 0; i < t->num_fds; i++) {
            if (t->local_addrs[i].ss_family == msg.addr.ss_family) {
              if (msg.addr.ss_family == AF_INET) {
                struct sockaddr_in *s1 =
                    (struct sockaddr_in *)&t->local_addrs[i];
                struct sockaddr_in *s2 = (struct sockaddr_in *)&msg.addr;
                if (s1->sin_addr.s_addr == s2->sin_addr.s_addr)
                  is_duplicate = 1;
              } else if (msg.addr.ss_family == AF_INET6) {
                struct sockaddr_in6 *s1 =
                    (struct sockaddr_in6 *)&t->local_addrs[i];
                struct sockaddr_in6 *s2 = (struct sockaddr_in6 *)&msg.addr;
                if (memcmp(&s1->sin6_addr, &s2->sin6_addr,
                           sizeof(struct in6_addr)) == 0)
                  is_duplicate = 1;
              }
            }
          }
          if (is_duplicate) {
            continue;
          }

          int fd = open_unicast_socket(msg.addr.ss_family);
          if (fd >= 0) {
            /* Keep dynamically discovered unicast paths exclusive too. */
            configure_socket_buffers(t, fd);
            if (msg.addr.ss_family == AF_INET) {
              ((struct sockaddr_in *)&msg.addr)->sin_port =
                  t->is_server
                      ? (t->local_addrs[0].ss_family == AF_INET
                             ? ((struct sockaddr_in *)&t->local_addrs[0])
                                   ->sin_port
                             : ((struct sockaddr_in6 *)&t->local_addrs[0])
                                   ->sin6_port)
                      : 0;
            } else {
              ((struct sockaddr_in6 *)&msg.addr)->sin6_port =
                  t->is_server
                      ? (t->local_addrs[0].ss_family == AF_INET
                             ? ((struct sockaddr_in *)&t->local_addrs[0])
                                   ->sin_port
                             : ((struct sockaddr_in6 *)&t->local_addrs[0])
                                   ->sin6_port)
                      : 0;
            }

            if (bind(fd, (struct sockaddr *)&msg.addr, msg.addr_len) == 0) {
              if (!set_fd_nonblocking(fd)) {
                CLOSE_SOCKET(fd);
                continue;
              }
              bind_to_device(fd, msg.index);

              if (!transport_egress_init(
                      &t->egress[t->num_fds],
                      t->limits.max_egress_packets_per_socket,
                      t->limits.max_egress_bytes_per_socket)) {
                CLOSE_SOCKET(fd);
                continue;
              }

              size_t local_index = t->num_fds;
              t->fds[local_index] = fd;
              t->local_addrs[local_index] = msg.addr;
              t->local_addrs_len[local_index] = msg.addr_len;
              t->local_ifindices[local_index] = msg.index;
              copy_interface_name(t->local_ifnames[local_index], msg.name);
              t->num_fds++;

              if (!t->is_server) {
                size_t remote_index =
                    select_remote_for_added_local(t, local_index);
                if (remote_index == SIZE_MAX) {
                  transport_egress_destroy(&t->egress[local_index]);
                  CLOSE_SOCKET(t->fds[local_index]);
                  t->fds[local_index] = -1;
                  memset(&t->local_addrs[local_index], 0,
                         sizeof(t->local_addrs[local_index]));
                  t->local_addrs_len[local_index] = 0;
                  t->local_ifindices[local_index] = 0;
                  memset(t->local_ifnames[local_index], 0,
                         sizeof(t->local_ifnames[local_index]));
                  t->num_fds--;
                  continue;
                }
                t->local_remote_indices[local_index] = remote_index;
                t->path_open_pending[local_index] = true;
              }

              char ip_str[64];
              if (msg.addr.ss_family == AF_INET) {
                inet_ntop(AF_INET, &((struct sockaddr_in *)&msg.addr)->sin_addr,
                          ip_str, sizeof(ip_str));
              } else {
                inet_ntop(AF_INET6,
                          &((struct sockaddr_in6 *)&msg.addr)->sin6_addr,
                          ip_str, sizeof(ip_str));
              }
              transport_log(t, TRANSPORT_LOG_INFO, "ifmon", 0, local_index,
                            "opened socket for local IP %s", ip_str);

            } else {
              CLOSE_SOCKET(fd);
            }
          }
        }
      } else {
        /* ip removed */
        for (size_t i = 0; i < t->num_fds; i++) {
          int match = msg.addr.ss_family == AF_UNSPEC
                          ? t->local_ifindices[i] == msg.index
                          : 0;
          if (!match && t->local_addrs[i].ss_family == msg.addr.ss_family) {
            if (msg.addr.ss_family == AF_INET) {
              struct sockaddr_in *s1 = (struct sockaddr_in *)&t->local_addrs[i];
              struct sockaddr_in *s2 = (struct sockaddr_in *)&msg.addr;
              if (s1->sin_addr.s_addr == s2->sin_addr.s_addr)
                match = 1;
            } else {
              struct sockaddr_in6 *s1 =
                  (struct sockaddr_in6 *)&t->local_addrs[i];
              struct sockaddr_in6 *s2 = (struct sockaddr_in6 *)&msg.addr;
              if (memcmp(&s1->sin6_addr, &s2->sin6_addr,
                         sizeof(struct in6_addr)) == 0)
                match = 1;
            }
          }
          if (match) {
            accumulate_egress_stats(t, &t->egress[i], true);
            transport_egress_destroy(&t->egress[i]);
            CLOSE_SOCKET(t->fds[i]);
            remove_connection_physical_slot(t, i);
            /* remove from array */
            for (size_t j = i; j < t->num_fds - 1; j++) {
              t->fds[j] = t->fds[j + 1];
              t->local_addrs[j] = t->local_addrs[j + 1];
              t->local_addrs_len[j] = t->local_addrs_len[j + 1];
              t->local_ifindices[j] = t->local_ifindices[j + 1];
              memcpy(t->local_ifnames[j], t->local_ifnames[j + 1],
                     sizeof(t->local_ifnames[j]));
              t->udp_bytes_received[j] = t->udp_bytes_received[j + 1];
              t->egress[j] = t->egress[j + 1];
              t->local_remote_indices[j] = t->local_remote_indices[j + 1];
              t->path_open_pending[j] = t->path_open_pending[j + 1];
              t->path_open_retry_at[j] = t->path_open_retry_at[j + 1];
            }
            t->num_fds--;
            memset(t->local_ifnames[t->num_fds], 0,
                   sizeof(t->local_ifnames[t->num_fds]));
            t->udp_bytes_received[t->num_fds] = 0;
            memset(&t->egress[t->num_fds], 0, sizeof(t->egress[t->num_fds]));
            t->local_remote_indices[t->num_fds] = SIZE_MAX;
            t->path_open_pending[t->num_fds] = false;
            t->path_open_retry_at[t->num_fds] = 0;
            transport_log(t, TRANSPORT_LOG_INFO, "ifmon", 0, i,
                          "removed socket for local IP");
            break;
          }
        }
      }
    }
  }

  size_t receive_budget = t->limits.max_packets_per_tick;
  size_t flexicast_receive_budget = (receive_budget + 1U) / 2U;
  for (size_t slot = 0; slot < 2 && flexicast_receive_budget > 0; slot++) {
    while (t->flexicast_fds[slot] >= 0 && flexicast_receive_budget > 0) {
      uint8_t buf[2048];
      struct sockaddr_storage sa;
      socklen_t sa_len = sizeof(sa);
      ssize_t rret = recvfrom(t->flexicast_fds[slot], buf, sizeof(buf), 0,
                              (struct sockaddr *)&sa, &sa_len);
      if (rret == -1) {
        if (SOCKET_ERROR_CODE == SOCKET_EAGAIN ||
            SOCKET_ERROR_CODE == SOCKET_EWOULDBLOCK)
          break;
        continue;
      }
      receive_budget--;
      flexicast_receive_budget--;
      t->stats.flexicast_multicast_datagrams_received++;
      transport_conn_t *flexicast_source = NULL;
      ptls_iovec_t flexicast_payload = ptls_iovec_init(NULL, 0);
      if (transport_flexicast_receive_packet(
              t, buf, (size_t)rret, &flexicast_source, &flexicast_payload) &&
          flexicast_source && flexicast_payload.base) {
        if (flexicast_source->authenticated && t->simulated_loss_rate > 0 &&
            (rand() % 100) < t->simulated_loss_rate)
          continue;
        transport_protocol_receive_datagram(flexicast_source, flexicast_payload,
                                            false);
      } else
        t->stats.flexicast_multicast_datagrams_rejected++;
    }
  }
  for (size_t fd_idx = 0; fd_idx < t->num_fds && receive_budget > 0; fd_idx++) {
    while (receive_budget > 0) {
      uint8_t buf[2048];
      struct sockaddr_storage sa;
      socklen_t sa_len = sizeof(sa);
      ssize_t rret = recvfrom(t->fds[fd_idx], buf, sizeof(buf), 0,
                              (struct sockaddr *)&sa, &sa_len);
      if (rret == -1) {
        if (SOCKET_ERROR_CODE == SOCKET_EAGAIN ||
            SOCKET_ERROR_CODE == SOCKET_EWOULDBLOCK)
          break;
        if (SOCKET_ERROR_CODE == SOCKET_EINTR)
          continue;
        break; /* A persistent socket error must not spin the owner thread. */
      }
      receive_budget--;
      serviced++;
      t->udp_bytes_received[fd_idx] += (uint64_t)rret;

      transport_conn_t *flexicast_source = NULL;
      ptls_iovec_t flexicast_payload = ptls_iovec_init(NULL, 0);
      if (transport_flexicast_receive_packet(
              t, buf, (size_t)rret, &flexicast_source, &flexicast_payload)) {
        if (flexicast_source && flexicast_payload.base &&
            !(flexicast_source->authenticated && t->simulated_loss_rate > 0 &&
              (rand() % 100) < t->simulated_loss_rate))
          transport_protocol_receive_datagram(flexicast_source,
                                              flexicast_payload, false);
        continue;
      }

      struct sockaddr *psa = (struct sockaddr *)&sa;

      quicly_decoded_packet_t decoded;
      size_t off = 0;
      while (off < (size_t)rret) {
        if (quicly_decode_packet(&t->quic_ctx, &decoded, buf, rret, &off) ==
            SIZE_MAX)
          break;

        transport_conn_t *target = NULL;
        if (t->is_server) {
          /* Ordinary short-header traffic carries our stable master CID.
           * Avoid testing every earlier peer's reset tokens for each packet.
           * Initials, unknown CIDs and cache collisions retain the full path.
           */
          if (t->quic_ctx.cid_encryptor != NULL &&
              !QUICLY_PACKET_IS_LONG_HEADER(decoded.octets.base[0])) {
            transport_conn_t *hint =
                transport_connection_cache_find(t, &decoded.cid.dest.plaintext);
            if (hint &&
                quicly_is_destination(
                    hint->quic, (struct sockaddr *)&t->local_addrs[fd_idx], psa,
                    &decoded))
              target = hint;
          }
          for (size_t i = 0; !target && i < t->conn_count; ++i) {
            if (quicly_is_destination(
                    t->conns[i]->quic,
                    (struct sockaddr *)&t->local_addrs[fd_idx], psa,
                    &decoded)) {
              target = t->conns[i];
              transport_connection_cache_remember(t, target);
              break;
            }
          }
          if (!target && !t->shutting_down &&
              t->conn_count < t->limits.max_connections) {
            quicly_conn_t *new_quic = NULL;
            /* Each accepted connection needs a distinct master CID. Reusing
             * the zero-initialized value makes later clients indistinguishable
             * once their server-issued CID becomes active. */
            quicly_cid_plaintext_t connection_cid = t->next_cid;
            int accept_res =
                quicly_accept(&new_quic, &t->quic_ctx,
                              (struct sockaddr *)&t->local_addrs[fd_idx], psa,
                              &decoded, NULL, &connection_cid, NULL, NULL);
            if (accept_res == 0 && new_quic) {
              t->next_cid.master_id++;
              target = calloc(1, sizeof(transport_conn_t));
              if (!target) {
                quicly_free(new_quic);
                t->stats.connections_rejected++;
                continue;
              }
              target->transport = t;
              target->quic = new_quic;
              target->id = t->next_conn_id++;
              if (!init_connection_subscriptions(
                      target, t->limits.max_subscriptions_per_connection)) {
                quicly_free(new_quic);
                free(target);
                target = NULL;
                t->stats.connections_rejected++;
                continue;
              }
              *quicly_get_data(new_quic) = target;
              t->conns[t->conn_count++] = target;
              transport_connection_cache_remember(t, target);
              t->stats.connections_accepted++;
            }
          } else if (!target && !t->shutting_down) {
            t->stats.connections_rejected++;
          }
        } else {
          target = t->client_conn;
        }

        if (target && target->authenticated && t->simulated_loss_rate > 0 &&
            (rand() % 100) < t->simulated_loss_rate) {
          continue; /* simulate packet loss on wire after connection is
                       established */
        }

        if (target) {
          quicly_receive(target->quic,
                         (struct sockaddr *)&t->local_addrs[fd_idx], psa,
                         &decoded);
        }
      }
    }
  }

  transport_flexicast_tick(t);

  /* run tick timeout for active connections and check sends */
  uint64_t now = ptls_get_time.cb(&ptls_get_time);

  if (now - t->last_pathflow_update >= 25) {
    t->last_pathflow_update = now;
    /* Peer limits are unchanged throughout this synchronous update. Resolve
     * their common symbol size once, instead of scanning the cohort again
     * for each connection. */
    size_t symbol_size = transport_get_datagram_symbol_size(t);

    size_t update_count =
        t->is_server ? t->conn_count : (t->client_conn ? 1U : 0U);
    for (size_t c = 0; c < update_count; c++) {
      transport_conn_t *target = t->is_server ? t->conns[c] : t->client_conn;
      if (!target || !target->quic)
        continue;
      /* Pathflow needs only the primary RTT and congestion window. Reading
       * the complete connection counters for every peer every 25 ms copies
       * unrelated telemetry and polls the delivery-rate estimator. */
      quicly_path_stats_t primary;
      uint32_t primary_rtt, primary_cwnd;
      bool have_primary = quicly_get_path_stats(target->quic, 0, &primary) == 0;
      if (have_primary) {
        primary_rtt = primary.rtt_smoothed;
        primary_cwnd = primary.cwnd;
      } else {
        /* A primary address may disappear while its path space survives. */
        quicly_stats_t stats;
        if (quicly_get_stats(target->quic, &stats) != 0)
          continue;
        primary_rtt = (uint32_t)stats.rtt.smoothed;
        primary_cwnd = stats.cc.cwnd;
      }
      /* convert RTT to seconds */
      fp_t l = FP_DIV(FP_FROM_INT(primary_rtt), FP_FROM_INT(1000));

      /* convert bandwidth to packets/second */
      size_t cwnd_packets = primary_cwnd / symbol_size;
      if (cwnd_packets == 0)
        cwnd_packets = 1;
      uint32_t rtt_val = primary_rtt > 0 ? primary_rtt : 1;
      fp_t b = FP_FROM_INT(cwnd_packets * 1000 / rtt_val);
      if (b <= 0) {
        b = FP_FROM_INT(100);
      }

      fp_t p = FP_FROM_FLOAT(0.01f); /* default mock loss rate */
      size_t q = 0;                  /* bytes in flight or egress queue size */

      for (size_t i = 0; i < t->num_fds; i++) {
        if (target->path_state_overridden[i])
          continue;
        /* use path-specific stats if available, otherwise fallback to
         * connection defaults */
        fp_t path_l = l / 2;
        fp_t path_p = p;
        quicly_path_stats_t matched;
        const quicly_path_stats_t *path_stats = &primary;
        size_t path_idx = 0;
        /* Link lookup starts at path zero. Its snapshot was already read
         * above, and no QUIC state changes during this synchronous update. */
        if (!have_primary ||
            !transport_path_matches_local(&primary, &t->local_addrs[i])) {
          path_idx = transport_path_get_stats_by_link(
              target->quic, t->local_addrs, t->num_fds, i, &matched);
          path_stats = &matched;
        }
        if (path_idx < TRANSPORT_MAX_QUIC_PATHS) {
          if (path_stats->rtt_smoothed > 0) {
            path_l = FP_DIV(FP_FROM_INT(path_stats->rtt_smoothed),
                            FP_FROM_INT(2000));
          }
          if (path_stats->sent > 0) {
            path_p = FP_DIV(FP_FROM_INT(path_stats->lost),
                            FP_FROM_INT(path_stats->sent));
          }
        }

        if (target->latest_owd_fp[i] > 0) {
          path_l += target->latest_owd_fp[i];
        }

        pathflow_update_state(&target->path_states[i], b, path_l, path_p, q,
                              FP_FROM_FLOAT(0.1f));
      }
    }
  }

  size_t active_count = t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
  for (size_t i = 0; i < active_count; ++i) {
    transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
    if (!conn)
      continue;

    if (!conn->quic_ready && quicly_connection_is_ready(conn->quic)) {
      conn->quic_ready = true;
    }
    try_open_pending_paths(t, conn, now);
    if (conn->quic_ready)
      (void)transport_protocol_send_hello(conn);
    transport_protocol_maybe_emit_connected(conn);

    while (1) {
      bool egress_has_room = true;
      for (size_t p = 0; p < t->num_fds; p++) {
        if (!transport_egress_can_accept(&t->egress[p], 64U, 64U * 1500U)) {
          egress_has_room = false;
          break;
        }
      }
      if (!egress_has_room)
        break;

      quicly_address_t dest, src;
      struct iovec dgrams[64];
      uint8_t dgrams_buf[64 * 1500];
      size_t num_dgrams = 64;
      int send_res = quicly_send(conn->quic, &dest, &src, dgrams, &num_dgrams,
                                 dgrams_buf, sizeof(dgrams_buf));
      if (send_res == 0) {
        if (num_dgrams == 0) {
          if (!quicly_has_datagram_frames(conn->quic))
            memset(conn->queued_datagrams, 0, sizeof(conn->queued_datagrams));
          break;
        }

        size_t sent_path =
            transport_path_find_by_addresses(conn->quic, &src.sa, &dest.sa);
        if (sent_path < TRANSPORT_MAX_QUIC_PATHS)
          conn->queued_datagrams[sent_path] =
              (uint16_t)quicly_get_num_datagram_frames_path(conn->quic,
                                                            sent_path);

        size_t out_fd_index = SIZE_MAX;
        if (src.sa.sa_family == AF_INET) {
          struct sockaddr_in *src_in = (struct sockaddr_in *)&src.sa;
          for (size_t k = 0; k < t->num_fds; k++) {
            if (t->local_addrs[k].ss_family == AF_INET) {
              struct sockaddr_in *loc =
                  (struct sockaddr_in *)&t->local_addrs[k];
              if (loc->sin_addr.s_addr == src_in->sin_addr.s_addr) {
                out_fd_index = k;
                break;
              }
            }
          }
        } else if (src.sa.sa_family == AF_INET6) {
          struct sockaddr_in6 *src_in6 = (struct sockaddr_in6 *)&src.sa;
          for (size_t k = 0; k < t->num_fds; k++) {
            if (t->local_addrs[k].ss_family == AF_INET6) {
              struct sockaddr_in6 *loc =
                  (struct sockaddr_in6 *)&t->local_addrs[k];
              if (memcmp(&loc->sin6_addr, &src_in6->sin6_addr,
                         sizeof(struct in6_addr)) == 0) {
                out_fd_index = k;
                break;
              }
            }
          }
        }

        if (out_fd_index == SIZE_MAX) {
          t->stats.udp_send_errors += num_dgrams;
          transport_log(t, TRANSPORT_LOG_ERROR, "udp", conn->id, SIZE_MAX,
                        "no socket matches QUIC source address");
          continue;
        }

        if (!transport_egress_submit(
                &t->egress[out_fd_index], t->fds[out_fd_index], &dest.sa,
                quicly_get_socklen(&dest.sa), dgrams, num_dgrams))
          transport_log(t, TRANSPORT_LOG_WARNING, "udp", conn->id, out_fd_index,
                        "egress queue exhausted");
      } else if (send_res == QUICLY_ERROR_FREE_CONNECTION) {
        uint64_t offending_frame_type = UINT64_MAX;
        const char *reason = "";
        int is_remote = 0;
        quicly_error_t close_error = quicly_get_close_reason(
            conn->quic, &offending_frame_type, &reason, &is_remote);
        bool application_error = QUICLY_ERROR_IS_QUIC_APPLICATION(close_error);
        uint64_t error_code = QUICLY_ERROR_IS_QUIC(close_error)
                                  ? QUICLY_ERROR_GET_ERROR_CODE(close_error)
                                  : (uint64_t)close_error;
        if (!reason)
          reason = "";
        transport_log(t, TRANSPORT_LOG_INFO, "connection", conn->id, SIZE_MAX,
                      "closed origin=%s class=%s error=%" PRIu64 " raw=%" PRId64
                      " reason=%s",
                      is_remote ? "remote" : "local",
                      application_error
                          ? "application"
                          : (QUICLY_ERROR_IS_QUIC(close_error) ? "transport"
                                                               : "internal"),
                      error_code, (int64_t)close_error,
                      reason[0] ? reason : "none");
        transport_event_t ev = {
            .type = TRANSPORT_EVENT_DISCONNECTED,
            .conn = conn,
            .disconnect = {.error_code = error_code,
                           .raw_error = (int64_t)close_error,
                           .application_error = application_error,
                           .offending_frame_type = offending_frame_type,
                           .remote = is_remote != 0,
                           .reason = reason}};
        transport_emit_event(t, &ev);
        t->stats.connections_closed++;

        transport_flexicast_remove_connection(t, conn);
        transport_publish_checkpoint_connection_removed(t, conn);
        transport_connection_cache_forget(t, conn);
        quicly_free(conn->quic);
        for (size_t a = 0; a < t->limits.max_assemblers_per_connection; a++)
          transport_release_assembler(t, &conn->assemblers[a]);
        destroy_connection_subscriptions(conn);
        free(conn);

        if (t->is_server) {
          memmove(t->conns + i, t->conns + i + 1,
                  sizeof(t->conns[0]) * (t->conn_count - i - 1));
          t->conn_count--;
          i--;
          active_count = t->conn_count;
        } else {
          t->client_conn = NULL;
          active_count = 0;
          schedule_client_reconnect(t, transport_get_time_ms());
        }
        break;
      } else {
        quicly_close(conn->quic, send_res, "send failure");
        break;
      }
    }
  }
  transport_protocol_poll_lifecycle(t);
  transport_publish_poll_lifecycle(t);
  t->tick_active = false;
}

static bool subscribe_connection(transport_conn_t *conn,
                                 const moq_track_id_t *track_id) {
  if (!conn || !conn->protocol_ready || !conn->authenticated || !conn->stream ||
      !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;

  const track_subscription_t *existing = transport_subscriptions_find_const(
      &conn->receive_subscriptions, track_id);
  if (existing && existing->track_id.flags != track_id->flags)
    return false;
  uint8_t alias;
  bool newly_added = false;
  if (transport_subscriptions_find_alias(&conn->subscriptions, track_id,
                                         &alias) != 0) {
    if (transport_subscriptions_count(&conn->receive_subscriptions) >=
        conn->negotiated_limits.max_subscriptions_per_connection)
      return false;
    if (track_id->name[0] == '\0') {
      alias = (uint8_t)track_id->type;
    } else {
      int next_alias =
          transport_subscriptions_next_alias(&conn->receive_subscriptions, 8);
      if (next_alias < 0)
        return false;
      alias = (uint8_t)next_alias;
    }
    if (!transport_subscriptions_add(&conn->receive_subscriptions,
                                     track_id->type, track_id->flags,
                                     track_id->name, alias))
      return false;
    newly_added = true;
  }

  if (!transport_stream_write_track_frame(conn->stream, QLINQ_WIRE_SUBSCRIBE,
                                          alias, track_id)) {
    if (newly_added)
      transport_subscriptions_remove(&conn->receive_subscriptions,
                                     track_id->type, track_id->name);
    return false;
  if (newly_added)
    memset(&conn->object_gaps[alias], 0, sizeof(conn->object_gaps[alias]));
  transport_publish_checkpoint_member_added(conn->transport, conn, track_id,
                                            alias);
  return true;
}

bool transport_subscribe_conn(transport_t *t, transport_conn_t *conn,
                              moq_track_id_t track_id) {
  if (!transport_owner_ok(t) || !transport_track_id_valid(&track_id) ||
      !transport_has_connection(t, conn))
    return false;
  return subscribe_connection(conn, &track_id);
}

bool transport_subscribe(transport_t *t, moq_track_id_t track_id) {
  if (!transport_owner_ok(t) || !transport_track_id_valid(&track_id))
    return false;
  if (!t->is_server)
    return t->client_conn && subscribe_connection(t->client_conn, &track_id);

  bool found = false;
  bool succeeded = true;
  for (size_t i = 0; i < t->conn_count; i++) {
    transport_conn_t *conn = t->conns[i];
    if (!conn || !conn->protocol_ready || !conn->authenticated)
      continue;
    found = true;
    if (!subscribe_connection(conn, &track_id))
      succeeded = false;
  }
  return !found || succeeded;
}

static bool unsubscribe_connection(transport_t *t, transport_conn_t *conn,
                                   const moq_track_id_t *track_id) {
  if (!conn || !conn->protocol_ready || !conn->authenticated || !conn->stream ||
      !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;

  const track_subscription_t *subscription = transport_subscriptions_find_const(
      &conn->receive_subscriptions, track_id);
  if (!subscription)
    return false;
  moq_track_id_t subscribed_track = subscription->track_id;
  uint8_t alias = subscription->alias;
  if (!transport_stream_write_track_frame(conn->stream, QLINQ_WIRE_UNSUBSCRIBE,
                                          alias, &subscribed_track))
    return false;

  transport_publish_checkpoint_member_removed(t, conn, &subscribed_track,
                                              alias);
  transport_flexicast_unsubscribe(t, conn, &subscribed_track);
  transport_subscriptions_remove(&conn->subscriptions, subscribed_track.type,
                                 subscribed_track.name);
  return true;
}

bool transport_unsubscribe(transport_t *t, moq_track_id_t track_id) {
  if (!transport_owner_ok(t) || !transport_track_id_valid(&track_id))
    return false;

  if (!t->is_server)
    return t->client_conn &&
           unsubscribe_connection(t, t->client_conn, &track_id);

  bool found = false;
  bool succeeded = true;
  for (size_t i = 0; i < t->conn_count; i++) {
    transport_conn_t *conn = t->conns[i];
    if (!conn || !transport_subscriptions_contains(&conn->receive_subscriptions,
                                                   &track_id))
      continue;
    found = true;
    if (!unsubscribe_connection(t, conn, &track_id))
      succeeded = false;
  }
  return found && succeeded;
}

bool transport_request_keyframe(transport_t *t, moq_track_id_t track_id) {
  if (!transport_owner_ok(t) || !transport_track_id_valid(&track_id) ||
      t->is_server || !t->client_conn || !t->client_conn->protocol_ready ||
      !t->client_conn->authenticated || !t->client_conn->stream ||
      !quicly_sendstate_is_open(&t->client_conn->stream->sendstate))
    return false;

  return transport_stream_write_track_frame(
      t->client_conn->stream, QLINQ_WIRE_KEYFRAME_REQUEST, 0, &track_id);
}

bool transport_send_unicast(transport_t *t, transport_conn_t *conn,
                            const void *data, size_t size) {
  if (!transport_owner_ok(t) || size > t->limits.max_reliable_object_size ||
      (size > 0 && !data))
    return false;
  if (!transport_has_connection(t, conn) || !conn->protocol_ready ||
      !conn->stream || !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;

  return transport_stream_write_frame(conn->stream, QLINQ_WIRE_UNICAST, data,
                                      size);
}

void transport_close_conn(transport_t *t, transport_conn_t *conn) {
  transport_close_conn_with_error(t, conn, 0, "application close");
}

void transport_close_conn_with_error(transport_t *t, transport_conn_t *conn,
                                     int64_t error, const char *reason) {
  if (!transport_owner_ok(t))
    return;
  if (error != 0 && !QUICLY_ERROR_IS_QUIC_APPLICATION(error))
    return;
  if (transport_has_connection(t, conn) && conn->quic &&
      quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING) {
    if (error == TRANSPORT_APP_ERROR_RESOURCE_LIMIT)
      t->stats.resource_limit_errors++;
    quicly_close(conn->quic, error, reason ? reason : "application close");
  }
}

void transport_shutdown(transport_t *t, const char *reason) {
  if (!transport_owner_ok(t))
    return;
  t->shutting_down = true;
  t->reconnect_in_progress = false;
  const char *phrase = reason && reason[0] ? reason : "application shutdown";
  size_t count = t->is_server ? t->conn_count : (t->client_conn ? 1U : 0U);
  for (size_t i = 0; i < count; i++) {
    transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
    if (conn && conn->quic &&
        quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING)
      (void)quicly_close(conn->quic, 0, phrase);
  }
}

bool transport_is_drained(transport_t *t) {
  if (!transport_owner_ok(t))
    return false;
  if (t->is_server ? t->conn_count != 0 : t->client_conn != NULL)
    return false;
  for (size_t i = 0; i < t->num_fds; i++) {
    if (t->egress[i].count != 0)
      return false;
  }
  return true;
}

static void dispose_tls_identity(ptls_context_t *tls,
                                 ptls_openssl_sign_certificate_t *signer) {
  if (!tls || !signer)
    return;
  if (tls->sign_certificate)
    ptls_openssl_dispose_sign_certificate(signer);
  for (size_t i = 0; i < tls->certificates.count; i++)
    free(tls->certificates.list[i].base);
  free(tls->certificates.list);
  tls->certificates.list = NULL;
  tls->certificates.count = 0;
  tls->sign_certificate = NULL;
}

bool transport_reload_credentials(transport_t *t, const char *cert_file,
                                  const char *key_file) {
  if (!transport_owner_ok(t) || !cert_file || !key_file)
    return false;
  ptls_context_t candidate = {0};
  ptls_openssl_sign_certificate_t candidate_signer = {0};
  if (transport_tls_load_certificate_and_key(&candidate, &candidate_signer,
                                             cert_file, key_file) != 0) {
    dispose_tls_identity(&candidate, &candidate_signer);
    transport_log(t, TRANSPORT_LOG_ERROR, "tls", 0, SIZE_MAX,
                  "credential reload failed; retaining current identity");
    return false;
  }

  dispose_tls_identity(&t->tls_ctx, &t->sign_cert);
  t->sign_cert = candidate_signer;
  t->tls_ctx.certificates = candidate.certificates;
  t->tls_ctx.sign_certificate = &t->sign_cert.super;
  transport_log(t, TRANSPORT_LOG_INFO, "tls", 0, SIZE_MAX,
                "credentials reloaded for future handshakes");
  return true;
}

bool transport_send_auth(transport_t *t, transport_conn_t *conn,
                         const uint8_t *token, size_t token_len) {
  if (!transport_owner_ok(t))
    return false;
  if (!transport_has_connection(t, conn) || !conn->protocol_ready ||
      !conn->stream || !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;
  if (token_len > 65535 || (token_len > 0 && !token))
    return false;

  return transport_stream_write_frame(conn->stream, QLINQ_WIRE_AUTH_REQUEST,
                                      token, token_len);
}

bool transport_respond_auth(transport_t *t, transport_conn_t *conn,
                            bool success) {
  if (!transport_owner_ok(t))
    return false;
  if (!transport_has_connection(t, conn) || !conn->protocol_ready ||
      !conn->stream || !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;

  uint8_t status = success ? 1 : 0;
  if (!transport_stream_write_frame(conn->stream, QLINQ_WIRE_AUTH_RESPONSE,
                                    &status, sizeof(status)))
    return false;

  if (success) {
    conn->authenticated = true;
  } else {
    quicly_close(conn->quic, TRANSPORT_APP_ERROR_AUTHENTICATION,
                 "authentication failed");
  }
  return true;
}

uint64_t transport_get_estimated_bandwidth(transport_t *t) {
  if (!transport_owner_ok(t))
    return 0;
  transport_conn_t *conn =
      t->is_server ? (t->conn_count > 0 ? t->conns[0] : NULL) : t->client_conn;
  if (!conn || !conn->quic) {
    return 0;
  }
  quicly_stats_t stats;
  uint64_t rate = 0;
  if (quicly_get_stats(conn->quic, &stats) == 0) {
    rate = stats.delivery_rate.latest;
  }
  return rate;
}

static bool transport_has_connection(const transport_t *t,
                                     const transport_conn_t *conn) {
  if (!t || !conn)
    return false;
  if (!t->is_server)
    return t->client_conn == conn;
  for (size_t i = 0; i < t->conn_count; i++) {
    if (t->conns[i] == conn)
      return true;
  }
  return false;
}

bool transport_get_stats(transport_t *t, transport_stats_t *stats) {
  if (!transport_owner_ok(t) || !stats)
    return false;
  *stats = t->stats;
  stats->recovery_cache_payload_bytes = t->sent_cache.payload_bytes;
  stats->recovery_cache_peak_payload_bytes = t->sent_cache.peak_payload_bytes;
  stats->recovery_cache_entries = t->sent_cache.count;
  stats->recovery_cache_peak_entries = t->sent_cache.peak_count;
  stats->api_thread_violations +=
      atomic_load_explicit(&t->cross_thread_violations, memory_order_relaxed);
  stats->active_connections =
      t->is_server ? t->conn_count : (t->client_conn ? 1U : 0U);
  stats->assembler_memory_bytes = t->assembler_memory_bytes;
  stats->flexicast_cc_mode = t->flexicast_cc_mode;
  stats->flexicast_active_flows = 0;
  stats->flexicast_active_members = 0;
  int64_t now_ms = transport_get_time_ms();
  size_t active_count =
      t->is_server ? t->conn_count : (t->client_conn ? 1U : 0U);
  for (size_t i = 0; i < active_count; i++) {
    const transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
    if (!conn)
      continue;
    for (size_t slot = 0; slot < conn->send_subscriptions.capacity; slot++) {
      const track_subscription_t *sub = &conn->send_subscriptions.entries[slot];
      if (!sub->active)
        continue;
      uint8_t alias = sub->alias;
      const transport_checkpoint_ack_state_t *ack =
          transport_checkpoint_ack(conn, alias);
      if (!ack || !ack->participating || !ack->sent_initialized ||
          (ack->acked_initialized &&
           ack->acked_group_id == ack->sent_group_id &&
           ack->acked_object_id >= ack->sent_object_id))
        continue;
      stats->recovery_checkpoints_pending++;
      if (ack->oldest_unacked_sent_at_ms > 0 &&
          now_ms > ack->oldest_unacked_sent_at_ms &&
          (uint64_t)(now_ms - ack->oldest_unacked_sent_at_ms) >
              stats->recovery_oldest_checkpoint_age_ms)
        stats->recovery_oldest_checkpoint_age_ms =
            (uint64_t)(now_ms - ack->oldest_unacked_sent_at_ms);
    }
  }
  for (size_t f = 0; f < t->flexicast.capacity; f++) {
    const transport_flexicast_flow_t *flow = &t->flexicast.flows[f];
    if (!flow->active)
      continue;
    stats->flexicast_active_flows++;
    if (flow->source)
      stats->flexicast_active_members +=
          transport_flexicast_listening_members(flow);
    stats->flexicast_queued_packets +=
        flow->queue_count + flow->repair_queue_count;
    stats->flexicast_queued_bytes +=
        flow->queue_bytes + flow->repair_queue_bytes;
    stats->repair_queued_packets += flow->repair_queue_count;
    stats->repair_queued_bytes += flow->repair_queue_bytes;
    stats->repair_pending_objects += flow->pending_repair_count;
    for (size_t i = 0; i < flow->repair_queue_count; i++) {
      size_t slot = (flow->repair_queue_head + i) %
                    TRANSPORT_FLEXICAST_REPAIR_QUEUE_CAPACITY;
      int64_t enqueued = flow->repair_queued[slot].enqueued_at_ms;
      if (enqueued > 0 && now_ms > enqueued &&
          (uint64_t)(now_ms - enqueued) > stats->repair_oldest_age_ms)
        stats->repair_oldest_age_ms = (uint64_t)(now_ms - enqueued);
    }
    for (size_t i = 0; i < TRANSPORT_FLEXICAST_PENDING_REPAIRS; i++) {
      int64_t requested = flow->pending_repairs[i].first_request_ms;
      if (flow->pending_repairs[i].active && requested > 0 &&
          now_ms > requested &&
          (uint64_t)(now_ms - requested) > stats->repair_oldest_age_ms)
        stats->repair_oldest_age_ms = (uint64_t)(now_ms - requested);
    }
    if (flow->pacing_rate_bytes_per_second != 0 &&
        (stats->flexicast_pacing_rate_bytes_per_second == 0 ||
         flow->pacing_rate_bytes_per_second <
             stats->flexicast_pacing_rate_bytes_per_second)) {
      stats->flexicast_pacing_rate_bytes_per_second =
          flow->pacing_rate_bytes_per_second;
      if (flow->source && flow->crypto) {
        quicly_flexicast_cc_output_t output;
        quicly_flexicast_cc_get_flow_output(flow->crypto, &output);
        stats->flexicast_cc_rate_bytes_per_second =
            output.rate_bytes_per_second;
        stats->flexicast_cc_burst_bytes = output.burst_bytes;
        stats->flexicast_cc_limiting_member = output.limiting_member_id;
      }
    }
    if (flow->source && flow->crypto) {
      quicly_flexicast_cc_output_t output;
      quicly_flexicast_cc_get_flow_output(flow->crypto, &output);
      stats->flexicast_cc_rate_increase_events += output.rate_increase_events;
      stats->flexicast_cc_rate_reduction_events += output.rate_reduction_events;
      stats->flexicast_cc_floor_entry_events += output.floor_entry_events;
      stats->flexicast_cc_floor_exit_events += output.floor_exit_events;
      stats->flexicast_cc_ack_growth_events += output.ack_growth_events;
      stats->flexicast_cc_other_growth_events += output.other_growth_events;
      stats->flexicast_cc_loss_reduction_events += output.loss_reduction_events;
      stats->flexicast_cc_rtt_reduction_events += output.rtt_reduction_events;
      stats->flexicast_cc_ecn_reduction_events += output.ecn_reduction_events;
      stats->flexicast_cc_timeout_reduction_events +=
          output.timeout_reduction_events;
      stats->flexicast_cc_rate_limit_reduction_events +=
          output.rate_limit_reduction_events;
      stats->flexicast_cc_other_reduction_events +=
          output.other_reduction_events;
      stats->flexicast_cc_external_load_growth_freeze_events +=
          output.external_load_growth_freeze_events;
    }
  }
  for (size_t m = 0; m < t->flexicast.capacity; m++)
    stats->flexicast_active_memberships += t->flexicast.memberships[m].active;
  for (size_t i = 0; i < t->num_fds; i++) {
    const transport_egress_t *egress = &t->egress[i];
    stats->udp_packets_sent += egress->packets_sent;
    stats->udp_bytes_sent += egress->bytes_sent;
    stats->udp_would_block += egress->would_block;
    stats->udp_send_errors += egress->send_errors;
    stats->egress_packets_queued += egress->packets_queued;
    stats->egress_bytes_queued += egress->bytes_queued;
    stats->egress_packets_dropped += egress->packets_dropped;
    stats->egress_current_packets += egress->count;
    stats->egress_current_bytes += egress->bytes;
    if (egress->peak_count > stats->egress_peak_packets)
      stats->egress_peak_packets = egress->peak_count;
    if (egress->peak_bytes > stats->egress_peak_bytes)
      stats->egress_peak_bytes = egress->peak_bytes;
  }
  return true;
}

bool transport_get_conn_stats(transport_t *t, transport_conn_t *conn,
                              transport_conn_stats_t *stats) {
  if (!transport_owner_ok(t) || !stats || !transport_has_connection(t, conn))
    return false;
  memset(stats, 0, sizeof(*stats));
  stats->id = conn->id;
  stats->quic_ready = conn->quic_ready;
  stats->protocol_ready = conn->protocol_ready;
  stats->authenticated = conn->authenticated;
  stats->subscriptions =
      transport_subscriptions_count(&conn->receive_subscriptions) +
      transport_subscriptions_count(&conn->send_subscriptions);
  stats->peer_capabilities = conn->peer_capabilities;
  stats->negotiated_limits = conn->negotiated_limits;
  stats->stream_frames_received = conn->stream_frames_received;
  stats->datagrams_received = conn->datagrams_received;
  stats->malformed_datagrams = conn->malformed_datagrams;
  quicly_stats_t quic_stats;
  if (quicly_get_stats(conn->quic, &quic_stats) == 0) {
    stats->quic_paths_created = quic_stats.num_paths.created;
    stats->quic_paths_validated = quic_stats.num_paths.validated;
    stats->quic_paths_validation_failed =
        quic_stats.num_paths.validation_failed;
  }
  return true;
}

uint32_t transport_get_conn_id(transport_t *t, transport_conn_t *conn) {
  return transport_owner_ok(t) && transport_has_connection(t, conn) ? conn->id
                                                                    : 0;
}

transport_repair_mode_t
transport_get_effective_repair_mode(transport_t *t, transport_conn_t *conn,
                                    const moq_track_id_t *track_id) {
  if (!transport_owner_ok(t) || !transport_has_connection(t, conn) ||
      !transport_track_id_valid(track_id))
    return TRANSPORT_REPAIR_MODE_INDEXED;
  return t->repair_mode != TRANSPORT_REPAIR_MODE_INDEXED &&
                 (track_id->flags & MOQ_TRACK_FLAG_FEC_RATELESS) != 0 &&
                 (conn->peer_capabilities & QLINQ_WIRE_CAP_RATELESS_REPAIR) != 0
             ? TRANSPORT_REPAIR_MODE_RATELESS
             : TRANSPORT_REPAIR_MODE_INDEXED;
}

int transport_enable_qlog(const char *socket_path) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    CLOSE_SOCKET(fd);
    return -1;
  }

  /* Set non-blocking to prevent logging from hanging the main transport thread
   */
  if (!set_fd_nonblocking(fd)) {
    CLOSE_SOCKET(fd);
    return -1;
  }

  /* enable picotls and quicly tracing, sample ratio 1.0 (all logs), write to fd
   */
  ptls_log_add_fd(fd, 1.0, NULL, NULL, NULL, 0);
  ptls_log_add_fd(fd, 1.0, NULL, NULL, NULL, 1);
  return 0;
}

bool transport_get_path_stats(transport_t *t, size_t path_idx,
                              transport_path_stats_t *stats) {
  if (!transport_owner_ok(t) || !stats || path_idx >= t->num_fds)
    return false;

  memset(stats, 0, sizeof(*stats));
  stats->interface_index = t->local_ifindices[path_idx];
  copy_interface_name(stats->interface_name, t->local_ifnames[path_idx]);
  const void *address = NULL;
  if (t->local_addrs[path_idx].ss_family == AF_INET)
    address =
        &((const struct sockaddr_in *)&t->local_addrs[path_idx])->sin_addr;
  else if (t->local_addrs[path_idx].ss_family == AF_INET6)
    address =
        &((const struct sockaddr_in6 *)&t->local_addrs[path_idx])->sin6_addr;
  if (address)
    (void)inet_ntop(t->local_addrs[path_idx].ss_family, address,
                    stats->local_address, sizeof(stats->local_address));
  if (!stats->interface_name[0])
    copy_interface_name(stats->interface_name, stats->local_address);
  stats->bytes_sent = t->egress[path_idx].bytes_sent;
  stats->bytes_received = t->udp_bytes_received[path_idx];

  transport_conn_t *target =
      t->is_server ? (t->conn_count > 0 ? t->conns[0] : NULL) : t->client_conn;
  stats->lifecycle = t->shutting_down
                         ? TRANSPORT_PATH_DRAINING
                         : (target ? TRANSPORT_PATH_DISCOVERED
                                   : (t->is_server ? TRANSPORT_PATH_DISCOVERED
                                                   : TRANSPORT_PATH_FAILED));
  if (target && target->quic) {
    quicly_path_stats_t path_stats;
    size_t mapped_path_idx = transport_path_get_stats_by_link(
        target->quic, t->local_addrs, t->num_fds, path_idx, &path_stats);
    if (quicly_get_state(target->quic) >= QUICLY_STATE_CLOSING) {
      stats->lifecycle = TRANSPORT_PATH_DRAINING;
    } else if (mapped_path_idx >= TRANSPORT_MAX_QUIC_PATHS) {
      stats->lifecycle = t->path_open_pending[path_idx]
                             ? TRANSPORT_PATH_OPENING
                             : TRANSPORT_PATH_DISCOVERED;
    } else if (!quicly_is_path_available(target->quic, mapped_path_idx)) {
      stats->lifecycle = TRANSPORT_PATH_VALIDATING;
    } else {
      stats->lifecycle = TRANSPORT_PATH_ACTIVE;
      stats->sent = path_stats.sent;
      stats->lost = path_stats.lost;
      stats->rtt = path_stats.rtt_smoothed;
    }
  }

  stats->relative_owd =
      target ? (double)FP_TO_FLOAT(target->latest_owd_fp[path_idx]) * 1000.0
             : 0.0;
  stats->ewma_latency =
      target
          ? (double)FP_TO_FLOAT(target->path_states[path_idx].l_ewma) * 1000.0
          : 0.0;

  return true;
}

static void transport_mock_iface_change(transport_t *t, const char *ip_addr,
                                        bool added) {
  if (!transport_owner_ok(t) || t->ifmon_pipe[1] < 0)
    return;

  ifmon_pipe_msg_t msg = {0};
  msg.is_added = added ? 1 : 0;
  msg.index = 1; /* loopback interface index */
  struct sockaddr_in *sin = (struct sockaddr_in *)&msg.addr;
  sin->sin_family = AF_INET;
  if (!ip_addr || inet_pton(AF_INET, ip_addr, &sin->sin_addr) != 1)
    return;
  msg.addr_len = sizeof(*sin);

  ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
  (void)w;
}

/* deterministic interface changes for integration tests */
void transport_mock_iface_add(transport_t *t, const char *ip_addr) {
  transport_mock_iface_change(t, ip_addr, true);
}

void transport_mock_iface_remove(transport_t *t, const char *ip_addr) {
  transport_mock_iface_change(t, ip_addr, false);
}

bool transport_mock_path_state(transport_t *t, size_t path_idx,
                               uint32_t packets_per_second, double latency_ms,
                               double loss_rate) {
  if (!transport_owner_ok(t) || path_idx >= t->num_fds ||
      packets_per_second == 0 || latency_ms < 0.0 || loss_rate < 0.0 ||
      loss_rate > 1.0)
    return false;
  size_t active_count = t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
  if (active_count == 0)
    return false;
  for (size_t i = 0; i < active_count; i++) {
    transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
    if (!conn)
      continue;
    path_state_t *state = &conn->path_states[path_idx];
    state->initialized = 1;
    state->b_ewma = FP_FROM_INT(packets_per_second);
    state->l_ewma = FP_FROM_FLOAT((float)(latency_ms / 1000.0));
    state->p_ewma = FP_FROM_FLOAT((float)loss_rate);
    state->q_ewma = 0;
    conn->path_state_overridden[path_idx] = true;
  }
  return true;
}

size_t transport_get_datagram_symbol_size(const transport_t *t) {
  if (!t || !transport_owner_ok((transport_t *)t))
    return 0;
  size_t udp_payload_size = t->limits.max_udp_payload_size;
  size_t active_count = t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
  for (size_t i = 0; i < active_count; i++) {
    const transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
    if (conn && conn->protocol_ready &&
        conn->negotiated_limits.max_udp_payload_size < udp_payload_size)
      udp_payload_size = conn->negotiated_limits.max_udp_payload_size;
  }
  size_t symbol_size = udp_payload_size > 80U ? udp_payload_size - 80U : 0U;
  return symbol_size < 1000 ? 1000 : symbol_size;
}

bool transport_is_track_ready(transport_t *t, const moq_track_id_t *track_id) {
  if (!transport_owner_ok(t) || !transport_track_id_valid(track_id))
    return false;

  if (!transport_publish_recovery_ready(t, track_id))
    return false;

  for (size_t i = 0; i < t->num_fds; i++) {
    const transport_egress_t *egress = &t->egress[i];
    if (egress->count >= egress->capacity * 3U / 4U ||
        egress->bytes >= egress->max_bytes * 3U / 4U)
      return false;
  }

  transport_track_profile_t profile = transport_track_profile(track_id);

  if (!profile.reliable && t->is_server && t->flexicast_enabled &&
      !transport_flexicast_track_ready(t, track_id))
    return false;

  size_t active_count = t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
  if (active_count == 0)
    return true; /* no peers means data is dropped anyway, so it's "ready" */

  bool all_ready = true;
  for (size_t c = 0; c < active_count; c++) {
    transport_conn_t *conn = t->is_server ? t->conns[c] : t->client_conn;
    if (!conn || !conn->quic ||
        quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING)
      continue;

    if (!t->is_server && (!conn->authenticated || !conn->protocol_ready))
      return false;
    if (!transport_publish_recipient_eligible(t, conn, track_id))
      continue;
    const track_subscription_t *mode =
        transport_subscriptions_find_const(&conn->send_subscriptions, track_id);
    if (mode && mode->track_id.flags != track_id->flags)
      return false;

    if (profile.reliable) {
      const track_subscription_t *subscription =
          transport_subscriptions_find_const(&conn->send_subscriptions,
                                             track_id);
      quicly_stream_t *stream = subscription ? subscription->stream : NULL;

      if (stream) {
        if (!transport_stream_can_accept(
                stream,
                QLINQ_WIRE_FRAME_HEADER_SIZE +
                    QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE,
                true)) {
          all_ready = false;
          break;
        }
      }
    } else {
      for (size_t p = 0; p < TRANSPORT_MAX_QUIC_PATHS; p++) {
        conn->queued_datagrams[p] =
            (uint16_t)quicly_get_num_datagram_frames_path(conn->quic, p);
        if (conn->queued_datagrams[p] >=
            QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY * 3 / 4) {
          all_ready = false;
          break;
        }
      }
      if (!all_ready)
        break;
      quicly_path_stats_t pstats;
      if (quicly_get_path_stats(conn->quic, 0, &pstats) == 0) {
        if (pstats.bytes_in_flight >= pstats.cwnd * 2) {
          all_ready = false;
          break;
        }
      }
    }
  }

  return all_ready;
}

int64_t transport_get_time_ms(void) {
  return (int64_t)ptls_get_time.cb(&ptls_get_time);
}

int64_t transport_get_first_timeout(transport_t *t) {
  if (!transport_owner_ok(t))
    return INT64_MAX;

  int64_t first_timeout = t->aggregate_nack_retry_at_ms > 0
                              ? t->aggregate_nack_retry_at_ms
                              : INT64_MAX;
  size_t active_conns = t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
  for (size_t c = 0; c < active_conns; c++) {
    transport_conn_t *conn = t->is_server ? t->conns[c] : t->client_conn;
    if (!conn || !conn->quic ||
        quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING)
      continue;
    for (size_t i = 0; i < t->limits.max_assemblers_per_connection; i++) {
      const frame_assembler_t *assembler = &conn->assemblers[i];
      if (assembler->total_symbols == 0)
        continue;
      int64_t expires =
          assembler->last_activity_time_ms >
                  INT64_MAX - t->fec_assembler_timeout_ms
              ? INT64_MAX
              : assembler->last_activity_time_ms + t->fec_assembler_timeout_ms;
      if (expires < first_timeout)
        first_timeout = expires;
    }
  }

  if (active_conns != 0 && t->last_pathflow_update <= INT64_MAX - 25 &&
      (int64_t)t->last_pathflow_update + 25 < first_timeout)
    first_timeout = (int64_t)t->last_pathflow_update + 25;
  if (t->fec_buf_len != 0 && t->fec_first_pkt_time <= INT64_MAX - 3 &&
      (int64_t)t->fec_first_pkt_time + 3 < first_timeout)
    first_timeout = (int64_t)t->fec_first_pkt_time + 3;

  if (!t->is_server && !t->client_conn && t->reconnect_enabled &&
      !t->shutting_down && t->reconnect_at_ms < first_timeout)
    first_timeout = t->reconnect_at_ms;

  if (t->client_conn && t->client_conn->quic) {
    int64_t to = quicly_get_first_timeout(t->client_conn->quic);
    if (to < first_timeout)
      first_timeout = to;
  }

  for (size_t i = 0; i < t->conn_count; i++) {
    if (t->conns[i] && t->conns[i]->quic) {
      int64_t to = quicly_get_first_timeout(t->conns[i]->quic);
      if (to < first_timeout)
        first_timeout = to;
    }
  }

  int64_t flexicast_timeout = transport_flexicast_get_first_timeout(t);
  if (flexicast_timeout < first_timeout)
    first_timeout = flexicast_timeout;

  return first_timeout;
}

size_t transport_get_poll_fds(transport_t *t, struct pollfd *fds,
                              size_t max_fds) {
  if (!transport_owner_ok(t) || !fds)
    return 0;

  size_t count = 0;
  for (size_t i = 0; i < t->num_fds && count < max_fds; i++) {
    if (t->fds[i] >= 0) {
      fds[count].fd = t->fds[i];
      fds[count].events = POLLIN;
      if (t->egress[i].count > 0)
        fds[count].events |= POLLOUT;
      fds[count].revents = 0;
      count++;
    }
  }
  for (size_t i = 0; i < 2 && count < max_fds; i++)
    if (t->flexicast_fds[i] >= 0) {
      fds[count].fd = t->flexicast_fds[i];
      fds[count].events = POLLIN;
      fds[count].revents = 0;
      count++;
    }
  return count;
}

bool transport_get_track_stats(transport_t *t, const moq_track_id_t *track,
                               transport_track_stats_t *stats) {
  if (!transport_owner_ok(t) || !transport_track_id_valid(track) || !stats)
    return false;
  *stats = (transport_track_stats_t){0};
  size_t count = t->is_server ? t->conn_count : (t->client_conn ? 1U : 0U);
  for (size_t i = 0; i < count; i++) {
    transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
    uint8_t alias;
    if (conn && conn->authenticated && conn->quic &&
        quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING &&
        transport_subscriptions_find_alias(&conn->send_subscriptions, track,
                                           &alias) == 0)
      stats->subscribers++;
  }
  return true;
}
