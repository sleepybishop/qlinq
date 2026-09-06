#ifndef QLINQ_TRANSPORT_INTERNAL_H
#define QLINQ_TRANSPORT_INTERNAL_H

#include "ifmon.h"
#include "pathflow.h"
#include "transport.h"
#include "transport_egress.h"
#include "transport_fec_state.h"
#include "transport_flexicast.h"
#include "transport_memory.h"
#include "transport_paths.h"
#include "transport_repair.h"
#include "transport_repair_planner.h"
#include "transport_subscriptions.h"

#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>

#define QLINQ_FEC_ASSEMBLER_TIMEOUT_MS 2000
#define QLINQ_FEC_NACK_DELAY_MS 25
#define QLINQ_FEC_MULTICAST_NACK_BACKOFF_MAX_MS 250
#define QLINQ_FEC_MULTICAST_NACK_RETRY_BASE_MS 500
#define QLINQ_FEC_MULTICAST_NACK_RETRY_MAX_MS 1000
#define QLINQ_FEC_REPAIR_SUPPRESSION_MS 250
#define QLINQ_FEC_COMPLETION_RETRY_MS 500
#define QLINQ_RECOVERY_WINDOW_OBJECTS 32U
#define QLINQ_RECOVERY_MAX_WINDOWS 8U
#define QLINQ_RECOVERY_HISTORY_OBJECTS                                         \
  (QLINQ_RECOVERY_WINDOW_OBJECTS * QLINQ_RECOVERY_MAX_WINDOWS)
#define QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY 256U

typedef struct {
  bool active;
  uint64_t group_id;
  uint64_t first_object_id;
  uint64_t final_object_id;
  uint32_t missing_mask;
  uint32_t requested_mask;
  uint8_t cursor;
  uint16_t nack_attempt;
  int64_t last_request_ms;
} transport_recovery_window_t;

uint64_t transport_multicast_nack_retry_backoff_ms(uint16_t attempt);

typedef struct {
  uint64_t last_seen;
  bool seen_initialized;
  uint64_t pending_base;
  uint32_t pending_mask;
  uint32_t requested_mask;
  uint64_t group_id;
  int64_t detected_at_ms;
  uint16_t nack_attempt;
  uint64_t largest_delivered;
  uint64_t delivered_mask[QLINQ_RECOVERY_HISTORY_OBJECTS / 64U];
  bool delivered_initialized;
  bool checkpoint_initialized;
  bool shared_delivery;
  uint64_t last_checkpoint_object_id;
  bool finish_pending;
  bool finish_emitted;
  bool aborted;
  uint64_t finish_group_id;
  uint64_t finish_object_id;
  transport_recovery_window_t recovery_windows[QLINQ_RECOVERY_MAX_WINDOWS];
} transport_object_gap_state_t;

typedef struct {
  moq_track_id_t track_id;
  uint64_t next_object_id;
  bool active;
  bool has_objects;
  bool checkpoint_initialized;
  uint64_t checkpoint_group_id;
  uint64_t last_checkpoint_object_id;
  bool finish_started;
  bool drain_emitted;
  bool aborted;
  size_t finish_targets;
  size_t finish_completed;
  size_t finish_failed;
} transport_fec_track_state_t;

typedef struct {
  bool participating;
  bool retired;
  bool sent_initialized;
  uint64_t sent_group_id;
  uint64_t sent_object_id;
  int64_t oldest_unacked_sent_at_ms;
  bool acked_initialized;
  uint64_t acked_group_id;
  uint64_t acked_object_id;
  bool finish_target;
  bool finish_accounted;
} transport_checkpoint_ack_state_t;

struct transport_t {
  transport_callback_t callback;
  void *user_data;
  transport_log_callback_t log_callback;
  void *log_user_data;
  bool is_server;
  bool shutting_down;
  bool reconnect_enabled;
  bool reconnect_in_progress;
  uint32_t reconnect_initial_delay_ms;
  uint32_t reconnect_max_delay_ms;
  uint32_t reconnect_current_delay_ms;
  int64_t reconnect_at_ms;
  char server_name[256];
  int fds[TRANSPORT_MAX_PATHS];
  size_t num_fds;
  struct sockaddr_storage local_addrs[TRANSPORT_MAX_PATHS];
  socklen_t local_addrs_len[TRANSPORT_MAX_PATHS];
  uint32_t local_ifindices[TRANSPORT_MAX_PATHS];
  char local_ifnames[TRANSPORT_MAX_PATHS][64];
  char path_interface_names[TRANSPORT_MAX_PATHS][64];
  size_t num_path_interface_names;
  uint64_t udp_bytes_received[TRANSPORT_MAX_PATHS];
  transport_egress_t egress[TRANSPORT_MAX_PATHS];
  size_t local_remote_indices[TRANSPORT_MAX_PATHS];
  bool path_open_pending[TRANSPORT_MAX_PATHS];
  uint64_t path_open_retry_at[TRANSPORT_MAX_PATHS];
  transport_limits_t limits;
  transport_stats_t stats;
  atomic_uint_fast64_t cross_thread_violations;
  pthread_t owner_thread;
  bool tick_active;
  bool log_callback_active;
  size_t receive_cursor;
  size_t callback_depth;

  struct sockaddr_storage remote_addrs[TRANSPORT_MAX_PATHS];
  socklen_t remote_addrs_len[TRANSPORT_MAX_PATHS];
  size_t num_remote_addrs;
  quicly_context_t quic_ctx;
  ptls_context_t tls_ctx;
  ptls_openssl_sign_certificate_t sign_cert;
  quicly_cid_plaintext_t next_cid;

  uint64_t last_pathflow_update;
  transport_conn_t **conns;
  size_t conn_count;
  uint32_t next_conn_id;
  transport_conn_t *client_conn;
  transport_conn_t *connection_cache[QLINQ_CONNECTION_CACHE_SLOTS];

  quicly_stream_open_t stream_open;
  ptls_openssl_verify_certificate_t verifier;
  bool verifier_initialized;
  quicly_receive_datagram_frame_t receive_datagram;
  quicly_receive_flexicast_frame_t receive_flexicast;
  quicly_receive_flexicast_ack_t receive_flexicast_ack;

  transport_sent_cache_t sent_cache;
  uint8_t simulated_loss_rate;
  uint8_t simulated_flexicast_feedback_loss_rate;
  arena_t arena;

  uint8_t *fec_buf;
  size_t fec_buf_len;
  size_t fec_buf_cap;
  uint64_t fec_first_pkt_time;
  moq_track_id_t fec_track_id;
  uint32_t fec_pkt_count;
  uint8_t fec_priority;
  bool fec_in_flush;
  transport_fec_track_state_t fec_tracks[TRANSPORT_HARD_MAX_SUBSCRIPTIONS];

  ifmon_watcher_t ifmon_w;
  int ifmon_pipe[2];
  transport_fec_cache_t fec_cache;
  transport_repair_limiter_t aggregate_repair_limiter;
  transport_repair_mode_t repair_mode;
  uint64_t repair_feedback_nonce;
  FILE *repair_shadow_log;
  uint64_t repair_shadow_deadline_ms;
  size_t assembler_memory_bytes;
  transport_flexicast_registry_t flexicast;
  uint64_t flexicast_retired_flow_ids[TRANSPORT_FLEXICAST_MAX_FLOWS];
  uint32_t flexicast_retired_flow_epochs[TRANSPORT_FLEXICAST_MAX_FLOWS];
  size_t flexicast_retired_flow_count;
  size_t flexicast_retired_flow_next;
  bool flexicast_enabled;
  transport_flexicast_cc_mode_t flexicast_cc_mode;
  uint64_t flexicast_cc_startup_rate;
  uint64_t flexicast_cc_minimum_rate;
  uint64_t flexicast_cc_maximum_rate;
  uint64_t flexicast_cc_aggregate_rate_limit;
  uint32_t flexicast_cc_feedback_timeout_ms;
  transport_flexicast_repair_route_t flexicast_repair_route;
  bool flexicast_native_source;
  int flexicast_fds[2]; /* IPv4, IPv6 */
  uint16_t flexicast_receive_ports[2];
  struct sockaddr_storage flexicast_group_addr;
  socklen_t flexicast_group_addr_len;
  int flexicast_interface_family;
  struct in_addr flexicast_interface_v4;
  struct in6_addr flexicast_interface_v6;
  uint32_t flexicast_interface_index;
  bool flexicast_interface_set;
};

struct transport_conn_t {
  transport_t *transport;
  quicly_conn_t *quic;
  uint32_t id;
  transport_subscription_table_t send_subscriptions;
  transport_subscription_table_t receive_subscriptions;
  bool quic_ready;
  bool hello_sent;
  bool hello_received;
  bool protocol_ready;
  bool connected_emitted;
  bool authenticated;
  uint32_t peer_capabilities;
  transport_limits_t negotiated_limits;
  uint64_t stream_frames_received;
  uint64_t datagrams_received;
  uint64_t malformed_datagrams;

  quicly_stream_t *stream;
  frame_assembler_t assemblers[TRANSPORT_HARD_MAX_ASSEMBLERS];
  size_t assembler_index;
  struct {
    uint64_t generation, group_id, object_id;
    uint8_t alias;
    bool active;
  } completed_objects[QLINQ_COMPLETED_OBJECTS];
  size_t completed_cursor;
  uint16_t queued_datagrams[TRANSPORT_MAX_QUIC_PATHS];
  path_state_t path_states[TRANSPORT_MAX_PATHS];
  int64_t min_owd_ns[TRANSPORT_MAX_PATHS];
  bool owd_initialized[TRANSPORT_MAX_PATHS];
  size_t telemetry_path[TRANSPORT_MAX_PATHS];
  fp_t latest_owd_fp[TRANSPORT_MAX_PATHS];
  uint64_t last_telemetry_s_ns[TRANSPORT_MAX_PATHS];
  uint64_t last_telemetry_r_ns[TRANSPORT_MAX_PATHS];
  bool path_state_overridden[TRANSPORT_MAX_PATHS];
  pathflow_context_t scheduler_context;
  size_t round_robin_path;
  transport_repair_limiter_t repair_request_limiter;
  transport_repair_limiter_t nack_request_limiter;
  transport_checkpoint_ack_state_t checkpoint_acks[UINT8_MAX + 1U];
};

/* Master identity is stable across path changes and CID rotation. A cache hit
 * is only a routing hint: the caller must still call quicly_is_destination and
 * quicly_receive. Never use these unauthenticated fields as peer identity. */
static inline transport_conn_t *
transport_connection_cache_find(transport_t *t,
                                const quicly_cid_plaintext_t *cid) {
  transport_conn_t *conn =
      t->connection_cache[cid->master_id % QLINQ_CONNECTION_CACHE_SLOTS];
  if (!conn)
    return NULL;
  const quicly_cid_plaintext_t *master = quicly_get_master_id(conn->quic);
  return master->master_id == cid->master_id &&
                 master->thread_id == cid->thread_id &&
                 master->node_id == cid->node_id
             ? conn
             : NULL;
}

static inline void transport_connection_cache_remember(transport_t *t,
                                                       transport_conn_t *conn) {
  const quicly_cid_plaintext_t *cid = quicly_get_master_id(conn->quic);
  t->connection_cache[cid->master_id % QLINQ_CONNECTION_CACHE_SLOTS] = conn;
}

static inline void transport_connection_cache_forget(transport_t *t,
                                                     transport_conn_t *conn) {
  const quicly_cid_plaintext_t *cid = quicly_get_master_id(conn->quic);
  size_t slot = cid->master_id % QLINQ_CONNECTION_CACHE_SLOTS;
  if (t->connection_cache[slot] == conn)
    t->connection_cache[slot] = NULL;
}

/* State exists only while its alias has a negotiated subscription. Callers
 * must resolve the alias before accessing it; unknown wire aliases are rejected
 * by the protocol parser and never cause an allocation. */
static inline transport_object_gap_state_t *
transport_object_gap(const transport_conn_t *conn, uint8_t alias) {
  transport_subscription_state_t *state =
      transport_subscriptions_get_state(&conn->receive_subscriptions, alias);
  return state ? &state->object_gap : NULL;
}

static inline transport_checkpoint_ack_state_t *
transport_checkpoint_ack(const transport_conn_t *conn, uint8_t alias) {
  transport_subscription_state_t *state =
      transport_subscriptions_get_state(&conn->send_subscriptions, alias);
  return state ? &state->checkpoint_ack : NULL;
}

uint64_t transport_get_time_ns(void);
bool transport_owner_ok(transport_t *t);
void transport_emit_event(transport_t *t, const transport_event_t *event);
void transport_log(transport_t *t, transport_log_level_t level,
                   const char *component, uint32_t connection_id,
                   size_t path_index, const char *format, ...);
void transport_release_assembler(transport_t *t, frame_assembler_t *assembler);
bool transport_grow_assembler(transport_t *t, frame_assembler_t *assembler,
                              uint16_t symbols, uint16_t symbol_size);
bool transport_queue_datagram(transport_conn_t *conn, size_t path_index,
                              ptls_iovec_t datagram);

#endif
