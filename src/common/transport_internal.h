#ifndef QLINQ_TRANSPORT_INTERNAL_H
#define QLINQ_TRANSPORT_INTERNAL_H

#include "ifmon.h"
#include "pathflow.h"
#include "transport.h"
#include "transport_egress.h"
#include "transport_fec_state.h"
#include "transport_memory.h"
#include "transport_paths.h"
#include "transport_repair.h"
#include "transport_subscriptions.h"

#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"

#include <pthread.h>
#include <stdatomic.h>

#define QLINQ_FEC_ASSEMBLER_TIMEOUT_MS 2000
#define QLINQ_FEC_NACK_DELAY_MS 25
#define QLINQ_FEC_REPAIR_DEDUP_MS 25
#define QLINQ_FEC_COMPLETION_RETRY_MS 500
#define QLINQ_RECOVERY_WINDOW_OBJECTS TRANSPORT_RECOVERY_WINDOW_OBJECTS
#define QLINQ_RECOVERY_MAX_WINDOWS 8U
#define QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY 256U
#define QLINQ_RECOVERY_HISTORY_OBJECTS                                         \
  (QLINQ_RECOVERY_WINDOW_OBJECTS * QLINQ_RECOVERY_MAX_WINDOWS)

typedef struct {
  bool active;
  uint64_t group_id;
  uint64_t first_object_id;
  uint64_t final_object_id;
  uint32_t missing_mask;
  uint8_t cursor;
  int64_t last_request_ms;
} transport_recovery_window_t;

typedef struct {
  uint64_t last_seen;
  bool seen_initialized;
  uint64_t pending_base;
  uint32_t pending_mask;
  uint64_t group_id;
  int64_t detected_at_ms;
  uint64_t largest_delivered;
  uint64_t delivered_mask[QLINQ_RECOVERY_HISTORY_OBJECTS / 64U];
  bool delivered_initialized;
  bool checkpoint_initialized;
  uint64_t last_checkpoint_object_id;
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
} transport_fec_track_state_t;

typedef struct {
  bool participating;
  bool sent_initialized;
  uint64_t sent_group_id;
  uint64_t sent_object_id;
  int64_t oldest_unacked_sent_at_ms;
  bool acked_initialized;
  uint64_t acked_group_id;
  uint64_t acked_object_id;
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

  quicly_stream_open_t stream_open;
  ptls_openssl_verify_certificate_t verifier;
  bool verifier_initialized;
  quicly_receive_datagram_frame_t receive_datagram;

  transport_sent_cache_t sent_cache;
  transport_repair_mode_t repair_mode;
  transport_repair_limiter_t aggregate_repair_limiter;
  uint8_t simulated_loss_rate;
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
  size_t assembler_memory_bytes;
};

struct transport_conn_t {
  transport_t *transport;
  quicly_conn_t *quic;
  uint32_t id;
  transport_subscription_table_t subscriptions;
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
  transport_object_gap_state_t object_gaps[UINT8_MAX + 1U];
  uint16_t queued_datagrams[TRANSPORT_MAX_QUIC_PATHS];
  path_state_t path_states[TRANSPORT_MAX_PATHS];
  int64_t min_owd_ns[TRANSPORT_MAX_PATHS];
  fp_t latest_owd_fp[TRANSPORT_MAX_PATHS];
  uint64_t last_telemetry_s_ns[TRANSPORT_MAX_PATHS];
  uint64_t last_telemetry_r_ns[TRANSPORT_MAX_PATHS];
  bool path_state_overridden[TRANSPORT_MAX_PATHS];
  pathflow_context_t scheduler_context;
  size_t round_robin_path;
  transport_repair_limiter_t repair_request_limiter;
  transport_repair_limiter_t nack_request_limiter;
  transport_checkpoint_ack_state_t checkpoint_acks[UINT8_MAX + 1U];
  int64_t last_repair_ms;
  uint64_t last_repair_group_id;
  uint64_t last_repair_object_id;
  uint8_t last_repair_alias;
  uint8_t last_repair_flags;
};

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
