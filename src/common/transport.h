/* transport.h
 *
 * design philosophy:
 * this interface uses media over quic (MoQ) and flexicast concepts as
 * architectural design blueprints rather than fully compliant protocols.
 * by adopting pub/sub decoupling, stateless loss recovery, and single-publish
 * track fan-out, we keep the codebase clean, lightweight, and simple while
 * retaining low-latency multi-client capabilities.
 */

#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* opaque handles for transport state and connections */
typedef struct transport_t transport_t;
typedef struct transport_conn_t transport_conn_t;

typedef enum {
  MOQ_TRACK_VIDEO = 0,
  MOQ_TRACK_AUDIO = 1,
  MOQ_TRACK_INPUT = 2,
  MOQ_TRACK_TEXT = 3, /* subtitles, chat, or performance statistics */
  MOQ_TRACK_DATA = 4, /* generic raw data tunnel (e.g. TUN network packets) */
  MOQ_TRACK_TELEMETRY = 6, /* one-way delay / network telemetry */
} moq_track_type_t;

#define MOQ_TRACK_FLAG_RELIABLE (1 << 0)
#define MOQ_TRACK_FLAG_FEC_ENABLED (1 << 1)
#define MOQ_TRACK_FLAG_FEC_RATELESS (1 << 2)

typedef enum {
  TRANSPORT_FLEXICAST_CC_MULTICAST = 0,
  TRANSPORT_FLEXICAST_CC_ADAPTIVE = 1
} transport_flexicast_cc_mode_t;

/* Experiment control for measuring repair counterfactuals inside an explicitly
 * enabled Flexicast flow. SHARED is the production behavior. UNICAST never
 * selects itself automatically; it sends requested repair over each member's
 * authenticated ordinary QUIC connection. */
typedef enum {
  TRANSPORT_FLEXICAST_REPAIR_SHARED = 0,
  TRANSPORT_FLEXICAST_REPAIR_UNICAST = 1
} transport_flexicast_repair_route_t;

typedef enum {
  /* AUTO uses rateless repair for a rateless-coded track when the peer
   * advertises support, otherwise indexed repair. */
  TRANSPORT_REPAIR_MODE_AUTO = 0,
  TRANSPORT_REPAIR_MODE_INDEXED = 1,
  TRANSPORT_REPAIR_MODE_RATELESS = 2
} transport_repair_mode_t;

typedef struct {
  moq_track_type_t type;
  uint8_t flags;
  char name[64];
} moq_track_id_t;

/* represents an object (e.g. video frame or audio chunk) */
typedef struct {
  moq_track_id_t track_id;
  uint64_t group_id;  /* gop index or time group */
  uint64_t object_id; /* frame/packet sequence number */
  const uint8_t *data;
  size_t size;
  bool is_keyframe; /* true if object starts a new group */
  uint8_t priority; /* 0 = low, 1 = medium, 2 = high */
} moq_object_t;

typedef enum {
  TRANSPORT_EVENT_CONNECTED,
  TRANSPORT_EVENT_DISCONNECTED,
  TRANSPORT_EVENT_SUBSCRIBE,     /* client subscribed to a track */
  TRANSPORT_EVENT_UNSUBSCRIBE,   /* client unsubscribed from a track */
  TRANSPORT_EVENT_OBJECT,        /* received a track object */
  TRANSPORT_EVENT_AUTH,          /* server received authentication token */
  TRANSPORT_EVENT_AUTH_COMPLETE, /* client received authentication response */
  TRANSPORT_EVENT_KEYFRAME_REQUEST, /* client requested a video keyframe */
  TRANSPORT_EVENT_OBJECT_LOST,      /* packet group failed FEC recovery and was
                                       evicted */
  TRANSPORT_EVENT_TRACK_FINISHED,   /* receiver completed finite recovery */
  TRANSPORT_EVENT_TRACK_DRAINED,    /* publisher's finish cohort settled */
  TRANSPORT_EVENT_TRACK_ABORTED     /* finite stream was canceled */
} transport_event_type_t;

typedef enum {
  TRANSPORT_LOG_DEBUG,
  TRANSPORT_LOG_INFO,
  TRANSPORT_LOG_WARNING,
  TRANSPORT_LOG_ERROR
} transport_log_level_t;

typedef struct {
  transport_log_level_t level;
  const char *component;
  uint32_t connection_id; /* zero when not connection-specific */
  size_t path_index;      /* SIZE_MAX when not path-specific */
  const char *message;    /* borrowed for the duration of the callback */
} transport_log_event_t;

typedef void (*transport_log_callback_t)(void *user_data,
                                         const transport_log_event_t *event);

typedef struct {
  /* Normalized QUIC application/transport code. For an internal local error,
   * this is the raw value and raw_error has the same value. */
  uint64_t error_code;
  int64_t raw_error;
  bool application_error;
  uint64_t offending_frame_type;
  bool remote;
  /* Borrowed and valid only for the duration of the event callback. */
  const char *reason;
} transport_disconnect_t;

typedef struct {
  transport_event_type_t type;
  transport_conn_t *conn;
  moq_track_id_t track_id; /* valid for subscribe / unsubscribe / object */
  moq_object_t object;     /* valid for object events */
  struct {
    const uint8_t *token;
    size_t token_len;
    bool success;
  } auth; /* valid for auth events */
  struct {
    size_t peers_total;
    size_t peers_completed;
    size_t peers_failed;
  } completion; /* valid for TRACK_DRAINED */
  transport_disconnect_t disconnect; /* valid for disconnected events */
} transport_event_t;

/* Pointers inside an event, including object.data and auth.token, are borrowed
 * and remain valid only for the duration of the callback.
 *
 * Threading contract:
 * - A transport is bound to the thread that calls transport_create(). Every
 *   public operation on that transport must be called by that owner thread.
 * - Callbacks execute synchronously on the owner thread from transport_tick().
 * - A callback may publish, subscribe, authenticate, close a connection, and
 *   call query functions. It must not call transport_tick() recursively or
 *   destroy the transport. Rejected contract violations are counted in
 *   transport_stats_t.
 * - Log callbacks are observational: they must not call transport operations.
 * - qlinq performs no application callbacks from its interface-monitor thread.
 */

/* callback for receiving transport events */
typedef void (*transport_callback_t)(void *user_data,
                                     const transport_event_t *event);

#define TRANSPORT_MAX_PATHS 4
#define TRANSPORT_MAX_POLL_FDS (TRANSPORT_MAX_PATHS + 1U)

/* Zero-valued limit fields select these defaults. Limits are deliberately
 * transport-level bounds, not application schemas or track hierarchies. */
#define TRANSPORT_DEFAULT_MAX_CONNECTIONS 32U
#define TRANSPORT_DEFAULT_MAX_SUBSCRIPTIONS 32U
#define TRANSPORT_DEFAULT_MAX_ASSEMBLERS 8U
#define TRANSPORT_DEFAULT_MAX_REPAIR_REQUESTS_PER_SECOND 16U
#define TRANSPORT_DEFAULT_MAX_AGGREGATE_REPAIR_REQUESTS_PER_SECOND 256U
#define TRANSPORT_DEFAULT_MAX_AGGREGATE_NACK_REQUESTS_PER_SECOND 16U
#define TRANSPORT_DEFAULT_MAX_EGRESS_PACKETS 1024U
#define TRANSPORT_DEFAULT_MAX_EGRESS_BYTES (2U * 1024U * 1024U)
#define TRANSPORT_RECOVERY_WINDOW_OBJECTS 32U
#define TRANSPORT_DEFAULT_STREAM_EGRESS_BYTES (2U * 1024U * 1024U)
#define TRANSPORT_DEFAULT_TOTAL_STREAM_EGRESS_BYTES (16U * 1024U * 1024U)
#define TRANSPORT_DEFAULT_RECOVERY_CACHE_BYTES (16U * 1024U * 1024U)
#define TRANSPORT_DEFAULT_ASSEMBLER_MEMORY_BUDGET (64U * 1024U * 1024U)
#define TRANSPORT_DEFAULT_MAX_PACKETS_PER_TICK 1024U
#define TRANSPORT_DEFAULT_RECONNECT_INITIAL_DELAY_MS 250U
#define TRANSPORT_DEFAULT_RECONNECT_MAX_DELAY_MS 30000U

#define TRANSPORT_HARD_MAX_CONNECTIONS 16384U
#define TRANSPORT_HARD_MAX_SUBSCRIPTIONS 256U
#define TRANSPORT_HARD_MAX_ASSEMBLERS 8U
#define TRANSPORT_HARD_MAX_EGRESS_PACKETS 65536U

typedef struct {
  size_t max_connections;
  size_t max_subscriptions_per_connection; /* independently in each direction */
  size_t max_assemblers_per_connection;
  size_t max_repair_requests_per_second;
  /* Source-wide failsafe. This remains independent of receiver count so a
   * large cohort cannot multiply the per-peer repair ceiling. */
  size_t max_aggregate_repair_requests_per_second;
  /* Receiver-wide outbound NACK budget, shared by all peers. */
  size_t max_aggregate_nack_requests_per_second;
  size_t max_egress_packets_per_socket;
  size_t max_egress_bytes_per_socket;
  size_t max_assembler_memory_bytes;
  /* Retained recovery payloads, in addition to the fixed cache entry table. */
  size_t max_recovery_cache_bytes;
  /* Frame allocations and send-vector capacity retained until QUIC releases
   * them. */
  size_t max_stream_egress_bytes; /* retained frames and vector capacity */
  size_t max_total_stream_egress_bytes; /* shared across all connections */
  size_t max_reliable_object_size;
  size_t max_fec_object_size;
  size_t max_udp_payload_size;
  size_t max_packets_per_tick;
} transport_limits_t;

/* Wire and flow-control limits enforced by the transport. */
#define TRANSPORT_MAX_RELIABLE_OBJECT_SIZE ((1024U * 1024U) - 16U)
#define TRANSPORT_MAX_FEC_OBJECT_SIZE (1024U * 1024U)
#define TRANSPORT_MAX_FEC_RECORD_SIZE UINT16_MAX

/* Quicly's public close API expects application errors in its tagged error
 * namespace; it subtracts the tag before encoding the QUIC close frame. */
#define TRANSPORT_APP_ERROR_PROTOCOL 0x30100U
#define TRANSPORT_APP_ERROR_AUTHENTICATION 0x30101U
#define TRANSPORT_APP_ERROR_RESOURCE_LIMIT 0x30102U

typedef struct {
  /* For clients, bind_hosts[i] uses remote_hosts[i]. When exactly one remote
   * host is supplied, every local address uses that endpoint. Hot-added local
   * addresses take the next compatible, unused remote endpoint. */
  const char *bind_hosts[TRANSPORT_MAX_PATHS];
  size_t num_bind_hosts;
  /* Optional exact-name allowlist for interfaces discovered after startup.
   * Zero entries accept every monitored interface. */
  const char *path_interface_names[TRANSPORT_MAX_PATHS];
  size_t num_path_interface_names;
  const char *remote_hosts[TRANSPORT_MAX_PATHS];
  size_t num_remote_hosts;
  uint16_t port;
  /* QUIC control-session idle timeout in milliseconds. Zero keeps Quicly's
   * default. Long-lived multicast recovery sessions should set this beyond
   * their maximum checkpoint/recovery deadline. */
  uint64_t quic_idle_timeout_ms;
  /* FEC assembler inactivity timeout. Zero selects 2000 ms. */
  uint32_t fec_assembler_timeout_ms;
  /* Zero keeps the corresponding Quicly default. */
  uint32_t initial_rtt_ms;
  uint32_t handshake_timeout_rtt_multiplier;
  const char *cert_file; /* required for server */
  const char *key_file;  /* required for server */
  const char *ca_file;   /* CA bundle path for validating peer certificates */
  bool verify_peer;      /* require and verify peer certificate (mTLS) */
  bool allow_insecure_peer; /* explicit opt-in for tests; never use in
                               production */
  transport_callback_t callback;
  void *user_data;
  /* Optional structured diagnostics. When omitted, WARNING and ERROR records
   * are written to stderr. The event and message are callback-borrowed. */
  transport_log_callback_t log_callback;
  void *log_user_data;
  uint8_t simulated_loss_rate; /* 0 to 100 representing percentage of packets to
                                  drop */
  /* Recreate a client QUIC session after an unexpected disconnect. Servers
   * ignore these fields. Zero delay fields select 250 ms and 30 seconds. */
  bool reconnect_enabled;
  uint32_t reconnect_initial_delay_ms;
  uint32_t reconnect_max_delay_ms;
  /* Test/emulation fault injection: percentage of Flexicast PATH_ACK attempts
   * to suppress while ordinary QUIC control traffic continues normally. */
  uint8_t simulated_flexicast_feedback_loss_rate;
  /* Enables the experimental Flexicast DATAGRAM path. Reliable tracks remain
   * ordinary QUIC streams. */
  bool enable_flexicast;
  /* Optional native IPv4 or IPv6 source-specific multicast policy. Sources
   * announce this numeric multicast address and UDP port; receivers learn both
   * through FC_ANNOUNCE. flexicast_interface is a numeric local address used
   * for multicast egress and membership. A source must set all three fields;
   * receivers may set only flexicast_interface to override route selection.
   * With no group configured, one protected packet is replicated over the
   * existing unicast UDP sockets. */
  const char *flexicast_group;
  uint16_t flexicast_group_port;
  const char *flexicast_interface;
  /* Multicast-specific congestion controller. Zero selects the conservative
   * multicast controller. Rate values are bytes per second; zero selects the
   * controller profile default. */
  transport_flexicast_cc_mode_t flexicast_cc_mode;
  uint64_t flexicast_cc_startup_rate;
  uint64_t flexicast_cc_minimum_rate;
  uint64_t flexicast_cc_maximum_rate;
  uint64_t flexicast_cc_aggregate_rate_limit;
  uint32_t flexicast_cc_feedback_timeout_ms;
  transport_flexicast_repair_route_t flexicast_repair_route;
  /* Local receiver preference for rateless-coded tracks. AUTO is the default
   * and remains interoperable with peers that only support indexed NACKs. */
  transport_repair_mode_t repair_mode;
  /* Optional deterministic seed for multicast repair-feedback timers. Zero
   * uses an operating-system random seed. Intended for reproducible scenario
   * comparisons; it does not affect protocol interoperability. */
  uint64_t repair_feedback_seed;
  /* Optional M4 shadow-planner record. The planner never changes traffic;
   * record repair-planner snapshots. */
  const char *repair_shadow_log_file;
  uint64_t repair_shadow_deadline_ms;
  transport_limits_t limits; /* zero fields select documented defaults */
} transport_config_t;

/* create and destroy transport instances */
transport_t *transport_create(const transport_config_t *config);
void transport_destroy(transport_t *t);

/* drive the event loop and process timers */
void transport_tick(transport_t *t);

typedef enum {
  TRANSPORT_PUBLISH_DELIVERED,
  TRANSPORT_PUBLISH_BUFFERED,
  TRANSPORT_PUBLISH_NO_RECIPIENTS,
  TRANSPORT_PUBLISH_PARTIAL,
  TRANSPORT_PUBLISH_BACKPRESSURE,
  TRANSPORT_PUBLISH_INVALID,
  TRANSPORT_PUBLISH_ERROR
} transport_publish_result_t;

/* Detailed publication result. PARTIAL means at least one eligible peer was
 * queued successfully and at least one failed. */
transport_publish_result_t transport_publish_ex(transport_t *t,
                                                const moq_object_t *obj);

/* Compatibility wrapper: true only when the object was delivered, buffered,
 * or had no eligible recipients. */
bool transport_publish(transport_t *t, const moq_object_t *obj);

/* Flush buffered rateless data and reliably announce its final internal FEC
 * object. Receivers use the watermark to request any wholly unseen tail
 * objects. Calling this function more than once is safe. */
bool transport_finish_track(transport_t *t, moq_track_id_t track_id);

/* Cancel a publishing track and notify its current subscribers. */
bool transport_abort_track(transport_t *t, moq_track_id_t track_id);

/* subscribe to a media track (client-side) */
bool transport_subscribe(transport_t *t, moq_track_id_t track_id);
/* Subscribe one authenticated connection. This is useful to direct API users
 * serving multiple peers; transport_subscribe broadcasts to every eligible
 * connection for compatibility. */
bool transport_subscribe_conn(transport_t *t, transport_conn_t *conn,
                              moq_track_id_t track_id);

/* unsubscribe from a media track. Once the reliable control frame is queued,
 * local Flexicast state and kernel SSM membership are released immediately. */
bool transport_unsubscribe(transport_t *t, moq_track_id_t track_id);

/* request a video keyframe from the publisher (client-side) */
bool transport_request_keyframe(transport_t *t, moq_track_id_t track_id);

/* send private unicast data (such as input events) to a specific connection */
bool transport_send_unicast(transport_t *t, transport_conn_t *conn,
                            const void *data, size_t size);

/* initiate session authentication (client-side) */
bool transport_send_auth(transport_t *t, transport_conn_t *conn,
                         const uint8_t *token, size_t token_len);

/* respond to connection authentication challenge (server-side) */
bool transport_respond_auth(transport_t *t, transport_conn_t *conn,
                            bool success);

/* connect to a unix domain socket and stream quicly debug events (qlog) */
int transport_enable_qlog(const char *socket_path);

/* close an active connection */
void transport_close_conn(transport_t *t, transport_conn_t *conn);
/* error is zero or a QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE value.
 * Unknown connections, invalid errors and already-closing peers are ignored. */
void transport_close_conn_with_error(transport_t *t, transport_conn_t *conn,
                                     int64_t error, const char *reason);

/* Close every connection and suppress automatic reconnect. Call tick until
 * transport_is_drained() or the application's drain deadline expires. */
void transport_shutdown(transport_t *t, const char *reason);
bool transport_is_drained(transport_t *t);

/* Atomically replace the identity used by future handshakes. Existing
 * connections are unaffected. On failure, the current identity is retained. */
bool transport_reload_credentials(transport_t *t, const char *cert_file,
                                  const char *key_file);

/* query latest estimated bandwidth in bytes per second */
uint64_t transport_get_estimated_bandwidth(transport_t *t);

typedef enum {
  TRANSPORT_PATH_DISCOVERED,
  TRANSPORT_PATH_OPENING,
  TRANSPORT_PATH_VALIDATING,
  TRANSPORT_PATH_ACTIVE,
  TRANSPORT_PATH_DRAINING,
  TRANSPORT_PATH_FAILED
} transport_path_lifecycle_t;

typedef struct {
  transport_path_lifecycle_t lifecycle;
  uint32_t interface_index;
  char interface_name[64];
  char local_address[64];
  uint64_t bytes_sent;
  uint64_t bytes_received;
  uint64_t sent;
  uint64_t lost;
  uint32_t rtt;
  double relative_owd;
  double ewma_latency;
} transport_path_stats_t;

typedef struct {
  uint64_t connections_accepted;
  uint64_t connections_rejected;
  uint64_t connections_closed;
  uint64_t reconnect_attempts;
  uint64_t reconnect_succeeded;
  uint64_t reconnect_failed;
  uint64_t protocol_handshakes_completed;
  uint64_t protocol_errors;
  uint64_t internal_state_recoveries;
  uint64_t resource_limit_errors;
  uint64_t stream_egress_blocked, stream_control_failures;
  size_t stream_egress_bytes, stream_egress_frames,
      stream_egress_vector_capacity;
  size_t stream_egress_peak_bytes, stream_egress_peak_frames,
      stream_egress_peak_vectors;
  uint64_t stream_frames_received;
  uint64_t datagrams_received;
  uint64_t malformed_datagrams;
  uint64_t fec_objects_recovered;
  uint64_t fec_objects_lost;
  uint64_t fec_duplicate_objects_suppressed;
  uint64_t repair_requests_received;
  uint64_t repair_indexed_requests_received;
  uint64_t repair_rateless_requests_received;
  uint64_t repair_requests_throttled;
  uint64_t repair_requests_aggregate_throttled;
  uint64_t repair_requests_suppressed;
  uint64_t repair_requests_sent;
  uint64_t repair_indexed_requests_sent;
  uint64_t repair_rateless_requests_sent;
  uint64_t repair_requests_coalesced;
  uint64_t repair_requests_deferred;
  uint64_t repair_whole_object_requests_sent;
  uint64_t repair_symbols_sent;
  uint64_t repair_rateless_symbols_sent;
  uint64_t repair_rateless_exhausted;
  uint64_t repair_multicast_symbols_sent;
  uint64_t repair_requests_merged;
  uint64_t repair_requester_records_peak;
  uint64_t repair_requester_overflow;
  uint64_t repair_requester_updates;
  uint64_t repair_requester_records_expired;
  uint64_t repair_shadow_plans_evaluated;
  uint64_t repair_shadow_all_shared;
  uint64_t repair_shadow_all_unicast;
  uint64_t repair_shadow_mixed;
  uint64_t repair_shadow_uncertain;
  uint64_t repair_shadow_infeasible;
  uint64_t repair_shadow_log_errors;
  uint64_t repair_shadow_last_airtime_us;
  uint64_t repair_shadow_last_physical_bytes;
  uint32_t repair_shadow_last_savings_ppm;
  uint64_t repair_shadow_observation_overflow;
  uint64_t repair_unicast_symbols_sent;
  uint64_t repair_unicast_payload_bytes_queued;
  uint64_t repair_batches_emitted;
  uint64_t repair_commit_failures;
  uint64_t repair_queue_backpressure;
  uint64_t repair_packets_cancelled;
  uint64_t repair_pending_symbols_cancelled;
  uint64_t repair_physical_bytes_sent;
  uint64_t flexicast_physical_bytes_sent;
  uint64_t track_ends_sent;
  uint64_t track_ends_received;
  uint64_t recovery_checkpoints_sent;
  uint64_t recovery_checkpoints_received;
  uint64_t recovery_checkpoint_acks_sent;
  uint64_t recovery_checkpoint_acks_received;
  uint64_t recovery_cache_releases;
  uint64_t recovery_cache_backpressure;
  size_t recovery_cache_payload_bytes, recovery_cache_peak_payload_bytes;
  size_t recovery_cache_entries, recovery_cache_peak_entries;
  size_t recovery_checkpoints_pending;
  uint64_t recovery_oldest_checkpoint_age_ms;
  uint64_t flexicast_packets_sent;
  uint64_t flexicast_native_packets_sent;
  uint64_t flexicast_packets_received;
  uint64_t flexicast_multicast_datagrams_received;
  uint64_t flexicast_multicast_datagrams_rejected;
  uint64_t flexicast_acks_received;
  uint64_t flexicast_fallbacks;
  uint64_t flexicast_rekeys;
  uint64_t flexicast_rekey_members;
  uint64_t flexicast_rekey_batched_changes;
  uint64_t flexicast_feedback_fallbacks;
  uint64_t flexicast_control_frames_throttled;
  uint64_t flexicast_paced_packets;
  uint64_t flexicast_pacing_delays;
  uint64_t flexicast_pacing_backpressure;
  uint64_t flexicast_pacing_dropped;
  uint64_t flexicast_pacing_rate_bytes_per_second;
  transport_flexicast_cc_mode_t flexicast_cc_mode;
  uint64_t flexicast_cc_rate_bytes_per_second;
  uint64_t flexicast_cc_burst_bytes;
  uint64_t flexicast_cc_limiting_member;
  uint64_t flexicast_cc_rate_increase_events;
  uint64_t flexicast_cc_rate_reduction_events;
  uint64_t flexicast_cc_floor_entry_events;
  uint64_t flexicast_cc_floor_exit_events;
  uint64_t flexicast_cc_ack_growth_events;
  uint64_t flexicast_cc_other_growth_events;
  uint64_t flexicast_cc_loss_reduction_events;
  uint64_t flexicast_cc_rtt_reduction_events;
  uint64_t flexicast_cc_ecn_reduction_events;
  uint64_t flexicast_cc_timeout_reduction_events;
  uint64_t flexicast_cc_rate_limit_reduction_events;
  uint64_t flexicast_cc_other_reduction_events;
  uint64_t flexicast_cc_external_load_growth_freeze_events;
  size_t flexicast_queued_packets;
  size_t flexicast_queued_bytes;
  size_t repair_queued_packets;
  size_t repair_queued_bytes;
  size_t repair_pending_objects;
  uint64_t repair_oldest_age_ms;
  uint64_t flexicast_membership_joins;
  uint64_t flexicast_membership_leaves;
  uint64_t flexicast_interface_fallbacks;
  uint64_t flexicast_interface_rejoins;
  size_t flexicast_active_memberships;
  size_t flexicast_active_flows;
  size_t flexicast_active_members;
  uint64_t events_emitted;
  uint64_t api_thread_violations;
  uint64_t recursive_tick_rejections;
  uint64_t callback_destroy_rejections;
  uint64_t udp_packets_sent;
  uint64_t udp_bytes_sent;
  uint64_t udp_would_block;
  uint64_t udp_send_errors;
  uint64_t egress_packets_queued;
  uint64_t egress_bytes_queued;
  uint64_t egress_packets_dropped;
  uint64_t publish_delivered;
  uint64_t publish_buffered;
  uint64_t publish_no_recipients;
  uint64_t publish_partial;
  uint64_t publish_backpressure;
  uint64_t publish_invalid;
  uint64_t publish_errors;
  size_t egress_current_packets;
  size_t egress_current_bytes;
  size_t egress_peak_packets;
  size_t egress_peak_bytes;
  size_t active_connections;
  size_t assembler_memory_bytes;
} transport_stats_t;

typedef struct {
  uint32_t id;
  bool quic_ready;
  bool protocol_ready;
  bool authenticated;
  size_t subscriptions; /* active send plus receive subscriptions */
  uint32_t peer_capabilities;
  transport_limits_t negotiated_limits;
  uint64_t stream_frames_received;
  uint64_t datagrams_received;
  uint64_t malformed_datagrams;
  uint64_t quic_paths_created;
  uint64_t quic_paths_validated;
  uint64_t quic_paths_validation_failed;
} transport_conn_stats_t;

typedef struct {
  size_t subscribers;
  size_t group_members;
  size_t confirmations_pending;
  size_t confirmations_completed;
  size_t confirmations_failed;
  bool finishing;
  bool drained;
} transport_track_stats_t;

/* Snapshot aggregate or per-connection observability. These functions follow
 * the same owner-thread rule as the rest of the API. */
bool transport_get_stats(transport_t *t, transport_stats_t *stats);
bool transport_get_conn_stats(transport_t *t, transport_conn_t *conn,
                              transport_conn_stats_t *stats);
bool transport_get_track_stats(transport_t *t, const moq_track_id_t *track_id,
                               transport_track_stats_t *stats);
uint32_t transport_get_conn_id(transport_t *t, transport_conn_t *conn);

/* Returns the negotiated repair semantics for this connection and track.
 * Rateless tracks fall back to indexed repair with legacy peers. */
transport_repair_mode_t
transport_get_effective_repair_mode(transport_t *t, transport_conn_t *conn,
                                    const moq_track_id_t *track_id);

typedef struct {
  size_t subscribers;
} transport_track_stats_t;
bool transport_get_track_stats(transport_t *t, const moq_track_id_t *track,
                               transport_track_stats_t *stats);

/* Snapshot the physical interface corresponding to a Pathflow input slot.
 * Returns false when path_idx is not currently active. */
bool transport_get_path_stats(transport_t *t, size_t path_idx,
                              transport_path_stats_t *stats);

/* mock a local IP interface addition for testing multipath */
void transport_mock_iface_add(transport_t *t, const char *ip_addr);
void transport_mock_iface_remove(transport_t *t, const char *ip_addr);

/* Deterministic path controls for integration tests. The override remains in
 * effect for the lifetime of the current connections. */
bool transport_mock_path_state(transport_t *t, size_t path_idx,
                               uint32_t packets_per_second, double latency_ms,
                               double loss_rate);

size_t transport_get_datagram_symbol_size(const transport_t *t);

/* check if a track is ready for more data (application-layer backpressure) */
bool transport_is_track_ready(transport_t *t, const moq_track_id_t *track_id);

/* get current time in milliseconds */
int64_t transport_get_time_ms(void);

/* query earliest timeout timestamp in milliseconds for pacer and timers */
int64_t transport_get_first_timeout(transport_t *t);

struct pollfd;

/* collect socket file descriptors for polling */
/* Includes the interface monitor; reserve TRANSPORT_MAX_POLL_FDS entries. */
/* Capacity TRANSPORT_MAX_POLL_FDS includes UDP sockets and interface wakeups.
 */
size_t transport_get_poll_fds(transport_t *t, struct pollfd *fds,
                              size_t max_fds);

#endif /* TRANSPORT_H */
