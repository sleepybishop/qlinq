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

#include "quicly/constants.h"

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
  /* AUTO prefers degree-of-freedom repair for a rateless track when the peer
   * advertises support, otherwise it uses indexed repair. */
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
  TRANSPORT_EVENT_OBJECT_LOST       /* packet group failed FEC recovery and was
                                       evicted */
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
  } auth;                            /* valid for auth events */
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
 * - qlinq performs no application callbacks from its interface-monitor thread.
 */

/* callback for receiving transport events */
typedef void (*transport_callback_t)(void *user_data,
                                     const transport_event_t *event);

#define TRANSPORT_MAX_PATHS 4

/* Zero-valued limit fields select these defaults. Limits are deliberately
 * transport-level bounds, not application schemas or track hierarchies. */
#define TRANSPORT_DEFAULT_MAX_CONNECTIONS 32U
#define TRANSPORT_DEFAULT_MAX_SUBSCRIPTIONS 32U
#define TRANSPORT_DEFAULT_MAX_ASSEMBLERS 8U
#define TRANSPORT_DEFAULT_MAX_REPAIR_REQUESTS_PER_SECOND 16U
#define TRANSPORT_DEFAULT_MAX_AGGREGATE_REPAIR_REQUESTS_PER_SECOND 256U
#define TRANSPORT_DEFAULT_MAX_EGRESS_PACKETS 1024U
#define TRANSPORT_DEFAULT_MAX_EGRESS_BYTES (2U * 1024U * 1024U)
#define TRANSPORT_RECOVERY_WINDOW_OBJECTS 32U
#define TRANSPORT_DEFAULT_RECOVERY_CACHE_BYTES (16U * 1024U * 1024U)
#define TRANSPORT_DEFAULT_ASSEMBLER_MEMORY_BUDGET (64U * 1024U * 1024U)
#define TRANSPORT_DEFAULT_MAX_PACKETS_PER_TICK 1024U
#define TRANSPORT_DEFAULT_RECONNECT_INITIAL_DELAY_MS 250U
#define TRANSPORT_DEFAULT_RECONNECT_MAX_DELAY_MS 30000U

#define TRANSPORT_HARD_MAX_CONNECTIONS 1024U
#define TRANSPORT_HARD_MAX_SUBSCRIPTIONS 256U
#define TRANSPORT_HARD_MAX_ASSEMBLERS 8U
#define TRANSPORT_HARD_MAX_EGRESS_PACKETS 65536U

typedef struct {
  size_t max_connections;
  size_t max_subscriptions_per_connection;
  size_t max_assemblers_per_connection;
  size_t max_repair_requests_per_second;
  size_t max_aggregate_repair_requests_per_second;
  size_t max_egress_packets_per_socket;
  size_t max_egress_bytes_per_socket;
  size_t max_assembler_memory_bytes;
  /* Retained recovery payloads, in addition to the fixed cache entry table. */
  size_t max_recovery_cache_bytes;
  size_t max_reliable_object_size;
  size_t max_fec_object_size;
  size_t max_udp_payload_size;
  size_t max_packets_per_tick;
} transport_limits_t;

/* Wire and flow-control limits enforced by the transport. */
#define TRANSPORT_MAX_RELIABLE_OBJECT_SIZE ((1024U * 1024U) - 16U)
#define TRANSPORT_MAX_FEC_OBJECT_SIZE (1024U * 1024U)
#define TRANSPORT_MAX_FEC_RECORD_SIZE UINT16_MAX

#define TRANSPORT_APP_ERROR_PROTOCOL                                           \
  QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x100U)
#define TRANSPORT_APP_ERROR_AUTHENTICATION                                     \
  QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x101U)
#define TRANSPORT_APP_ERROR_RESOURCE_LIMIT                                     \
  QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x102U)

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
   * default. */
  uint64_t quic_idle_timeout_ms;
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
  transport_repair_mode_t repair_mode;
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

/* Flush buffered rateless data and reliably announce the last internal FEC
 * object, allowing receivers to discover a wholly unseen tail. */
bool transport_finish_track(transport_t *t, moq_track_id_t track_id);

/* subscribe to a media track (client-side) */
bool transport_subscribe(transport_t *t, moq_track_id_t track_id);

/* Subscribe one authenticated connection. The compatibility wrapper above
 * broadcasts to every eligible server connection. */
bool transport_subscribe_conn(transport_t *t, transport_conn_t *conn,
                              moq_track_id_t track_id);

/* Queue an unsubscribe frame and release the matching local subscription. */
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
  uint64_t resource_limit_errors;
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
  uint64_t repair_requests_sent;
  uint64_t repair_indexed_requests_sent;
  uint64_t repair_rateless_requests_sent;
  uint64_t repair_requests_deferred;
  uint64_t repair_whole_object_requests_sent;
  uint64_t repair_symbols_sent;
  uint64_t repair_rateless_symbols_sent;
  uint64_t repair_rateless_exhausted;
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
  size_t subscriptions;
  uint32_t peer_capabilities;
  transport_limits_t negotiated_limits;
  uint64_t stream_frames_received;
  uint64_t datagrams_received;
  uint64_t malformed_datagrams;
  uint64_t quic_paths_created;
  uint64_t quic_paths_validated;
  uint64_t quic_paths_validation_failed;
} transport_conn_stats_t;

/* Snapshot aggregate or per-connection observability. These functions follow
 * the same owner-thread rule as the rest of the API. */
bool transport_get_stats(transport_t *t, transport_stats_t *stats);
bool transport_get_conn_stats(transport_t *t, transport_conn_t *conn,
                              transport_conn_stats_t *stats);
uint32_t transport_get_conn_id(transport_t *t, transport_conn_t *conn);

transport_repair_mode_t
transport_get_effective_repair_mode(transport_t *t, transport_conn_t *conn,
                                    const moq_track_id_t *track_id);

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
size_t transport_get_poll_fds(transport_t *t, struct pollfd *fds,
                              size_t max_fds);

#endif /* TRANSPORT_H */
