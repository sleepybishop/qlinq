/* qlinq.h
 *
 * Native application API for named, independently configured streams.
 *
 * A context owns endpoints and an event queue. An endpoint either listens for
 * peers or connects to one peer over one or more network paths. Applications
 * publish or subscribe to named streams on an endpoint. No stream operation
 * starts a private worker thread; the creating thread drives progress with
 * qlinq_service(). All context/endpoint/stream operations use the creating
 * thread. Logging callbacks must not call the API. Closed endpoint and stream
 * handles remain valid until context destruction.
 */

#ifndef QLINQ_H
#define QLINQ_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QLINQ_MAX_PATHS 4U
#define QLINQ_STREAM_NAME_CAPACITY 64U

typedef struct qlinq_context qlinq_context_t;
typedef struct qlinq_endpoint qlinq_endpoint_t;
typedef struct qlinq_stream qlinq_stream_t;

typedef enum {
  QLINQ_STATUS_OK = 0,
  QLINQ_STATUS_AGAIN = 1,
  QLINQ_STATUS_INVALID = -1,
  QLINQ_STATUS_STATE = -2,
  QLINQ_STATUS_NO_MEMORY = -3,
  QLINQ_STATUS_IO = -4,
  QLINQ_STATUS_RESOURCE_LIMIT = -5
} qlinq_status_t;

typedef enum {
  QLINQ_CONTENT_VIDEO = 0,
  QLINQ_CONTENT_AUDIO = 1,
  QLINQ_CONTENT_INPUT = 2,
  QLINQ_CONTENT_TEXT = 3,
  QLINQ_CONTENT_DATA = 4,
  QLINQ_CONTENT_TELEMETRY = 6
} qlinq_content_type_t;

typedef enum {
  QLINQ_DELIVERY_DATAGRAM = 0,
  QLINQ_DELIVERY_RELIABLE = 1,
  QLINQ_DELIVERY_FIXED_FEC = 2,
  QLINQ_DELIVERY_RATELESS = 3
} qlinq_delivery_t;

typedef enum {
  QLINQ_STREAM_OPEN = 0,
  QLINQ_STREAM_CLOSED
} qlinq_stream_state_t;

typedef enum {
  QLINQ_REPAIR_AUTO = 0,
  QLINQ_REPAIR_INDEXED = 1,
  QLINQ_REPAIR_RATELESS = 2
} qlinq_repair_mode_t;

typedef enum {
  QLINQ_LOG_DEBUG = 0,
  QLINQ_LOG_INFO,
  QLINQ_LOG_WARNING,
  QLINQ_LOG_ERROR
} qlinq_log_level_t;

typedef struct {
  qlinq_log_level_t level;
  const char *component;
  uint32_t peer_id;
  size_t path_index;
  const char *message;
} qlinq_log_event_t;

typedef void (*qlinq_log_callback_t)(void *user_data,
                                     const qlinq_log_event_t *event);

typedef struct {
  /* Zero selects the documented transport default for every limit. */
  size_t max_connections;
  size_t max_subscriptions_per_peer; /* independently in each publishing
                                        direction */
  size_t max_active_receive_objects_per_peer;
  size_t max_repair_requests_per_second;
  size_t max_aggregate_repair_requests_per_second;
  size_t max_aggregate_nack_requests_per_second;
  size_t max_egress_packets_per_socket;
  size_t max_egress_bytes_per_socket;
  size_t max_receive_memory_bytes;
  size_t max_recovery_cache_bytes;
  size_t max_stream_egress_bytes;
  size_t max_total_stream_egress_bytes;
  size_t max_reliable_record_bytes;
  size_t max_fec_record_bytes;
  size_t max_udp_payload_bytes;
  size_t max_packets_per_service;
} qlinq_limits_t;

typedef struct {
  /* qlinq copies the secret. An empty secret is valid but is intended only for
   * isolated deployments. */
  const void *shared_secret;
  size_t shared_secret_size;
  const char *certificate_file;
  const char *private_key_file;
  const char *trust_store_file;
  bool verify_peer;
  bool allow_insecure_peer;
} qlinq_security_config_t;

typedef struct {
  const char *bind_addresses[QLINQ_MAX_PATHS];
  size_t bind_address_count;
  const char *remote_addresses[QLINQ_MAX_PATHS];
  size_t remote_address_count;
  uint16_t port;
  uint64_t idle_timeout_ms;
  /* Incomplete FEC object idle timeout; zero selects 2,000 ms. Increase for
   * slow TDMA links so repair traffic can arrive before assembly expires. */
  uint32_t receive_object_timeout_ms;
  /* QUIC handshake deadline as a multiple of smoothed RTT. Zero keeps the
   * Quicly default (400); lossy, scheduled links may need a larger budget. */
  uint32_t handshake_timeout_rtt_multiplier;
  /* Initial QUIC RTT estimate in milliseconds. Zero keeps Quicly's default. */
  uint32_t initial_rtt_ms;
  bool reconnect_enabled;
  uint32_t reconnect_initial_delay_ms;
  uint32_t reconnect_max_delay_ms;
  qlinq_security_config_t security;
  qlinq_repair_mode_t repair_mode;
  qlinq_limits_t limits;
} qlinq_endpoint_config_t;

typedef struct {
  /* Zero values select 1,024 events and 64 MiB of event allocations (metadata,
   * copied payloads and strings). */
  size_t max_queued_events;
  size_t max_queued_event_bytes;
  /* Log strings are borrowed and valid only during the callback. */
  qlinq_log_callback_t log_callback;
  void *log_user_data;
} qlinq_context_config_t;

typedef struct {
  qlinq_content_type_t content_type;
  qlinq_delivery_t delivery;
  const char *name;
} qlinq_stream_config_t;

/* Payload bytes retain transport.h wire compatibility. FEC DATA records are
 * grouped by the transport: received group_id/sequence identify that coding
 * object, not each original record. Other delivery modes retain object IDs. */
typedef struct {
  uint64_t group_id;
  uint64_t sequence;
  const void *data;
  size_t size;
  bool keyframe;
  uint8_t priority;
} qlinq_record_t;

typedef enum {
  QLINQ_SEND_SENT = 0,
  QLINQ_SEND_BUFFERED,
  QLINQ_SEND_NO_SUBSCRIBERS,
  QLINQ_SEND_PARTIAL,
  QLINQ_SEND_WOULD_BLOCK,
  QLINQ_SEND_INVALID,
  QLINQ_SEND_FAILED
} qlinq_send_result_t;

typedef enum {
  QLINQ_EVENT_PEER_READY,
  QLINQ_EVENT_PEER_REJECTED,
  QLINQ_EVENT_PEER_DISCONNECTED,
  QLINQ_EVENT_SUBSCRIBER_JOINED,
  QLINQ_EVENT_SUBSCRIBER_LEFT,
  QLINQ_EVENT_RECORD,
  QLINQ_EVENT_RECORD_LOST,
  QLINQ_EVENT_KEYFRAME_REQUESTED,
  QLINQ_EVENT_STREAM_WRITABLE,
  QLINQ_EVENT_ERROR
} qlinq_event_type_t;

typedef struct {
  uint64_t error_code;
  int64_t raw_error;
  bool application_error;
  uint64_t offending_frame_type;
  bool remote;
  /* Connection state captured before teardown. was_ready means authenticated
   * application readiness was reached, not merely that QUIC connected. */
  bool was_ready;
  bool outgoing;
  /* Owned by the event and valid until qlinq_event_release(). */
  const char *reason;
} qlinq_disconnect_t;

typedef struct {
  qlinq_event_type_t type;
  qlinq_endpoint_t *endpoint;
  qlinq_stream_t *stream;
  uint32_t peer_id;
  qlinq_content_type_t content_type;
  qlinq_delivery_t delivery;
  char stream_name[QLINQ_STREAM_NAME_CAPACITY];
  qlinq_record_t record;
  qlinq_disconnect_t disconnect;
  qlinq_status_t status;
  const char *message;
  /* Private ownership token used by qlinq_event_release(). */
  void *_private;
} qlinq_event_t;

typedef struct {
  uint64_t connections_accepted;
  uint64_t connections_rejected;
  uint64_t connections_closed;
  uint64_t reconnect_attempts;
  uint64_t reconnect_succeeded;
  uint64_t reconnect_failed;
  uint64_t protocol_errors;
  uint64_t records_received;
  uint64_t fec_objects_recovered;
  uint64_t fec_objects_lost;
  uint64_t repair_requests_sent;
  uint64_t repair_requests_coalesced;
  uint64_t repair_requests_deferred;
  uint64_t repair_requests_received;
  uint64_t repair_symbols_sent;
  /* Retained source payload allocations; excludes the fixed inline table. */
  size_t recovery_cache_payload_bytes;
  size_t recovery_cache_peak_payload_bytes;
  size_t recovery_cache_entries;
  size_t recovery_cache_peak_entries;
  /* Reliable output allocations, including frame headers and vector capacity.
   * These are separate from datagram/socket queued_bytes below. */
  size_t stream_egress_bytes;
  size_t stream_egress_peak_bytes;
  size_t stream_egress_frames;
  size_t stream_egress_peak_frames;
  size_t stream_egress_vector_capacity;
  size_t stream_egress_peak_vectors;
  uint64_t stream_egress_blocked;
  uint64_t stream_control_failures;
  size_t active_connections;
  size_t queued_packets;
  size_t queued_bytes;
} qlinq_endpoint_stats_t;

typedef struct {
  qlinq_stream_state_t state;
  uint64_t records_sent;
  uint64_t records_received;
  uint64_t objects_lost;
  size_t subscribers;
  bool writable;
} qlinq_stream_stats_t;

qlinq_context_t *qlinq_context_create(const qlinq_context_config_t *config);
void qlinq_context_destroy(qlinq_context_t *context);

/* listen() requires no remote addresses. connect() requires at least one.
 * The port is the listener's control port in both cases. */
qlinq_endpoint_t *qlinq_listen(qlinq_context_t *context,
                               const qlinq_endpoint_config_t *config);
qlinq_endpoint_t *qlinq_connect(qlinq_context_t *context,
                                const qlinq_endpoint_config_t *config);

typedef struct {
  uint32_t peer_id;
  bool outgoing;
  bool ready;
  /* Setup observations; ready remains the authenticated application barrier. */
  bool quic_ready;
  bool protocol_ready;
  bool authenticated;
  /* Alternate-path validation events; the initial handshake path is excluded.
   */
  uint64_t paths_validated;
  uint64_t paths_validation_failed;
} qlinq_peer_info_t;

bool qlinq_endpoint_get_peer(qlinq_endpoint_t *endpoint, uint32_t peer_id,
                             qlinq_peer_info_t *info);
/* Starts an orderly close while leaving the endpoint serviceable until its
 * QUIC close packets and socket queues drain. Automatic reconnect is stopped.
 */
qlinq_status_t qlinq_endpoint_shutdown(qlinq_endpoint_t *endpoint,
                                       const char *reason);
bool qlinq_endpoint_is_drained(qlinq_endpoint_t *endpoint);
/* Replaces the identity used for future handshakes. Existing sessions retain
 * their current TLS state. Failure leaves the previous identity installed. */
qlinq_status_t qlinq_endpoint_reload_credentials(qlinq_endpoint_t *endpoint,
                                                 const char *certificate_file,
                                                 const char *private_key_file);
void qlinq_endpoint_close(qlinq_endpoint_t *endpoint);

/* A publishing stream accepts records from the application. A subscribed
 * stream produces QLINQ_EVENT_RECORD events. Subscriptions created before
 * authentication are remembered and activated when a peer becomes ready. */
/* One active stream per endpoint, direction, content type and name.
 * Delivery mode is immutable; conflicting opens return NULL with STATE status.
 * Publishers and subscribers for the same track must select the same mode. */
qlinq_stream_t *qlinq_publish(qlinq_endpoint_t *endpoint,
                              const qlinq_stream_config_t *config);
qlinq_stream_t *qlinq_subscribe(qlinq_endpoint_t *endpoint,
                                const qlinq_stream_config_t *config);
void qlinq_stream_close(qlinq_stream_t *stream);

bool qlinq_stream_is_writable(qlinq_stream_t *stream);
qlinq_send_result_t qlinq_stream_send(qlinq_stream_t *stream,
                                      const qlinq_record_t *record);

/* Drives network and timer progress for at most timeout_ms. A negative timeout
 * waits until network/timer activity. Pending events make this return
 * immediately. No application callback is made from another thread. */
qlinq_status_t qlinq_service(qlinq_context_t *context, int timeout_ms);

/* Pops one event, transferring its allocation to the caller and releasing
 * queue capacity. Record bytes and strings survive context destruction until
 * release; endpoint/stream handles survive only until context destruction.
 * Release each popped event exactly once. Do not release a copied event twice.
 */
bool qlinq_next_event(qlinq_context_t *context, qlinq_event_t *event);
void qlinq_event_release(qlinq_event_t *event);

qlinq_status_t qlinq_context_last_status(const qlinq_context_t *context);
bool qlinq_endpoint_get_stats(qlinq_endpoint_t *endpoint,
                              qlinq_endpoint_stats_t *stats);
bool qlinq_stream_get_stats(qlinq_stream_t *stream,
                            qlinq_stream_stats_t *stats);

#ifdef __cplusplus
}
#endif

#endif /* QLINQ_H */
