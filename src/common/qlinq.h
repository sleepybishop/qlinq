/* qlinq.h
 *
 * Native application API for named, independently configured streams.
 *
 * A context owns endpoints and an event queue. An endpoint either listens for
 * peers or connects to one peer over one or more network paths. Applications
 * publish or subscribe to named streams on an endpoint. No stream operation
 * starts a private worker thread; the creating thread drives progress with
 * qlinq_service().
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
  QLINQ_STREAM_FINISHING,
  QLINQ_STREAM_FINISHED,
  QLINQ_STREAM_ABORTED,
  QLINQ_STREAM_CLOSED
} qlinq_stream_state_t;

typedef enum {
  QLINQ_REPAIR_AUTO = 0,
  QLINQ_REPAIR_INDEXED = 1,
  QLINQ_REPAIR_RATELESS = 2
} qlinq_repair_mode_t;

typedef enum {
  QLINQ_GROUP_CC_CONSERVATIVE = 0,
  QLINQ_GROUP_CC_ADAPTIVE = 1
} qlinq_group_cc_t;

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
  size_t max_subscriptions_per_peer;
  size_t max_active_receive_objects_per_peer;
  size_t max_repair_requests_per_second;
  size_t max_aggregate_repair_requests_per_second;
  size_t max_egress_packets_per_socket;
  size_t max_egress_bytes_per_socket;
  size_t max_receive_memory_bytes;
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
  bool enabled;
  /* A source sets group_address, port, and interface_address. A receiver may
   * set only interface_address and learns the group from the source. */
  const char *group_address;
  uint16_t port;
  const char *interface_address;
  qlinq_group_cc_t congestion_control;
  uint64_t startup_rate_bytes_per_second;
  uint64_t minimum_rate_bytes_per_second;
  uint64_t maximum_rate_bytes_per_second;
  uint64_t aggregate_rate_bytes_per_second;
  uint32_t feedback_timeout_ms;
} qlinq_group_delivery_config_t;

typedef struct {
  const char *bind_addresses[QLINQ_MAX_PATHS];
  size_t bind_address_count;
  const char *remote_addresses[QLINQ_MAX_PATHS];
  size_t remote_address_count;
  uint16_t port;
  uint64_t idle_timeout_ms;
  bool reconnect_enabled;
  uint32_t reconnect_initial_delay_ms;
  uint32_t reconnect_max_delay_ms;
  qlinq_security_config_t security;
  qlinq_group_delivery_config_t group_delivery;
  qlinq_repair_mode_t repair_mode;
  uint64_t repair_feedback_seed;
  qlinq_limits_t limits;
} qlinq_endpoint_config_t;

typedef struct {
  /* Zero values select 1,024 events and 64 MiB of copied event payloads. */
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
  QLINQ_EVENT_STREAM_FINISHED,
  QLINQ_EVENT_STREAM_DRAINED,
  QLINQ_EVENT_STREAM_ABORTED,
  QLINQ_EVENT_ERROR
} qlinq_event_type_t;

typedef struct {
  uint64_t error_code;
  int64_t raw_error;
  bool application_error;
  uint64_t offending_frame_type;
  bool remote;
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
  struct {
    size_t peers_total;
    size_t peers_completed;
    size_t peers_failed;
  } completion;
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
  uint64_t internal_state_recoveries;
  uint64_t records_received;
  uint64_t fec_objects_recovered;
  uint64_t fec_objects_lost;
  uint64_t repair_requests_sent;
  uint64_t repair_requests_received;
  uint64_t repair_symbols_sent;
  uint64_t repair_commit_failures;
  uint64_t group_payloads_accepted;
  uint64_t group_plaintext_bytes_accepted;
  uint64_t group_physical_packets_sent;
  size_t group_protected_packets_queued;
  size_t group_protected_bytes_queued;
  uint64_t group_packets_sent;
  uint64_t group_packets_received;
  uint64_t group_native_packets_sent;
  uint64_t group_fallbacks;
  uint64_t group_feedback_fallbacks;
  uint64_t group_control_frames_throttled;
  uint64_t group_rekeys;
  uint64_t group_interface_fallbacks;
  uint64_t group_interface_rejoins;
  uint64_t group_rate_bytes_per_second;
  uint64_t group_physical_bytes_sent;
  uint64_t repair_physical_bytes_sent;
  uint64_t repair_oldest_age_ms;
  size_t active_connections;
  size_t active_group_flows;
  size_t active_group_memberships;
  size_t active_group_members;
  size_t repair_queued_packets;
  size_t repair_queued_bytes;
  size_t queued_packets;
  size_t queued_bytes;
} qlinq_endpoint_stats_t;

typedef struct {
  qlinq_stream_state_t state;
  uint64_t records_sent;
  uint64_t records_received;
  uint64_t objects_lost;
  size_t subscribers;
  size_t group_members;
  size_t confirmations_pending;
  size_t confirmations_completed;
  size_t confirmations_failed;
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
  bool quic_ready;
  bool protocol_ready;
  bool authenticated;
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
qlinq_stream_t *qlinq_publish(qlinq_endpoint_t *endpoint,
                              const qlinq_stream_config_t *config);
qlinq_stream_t *qlinq_subscribe(qlinq_endpoint_t *endpoint,
                                const qlinq_stream_config_t *config);
void qlinq_stream_close(qlinq_stream_t *stream);

bool qlinq_stream_is_writable(qlinq_stream_t *stream);
qlinq_send_result_t qlinq_stream_send(qlinq_stream_t *stream,
                                      const qlinq_record_t *record);

/* Starts the finite completion of a FEC-backed data stream and flushes its
 * partial coding group. Completion is asynchronous: subscribers receive
 * STREAM_FINISHED after recovery, and the publisher receives STREAM_DRAINED
 * after the finishing cohort has either confirmed or departed. */
qlinq_status_t qlinq_stream_finish(qlinq_stream_t *stream);

/* Terminates a publishing stream and notifies its current subscribers. */
qlinq_status_t qlinq_stream_abort(qlinq_stream_t *stream);

/* Drives network and timer progress for at most timeout_ms. A negative timeout
 * waits until network/timer activity. Pending events make this return
 * immediately. No application callback is made from another thread. */
qlinq_status_t qlinq_service(qlinq_context_t *context, int timeout_ms);

/* Pops one event. Record bytes and message text remain valid until release. */
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
