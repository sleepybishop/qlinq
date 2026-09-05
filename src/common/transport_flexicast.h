#ifndef QLINQ_TRANSPORT_FLEXICAST_H
#define QLINQ_TRANSPORT_FLEXICAST_H

#include "transport.h"
#include "transport_repair.h"
#include "transport_wire.h"

#include "quicly/flexicast.h"

#define TRANSPORT_FLEXICAST_MAX_FLOWS 256U
#define TRANSPORT_FLEXICAST_SECRET_SIZE 32U
#define TRANSPORT_FLEXICAST_ACK_PACKET_THRESHOLD 32U
#define TRANSPORT_FLEXICAST_MISSED_FEEDBACK_WINDOWS 3U
#define TRANSPORT_FLEXICAST_QUEUE_CAPACITY 256U
#define TRANSPORT_FLEXICAST_REPAIR_QUEUE_CAPACITY 128U
#define TRANSPORT_FLEXICAST_PENDING_REPAIRS 64U
#define TRANSPORT_FLEXICAST_REPAIR_REQUESTERS 1024U
/* Match the minimum randomized receiver NACK backoff. A shorter source window
 * closes before independently paced receiver feedback can coalesce. */
#define TRANSPORT_FLEXICAST_REPAIR_HOLDOFF_MS 25
#define TRANSPORT_FLEXICAST_REPAIR_PRIORITY_IDLE_MS 250
#define TRANSPORT_FLEXICAST_RECENT_REPAIRS 128U
#define TRANSPORT_FLEXICAST_REPAIR_REISSUE_MS 1000
#define TRANSPORT_FLEXICAST_REKEY_HOLDOFF_MS 250
#define TRANSPORT_FLEXICAST_SHADOW_OBSERVATIONS 64U
#define TRANSPORT_FLEXICAST_SHADOW_OBSERVATION_MS 500U

typedef struct transport_flexicast_member_t {
  transport_conn_t *conn;
  bool joined;
  bool listening;
  bool offer_pending;
  bool offer_bind_sent;
  uint32_t offer_epoch;
  quicly_flexicast_announce_frame_t offer_announce;
  /* FC_KEY enqueue can fail transiently when a member's control stream is
   * backpressured. Keep membership and retry instead of silently stranding
   * that receiver on the unicast repair path. */
  bool key_pending;
  /* A subscriber becomes responsible for recovery only after it has the
   * current group key and confirms that its multicast socket is listening. */
  bool recovery_baseline_pending;
  /* Epoch carried by the JOIN that established the current membership. It
   * distinguishes a concurrent pre-rekey LEAVE from a delayed LEAVE that
   * predates a later rejoin on the same connection. */
  uint32_t join_sequence;
  uint64_t acknowledged_delivery_epoch;
  int64_t last_ack_time_ms;
} transport_flexicast_member_t;

typedef struct transport_flexicast_member_map_entry_t {
  const transport_conn_t *conn;
  size_t slot;
  uint8_t state;
} transport_flexicast_member_map_entry_t;

typedef struct transport_flexicast_queued_payload_t {
  uint8_t *data;
  size_t size;
  int64_t enqueued_at_ms;
  uint64_t group_id;
  uint64_t object_id;
  uint16_t symbol_index;
  transport_repair_mode_t repair_mode;
} transport_flexicast_queued_payload_t;

typedef struct transport_flexicast_pending_repair_t {
  bool active;
  uint64_t intent_id;
  uint64_t group_id;
  uint64_t object_id;
  transport_repair_mode_t mode;
  uint64_t requested_symbols[QLINQ_WIRE_MAX_NACK_SYMBOLS / 64U];
  uint16_t requested_dof;
  int64_t first_request_ms;
  int64_t ready_at_ms;
  bool backpressure_reported;
  bool shadow_evaluated;
  size_t retained_requesters;
  size_t overflow_requests;
  uint64_t retained_deficit_sum;
  uint64_t overflow_deficit_sum;
  uint16_t maximum_requester_deficit;
  uint64_t minimum_delivery_rate_bytes_per_second;
  uint64_t oldest_feedback_age_ms;
  size_t shared_useful_requesters;
} transport_flexicast_pending_repair_t;

typedef struct transport_flexicast_repair_requester_t {
  uint64_t intent_id;
  uint64_t member_id;
  uint16_t deficit;
  uint64_t delivery_rate_bytes_per_second;
  int64_t first_request_ms;
  int64_t last_request_ms;
  int64_t last_feedback_ms;
  /* Latest bounded indexed demand. Rateless requesters leave this empty and
   * use deficit directly. Keeping the set per active requester lets the M4
   * shadow planner compute a subset union without changing wire semantics. */
  uint64_t requested_symbols[QLINQ_WIRE_MAX_NACK_SYMBOLS / 64U];
  /* Expected usefulness from the requester's accepted positive deficit;
   * later requests can confirm progress by reporting a smaller deficit. */
  bool shared_repair_useful;
} transport_flexicast_repair_requester_t;

typedef enum {
  TRANSPORT_FLEXICAST_OBS_ACCEPTED = 0,
  TRANSPORT_FLEXICAST_OBS_SUPPRESSED = 1,
  TRANSPORT_FLEXICAST_OBS_THROTTLED = 2
} transport_flexicast_observation_disposition_t;

typedef struct transport_flexicast_shadow_observation_t {
  bool active;
  uint64_t observation_id;
  uint64_t group_id;
  uint64_t object_id;
  transport_repair_mode_t mode;
  int64_t first_request_ms;
  int64_t ready_at_ms;
  size_t cohort_member_count;
  size_t accepted_requests;
  size_t suppressed_requests;
  size_t throttled_requests;
  size_t overflow_requests;
} transport_flexicast_shadow_observation_t;

typedef struct transport_flexicast_shadow_requester_t {
  uint64_t observation_id;
  uint64_t member_id;
  uint16_t deficit;
  uint64_t delivery_rate_bytes_per_second;
  int64_t first_request_ms;
  int64_t last_request_ms;
  int64_t last_feedback_ms;
  uint64_t requested_symbols[QLINQ_WIRE_MAX_NACK_SYMBOLS / 64U];
} transport_flexicast_shadow_requester_t;

typedef struct transport_flexicast_recent_repair_t {
  bool active;
  uint64_t group_id;
  uint64_t object_id;
  uint16_t symbol_index;
  transport_repair_mode_t mode;
  int64_t expires_at_ms;
} transport_flexicast_recent_repair_t;

typedef struct transport_flexicast_flow_t {
  bool active;
  bool source;
  bool native_multicast;
  bool binding_received;
  bool announcement_received;
  bool join_sent;
  bool multicast_unavailable;
  bool membership_acquired;
  uint8_t ip_version;
  uint8_t alias;
  uint32_t key_epoch;
  uint64_t flow_id;
  moq_track_id_t track_id;
  uint8_t secret[TRANSPORT_FLEXICAST_SECRET_SIZE];
  quicly_flexicast_flow_t *crypto;
  transport_conn_t *control_conn;
  uint8_t source_ip[16];
  uint8_t group_ip[16];
  uint16_t udp_port;
  uint32_t ack_delay_msec;
  uint32_t interface_index;
  transport_flexicast_queued_payload_t
      queued[TRANSPORT_FLEXICAST_QUEUE_CAPACITY];
  size_t queue_head;
  size_t queue_count;
  size_t queue_bytes;
  transport_flexicast_queued_payload_t
      repair_queued[TRANSPORT_FLEXICAST_REPAIR_QUEUE_CAPACITY];
  size_t repair_queue_head;
  size_t repair_queue_count;
  size_t repair_queue_bytes;
  transport_flexicast_pending_repair_t
      pending_repairs[TRANSPORT_FLEXICAST_PENDING_REPAIRS];
  size_t pending_repair_count;
  transport_flexicast_repair_requester_t *repair_requesters;
  size_t repair_requester_count;
  size_t repair_requester_capacity;
  uint64_t next_repair_intent_id;
  transport_flexicast_shadow_observation_t
      shadow_observations[TRANSPORT_FLEXICAST_SHADOW_OBSERVATIONS];
  size_t shadow_observation_count;
  uint64_t next_shadow_observation_id;
  transport_flexicast_shadow_requester_t *shadow_requesters;
  size_t shadow_requester_count;
  size_t shadow_requester_capacity;
  transport_flexicast_recent_repair_t
      recent_repairs[TRANSPORT_FLEXICAST_RECENT_REPAIRS];
  size_t next_recent_repair;
  uint64_t data_airtime_since_repair;
  int64_t last_repair_sent_ms;
  bool repair_priority_available;
  uint64_t cc_interval_physical_bytes;
  uint64_t cc_interval_repair_bytes;
  uint64_t cc_external_load_epoch;
  int64_t cc_external_load_interval_started_ms;
  uint32_t cc_external_load_fraction_ppm;
  uint64_t pacing_rate_bytes_per_second;
  uint64_t pacing_tokens;
  uint64_t pacing_burst_bytes;
  uint64_t pacing_remainder;
  int64_t pacing_last_refill_ms;
  int64_t last_payload_sent_ms;
  quicly_flexicast_cc_type_t *cc_type;
  quicly_flexicast_cc_config_t cc_config;
  transport_flexicast_member_t *members;
  transport_flexicast_member_map_entry_t *member_map;
  size_t member_count;
  size_t listening_count;
  size_t feedback_outstanding_count;
  size_t member_capacity;
  size_t member_map_capacity;
  bool rekey_pending;
  int64_t rekey_ready_at_ms;
  size_t rekey_pending_changes;
  uint64_t delivery_epoch;
  transport_repair_suppression_t repair_suppression;
} transport_flexicast_flow_t;

typedef struct transport_flexicast_membership_t {
  bool active;
  uint8_t ip_version;
  uint8_t source_ip[16];
  uint8_t group_ip[16];
  uint16_t udp_port;
  uint32_t interface_index;
  size_t references;
} transport_flexicast_membership_t;

typedef struct transport_flexicast_registry_t {
  transport_flexicast_flow_t *flows;
  transport_flexicast_membership_t *memberships;
  size_t capacity;
  size_t member_capacity;
} transport_flexicast_registry_t;

bool transport_flexicast_registry_init(transport_flexicast_registry_t *registry,
                                       size_t capacity, size_t member_capacity);
void transport_flexicast_registry_destroy(
    transport_flexicast_registry_t *registry);
/* Releases every flow and performs explicit kernel membership drops before
 * the owning transport closes its multicast socket. */
void transport_flexicast_dispose(transport_t *t);

/* Validates and installs the local native-multicast policy after the ordinary
 * QUIC sockets have been bound. */
bool transport_flexicast_configure(transport_t *t, const char *group,
                                   uint16_t port, const char *interface);

/* Source-side subscription lifecycle. Failure deliberately leaves the member
 * on the ordinary per-connection QUIC DATAGRAM path. */
bool transport_flexicast_offer(transport_t *t, transport_conn_t *conn,
                               const moq_track_id_t *track, uint8_t alias);
void transport_flexicast_remove_member(transport_t *t, transport_conn_t *conn,
                                       const moq_track_id_t *track);
/* Receiver-side teardown used after the reliable qlinq UNSUBSCRIBE frame has
 * been queued. This drops the local SSM reference immediately and sends a
 * best-effort Flexicast LEAVE to accelerate source-side rekeying. */
void transport_flexicast_unsubscribe(transport_t *t, transport_conn_t *conn,
                                     const moq_track_id_t *track);
void transport_flexicast_remove_connection(transport_t *t,
                                           transport_conn_t *conn);

bool transport_flexicast_receive_bind(transport_t *t, transport_conn_t *conn,
                                      const qlinq_wire_flexicast_bind_t *bind);
bool transport_flexicast_receive_path_ack(transport_t *t,
                                          transport_conn_t *conn,
                                          uint64_t flow_id,
                                          const quicly_ack_frame_t *ack);
bool transport_flexicast_receive_quic_frame(
    transport_t *t, transport_conn_t *conn,
    const quicly_flexicast_frame_t *frame);

/* Recognizes and decrypts a Flexicast packet in-place. A true result means the
 * UDP datagram belonged to a known flow and must not be passed to quicly. */
bool transport_flexicast_receive_packet(transport_t *t, uint8_t *packet,
                                        size_t packet_size,
                                        transport_conn_t **source_conn,
                                        ptls_iovec_t *payload);

bool transport_flexicast_send_ack(transport_flexicast_flow_t *flow,
                                  uint64_t packet_number);
transport_flexicast_flow_t *
transport_flexicast_find_source(transport_t *t, const moq_track_id_t *track);
transport_flexicast_flow_t *transport_flexicast_find_source_member(
    transport_t *t, const moq_track_id_t *track, const transport_conn_t *conn);
size_t
transport_flexicast_listening_members(const transport_flexicast_flow_t *flow);
bool transport_flexicast_member_is_listening(
    const transport_flexicast_flow_t *flow, const transport_conn_t *conn);
bool transport_flexicast_send_payload(transport_t *t,
                                      transport_flexicast_flow_t *flow,
                                      ptls_iovec_t payload);
bool transport_flexicast_schedule_repair(
    transport_t *t, transport_flexicast_flow_t *flow,
    const sent_object_cache_t *object, uint64_t requester_id,
    transport_repair_mode_t mode, bool whole_object, const uint16_t *missing,
    size_t missing_count, int64_t now_ms);
void transport_flexicast_observe_repair_request(
    transport_t *t, transport_flexicast_flow_t *flow,
    const sent_object_cache_t *object, uint64_t requester_id,
    transport_repair_mode_t mode, bool whole_object, const uint16_t *missing,
    size_t missing_count,
    transport_flexicast_observation_disposition_t disposition, int64_t now_ms);
size_t transport_flexicast_cancel_repairs_through(transport_t *t,
                                                  const moq_track_id_t *track,
                                                  uint64_t group_id,
                                                  uint64_t object_id);
size_t transport_flexicast_cancel_track_repairs(transport_t *t,
                                                const moq_track_id_t *track);
bool transport_flexicast_can_queue(const transport_t *t,
                                   const transport_flexicast_flow_t *flow,
                                   size_t packets, size_t bytes);
void transport_flexicast_tick(transport_t *t);
int64_t transport_flexicast_get_first_timeout(transport_t *t);
bool transport_flexicast_track_ready(transport_t *t,
                                     const moq_track_id_t *track);

#endif
