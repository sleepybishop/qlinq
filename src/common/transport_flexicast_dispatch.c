#include "transport_flexicast.h"
#include "transport_flexicast_internal.h"

#include "portable_sockets.h"
#include "transport_egress.h"
#include "transport_internal.h"
#include "transport_paths.h"
#include "transport_publish.h"
#include "transport_scheduler.h"
#include "transport_stream.h"
#include "transport_subscriptions.h"
#include "transport_tracks.h"
#include "transport_udp.h"

#include "quicly/defaults.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLEXICAST_EXTERNAL_LOAD_SCALE 1000000U

transport_flexicast_queued_payload_t *
tf_queue_at(transport_flexicast_queue_t *queue, size_t index) {
  if (!queue || index >= queue->count || !queue->entries)
    return NULL;
  return &queue->entries[(queue->head + index) % queue->capacity];
}

const transport_flexicast_queued_payload_t *
tf_queue_at_const(const transport_flexicast_queue_t *queue, size_t index) {
  if (!queue || index >= queue->count || !queue->entries)
    return NULL;
  return &queue->entries[(queue->head + index) % queue->capacity];
}

static transport_flexicast_queued_payload_t *
queue_front(transport_flexicast_queue_t *queue) {
  return tf_queue_at(queue, 0);
}

bool tf_queue_push(transport_flexicast_queue_t *queue,
                   const transport_flexicast_queued_payload_t *payload) {
  if (!queue || !payload || !payload->data || queue->count >= queue->capacity ||
      payload->size > SIZE_MAX - queue->bytes)
    return false;
  if (!queue->entries) {
    if (queue->capacity > SIZE_MAX / sizeof(*queue->entries))
      return false;
    queue->entries = calloc(queue->capacity, sizeof(*queue->entries));
    if (!queue->entries)
      return false;
  }
  size_t tail = (queue->head + queue->count) % queue->capacity;
  queue->entries[tail] = *payload;
  queue->count++;
  queue->bytes += payload->size;
  return true;
}

static void queue_pop(transport_flexicast_queue_t *queue) {
  transport_flexicast_queued_payload_t *payload = queue_front(queue);
  if (!payload)
    return;
  queue->bytes =
      payload->size <= queue->bytes ? queue->bytes - payload->size : 0;
  free(payload->data);
  free(payload->packet);
  memset(payload, 0, sizeof(*payload));
  queue->head = (queue->head + 1U) % queue->capacity;
  queue->count--;
}

size_t tf_queue_clear(transport_flexicast_queue_t *queue) {
  if (!queue)
    return 0;
  size_t cleared = queue->count;
  while (queue->count != 0)
    queue_pop(queue);
  queue->head = 0;
  return cleared;
}

void tf_queue_dispose(transport_flexicast_queue_t *queue) {
  if (!queue)
    return;
  (void)tf_queue_clear(queue);
  free(queue->entries);
  memset(queue, 0, sizeof(*queue));
}

static struct sockaddr_storage multicast_source_address(const transport_t *t) {
  struct sockaddr_storage source = {0};
  source.ss_family = t->flexicast_group_addr.ss_family;
  if (source.ss_family == AF_INET)
    ((struct sockaddr_in *)&source)->sin_addr = t->flexicast_interface_v4;
  else if (source.ss_family == AF_INET6) {
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&source;
    v6->sin6_addr = t->flexicast_interface_v6;
    if (IN6_IS_ADDR_LINKLOCAL(&v6->sin6_addr))
      v6->sin6_scope_id = t->flexicast_interface_index;
  }
  return source;
}

static uint64_t member_delivery_rate(const transport_flexicast_member_t *member,
                                     size_t packet_size) {
  if (!member || !member->conn || !member->conn->quic)
    return 0;
  quicly_stats_t stats;
  if (quicly_get_stats(member->conn->quic, &stats) != 0)
    return 0;
  uint64_t rate = stats.delivery_rate.smoothed != 0
                      ? stats.delivery_rate.smoothed
                      : stats.delivery_rate.latest;
  if (rate == 0) {
    uint64_t rtt = stats.rtt.smoothed != 0 ? stats.rtt.smoothed : 100;
    uint64_t cwnd = stats.cc.cwnd >= packet_size ? stats.cc.cwnd : packet_size;
    rate = cwnd > UINT64_MAX / 1000U ? UINT64_MAX : cwnd * 1000U / rtt;
  }
  return rate;
}

size_t tf_pending_repair_symbol_count(
    const transport_flexicast_pending_repair_t *pending) {
  return pending->mode == TRANSPORT_REPAIR_MODE_RATELESS
             ? pending->requested_dof
             : tf_repair_symbol_count(pending->requested_symbols);
}

uint64_t tf_saturating_add_u64(uint64_t left, uint64_t right) {
  return right > UINT64_MAX - left ? UINT64_MAX : left + right;
}

static void account_controller_airtime(transport_flexicast_flow_t *flow,
                                       uint64_t bytes, bool repair) {
  flow->cc_interval_physical_bytes =
      tf_saturating_add_u64(flow->cc_interval_physical_bytes, bytes);
  if (repair)
    flow->cc_interval_repair_bytes =
        tf_saturating_add_u64(flow->cc_interval_repair_bytes, bytes);
}

static void update_external_load_hint(const transport_t *t,
                                      transport_flexicast_flow_t *flow,
                                      quicly_flexicast_cc_hints_t *hints,
                                      int64_t now) {
  uint64_t interval = t->flexicast_cc_feedback_timeout_ms != 0
                          ? t->flexicast_cc_feedback_timeout_ms
                          : 1000U;
  if (flow->cc_external_load_interval_started_ms == 0) {
    flow->cc_external_load_interval_started_ms = now;
    if (flow->cc_external_load_epoch == 0)
      flow->cc_external_load_epoch = 1;
  } else if (now > flow->cc_external_load_interval_started_ms &&
             (uint64_t)(now - flow->cc_external_load_interval_started_ms) >=
                 interval) {
    flow->cc_external_load_fraction_ppm =
        flow->cc_interval_physical_bytes == 0
            ? 0
            : (uint32_t)((flow->cc_interval_repair_bytes >
                                  UINT64_MAX / FLEXICAST_EXTERNAL_LOAD_SCALE
                              ? UINT64_MAX
                              : flow->cc_interval_repair_bytes *
                                    FLEXICAST_EXTERNAL_LOAD_SCALE) /
                         flow->cc_interval_physical_bytes);
    flow->cc_interval_physical_bytes = 0;
    flow->cc_interval_repair_bytes = 0;
    flow->cc_external_load_interval_started_ms = now;
    if (flow->cc_external_load_epoch != UINT64_MAX)
      flow->cc_external_load_epoch++;
  }

  uint64_t queued = flow->repair_queue.bytes;
  uint64_t oldest = 0;
  size_t packet_size = t->limits.max_udp_payload_size;
  for (size_t i = 0; i < TRANSPORT_FLEXICAST_PENDING_REPAIRS; i++) {
    const transport_flexicast_pending_repair_t *pending =
        &flow->pending_repairs[i];
    if (!pending->active)
      continue;
    size_t symbols = tf_pending_repair_symbol_count(pending);
    uint64_t bytes = symbols > UINT64_MAX / packet_size
                         ? UINT64_MAX
                         : (uint64_t)symbols * packet_size;
    queued = tf_saturating_add_u64(queued, bytes);
    if (pending->first_request_ms > 0 && now > pending->first_request_ms &&
        (uint64_t)(now - pending->first_request_ms) > oldest)
      oldest = (uint64_t)(now - pending->first_request_ms);
  }
  for (size_t i = 0; i < flow->repair_queue.count; i++) {
    const transport_flexicast_queued_payload_t *queued =
        tf_queue_at_const(&flow->repair_queue, i);
    int64_t enqueued = queued->enqueued_at_ms;
    if (enqueued > 0 && now > enqueued && (uint64_t)(now - enqueued) > oldest)
      oldest = (uint64_t)(now - enqueued);
  }
  hints->external_load_epoch = flow->cc_external_load_epoch;
  hints->external_load_queued_bytes = queued;
  hints->external_load_oldest_age_msec = oldest;
  hints->external_load_fraction_ppm = flow->cc_external_load_fraction_ppm;
}

static void update_controller_hints(transport_t *t,
                                    transport_flexicast_flow_t *flow,
                                    int64_t now) {
  quicly_flexicast_cc_hints_t hints = {0};
  uint64_t rates[TRANSPORT_FLEXICAST_MAX_FLOWS];
  size_t count = 0;
  int64_t active_window =
      2 * (int64_t)(t->flexicast_cc_feedback_timeout_ms != 0
                        ? t->flexicast_cc_feedback_timeout_ms
                        : 1000U);
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *candidate = &t->flexicast.flows[i];
    if (!candidate->active || !candidate->source || !candidate->crypto ||
        transport_flexicast_listening_members(candidate) == 0 ||
        (candidate != flow && candidate->data_queue.count == 0 &&
         candidate->repair_queue.count == 0 &&
         candidate->pending_repair_count == 0 &&
         (candidate->last_payload_sent_ms == 0 ||
          now - candidate->last_payload_sent_ms > active_window)))
      continue;
    quicly_flexicast_cc_output_t output;
    quicly_flexicast_cc_get_flow_output(candidate->crypto, &output);
    rates[count++] = output.rate_bytes_per_second;
  }
  if (count == 0) {
    quicly_flexicast_cc_output_t output;
    quicly_flexicast_cc_get_flow_output(flow->crypto, &output);
    rates[0] = output.rate_bytes_per_second;
    count = 1;
  }
  for (size_t i = 1; i < count; i++) {
    uint64_t value = rates[i];
    size_t j = i;
    while (j > 0 && rates[j - 1] > value) {
      rates[j] = rates[j - 1];
      j--;
    }
    rates[j] = value;
  }
  hints.active_senders = (uint32_t)count;
  hints.median_sender_rate_bytes_per_second = rates[count / 2];
  if (t->flexicast_cc_aggregate_rate_limit != 0)
    hints.aggregate_rate_limit_bytes_per_second =
        t->flexicast_cc_aggregate_rate_limit / count;
  update_external_load_hint(t, flow, &hints, now);
  quicly_flexicast_cc_set_flow_hints(flow->crypto, &hints, now);
}

static void refresh_pacer(transport_t *t, transport_flexicast_flow_t *flow,
                          int64_t now) {
  update_controller_hints(t, flow, now);
  quicly_flexicast_cc_output_t cc_output;
  quicly_flexicast_cc_get_flow_output(flow->crypto, &cc_output);
  if (flow->listening_count == 0)
    return;
  uint64_t rate = cc_output.rate_bytes_per_second;
  uint64_t burst = cc_output.burst_bytes;
  if (rate == 0) {
    uint64_t slowest = UINT64_MAX;
    for (size_t i = 0; i < flow->member_count; i++) {
      transport_flexicast_member_t *member = &flow->members[i];
      if (!member->conn || !member->listening)
        continue;
      uint64_t member_rate =
          member_delivery_rate(member, t->limits.max_udp_payload_size);
      if (member_rate != 0 && member_rate < slowest)
        slowest = member_rate;
    }
    if (slowest == UINT64_MAX)
      slowest = 64U * 1024U;
    /* Compatibility fallback for flows created without a controller. */
    rate = slowest * 4U / 5U;
  }
  if (burst == 0)
    burst = rate / 20U;
  uint64_t minimum_burst = t->limits.max_udp_payload_size * 4U;
  if (burst < minimum_burst)
    burst = minimum_burst;
  uint64_t maximum_burst = t->limits.max_udp_payload_size * 10U;
  if (burst > maximum_burst)
    burst = maximum_burst;

  if (flow->pacing_last_refill_ms == 0) {
    flow->pacing_tokens = burst;
    flow->pacing_last_refill_ms = now;
  } else if (now > flow->pacing_last_refill_ms) {
    uint64_t elapsed = (uint64_t)(now - flow->pacing_last_refill_ms);
    if (elapsed > 60000U)
      elapsed = 60000U;
    uint64_t numerator = elapsed * rate + flow->pacing_remainder;
    uint64_t added = numerator / 1000U;
    flow->pacing_remainder = numerator % 1000U;
    flow->pacing_tokens =
        added >= burst -
                     (flow->pacing_tokens < burst ? flow->pacing_tokens : burst)
            ? burst
            : flow->pacing_tokens + added;
    flow->pacing_last_refill_ms = now;
  }
  flow->pacing_rate_bytes_per_second = rate;
  flow->pacing_burst_bytes = burst;
  if (flow->pacing_tokens > burst)
    flow->pacing_tokens = burst;
}

static size_t pacing_cost(const transport_flexicast_flow_t *flow,
                          size_t payload_size) {
  return quicly_flexicast_datagram_size(flow->crypto, payload_size);
}

static uint64_t fanout_cost(const transport_flexicast_flow_t *flow,
                            size_t packet_size) {
  size_t copies = flow->native_multicast ? 1 : flow->listening_count;
  return copies != 0 && packet_size <= UINT64_MAX / copies
             ? packet_size * copies
             : UINT64_MAX;
}

typedef enum {
  FLEXICAST_DISPATCH_OK,
  FLEXICAST_DISPATCH_BLOCKED,
  FLEXICAST_DISPATCH_FAILED,
} flexicast_dispatch_result_t;

/* Protected packets stay with their plaintext until submitted. In particular,
 * the generic egress queue must not emit an old group epoch after a rekey. */
static int
submit_protected_packet(transport_t *t, size_t socket_index,
                        const struct sockaddr *destination,
                        const struct sockaddr *source,
                        const transport_flexicast_queued_payload_t *queued) {
  if (socket_index == SIZE_MAX || t->fds[socket_index] < 0)
    return -1;
  transport_egress_t *egress = &t->egress[socket_index];
  if (egress->count != 0)
    return 0;
  struct iovec vec = {.iov_base = queued->packet,
                      .iov_len = queued->packet_size};
  socklen_t destination_len = destination->sa_family == AF_INET
                                  ? sizeof(struct sockaddr_in)
                                  : sizeof(struct sockaddr_in6);
  ssize_t sent =
      source
          ? transport_udp_send_from(t->fds[socket_index], destination, source,
                                    t->flexicast_interface_index, &vec)
          : transport_udp_send_batch(t->fds[socket_index], destination,
                                     destination_len, &vec, 1);
  if (sent > 0) {
    egress->packets_sent++;
    egress->bytes_sent += queued->packet_size;
    return 1;
  }
  if (sent == 0) {
    egress->would_block++;
    return 0;
  }
  egress->send_errors++;
  return -1;
}

static void
account_protected_packet(transport_t *t, transport_flexicast_flow_t *flow,
                         transport_flexicast_queued_payload_t *queued,
                         bool native) {
  if (!queued->counted) {
    tf_advance_delivery_epoch(flow);
    t->stats.flexicast_packets_sent++;
    t->stats.flexicast_paced_packets++;
    queued->counted = true;
  }
  t->stats.flexicast_physical_packets_sent++;
  if (native)
    t->stats.flexicast_native_packets_sent++;
  flow->last_payload_sent_ms = transport_get_time_ms();
  flow->pacing_tokens -= queued->packet_size;
  queued->airtime_bytes += queued->packet_size;
}

static flexicast_dispatch_result_t
dispatch_payload(transport_t *t, transport_flexicast_flow_t *flow,
                 transport_flexicast_queued_payload_t *queued) {
  if (flow->rekey_pending)
    return FLEXICAST_DISPATCH_BLOCKED;
  int64_t now = transport_get_time_ms();
  if (now < flow->dispatch_retry_at_ms)
    return FLEXICAST_DISPATCH_BLOCKED;
  if (queued->packet && queued->packet_epoch != flow->key_epoch) {
    free(queued->packet);
    queued->packet = NULL;
    queued->next_member = 0;
    queued->counted = false;
    /* An interrupted replicated packet remains replicated after rotation:
     * members already served must not see its plaintext a second time. */
    queued->replicated = true;
  }
  if (!queued->packet) {
    for (size_t i = 0; i < flow->member_count; i++) {
      if (flow->members[i].joined && !flow->members[i].listening) {
        flow->dispatch_retry_at_ms = now + 10;
        return FLEXICAST_DISPATCH_BLOCKED;
      }
    }
    size_t size = pacing_cost(flow, queued->size);
    if (size == 0 || size > t->limits.max_udp_payload_size)
      return FLEXICAST_DISPATCH_FAILED;
    if (size > flow->pacing_tokens)
      return FLEXICAST_DISPATCH_BLOCKED;
    queued->packet = malloc(size);
    if (!queued->packet)
      return FLEXICAST_DISPATCH_FAILED;
    int result = quicly_flexicast_send_datagram_at(
        flow->crypto, ptls_iovec_init(queued->data, queued->size),
        queued->packet, size, &queued->packet_size, &queued->packet_number,
        now);
    if (result != QUICLY_FLEXICAST_OK) {
      free(queued->packet);
      queued->packet = NULL;
      if (result == QUICLY_FLEXICAST_ERROR_SEND_WINDOW) {
        flow->dispatch_retry_at_ms = now + 10;
        return FLEXICAST_DISPATCH_BLOCKED;
      }
      return FLEXICAST_DISPATCH_FAILED;
    }
    queued->packet_epoch = flow->key_epoch;
    if (queued->delivery_id == 0) {
      if (++flow->next_payload_delivery_id == 0) {
        flow->next_payload_delivery_id = 1;
        for (size_t i = 0; i < flow->member_count; i++)
          flow->members[i].payload_delivery_id = 0;
      }
      queued->delivery_id = flow->next_payload_delivery_id;
    }
    for (size_t i = 0; i < flow->member_count; i++) {
      transport_flexicast_member_t *member = &flow->members[i];
      if (member->payload_delivery_id == queued->delivery_id ||
          !transport_publish_recipient_eligible(t, member->conn,
                                                &flow->track_id)) {
        int complete;
        (void)quicly_flexicast_abandon_datagram(
            flow->crypto, member->conn->id, queued->packet_number, &complete);
      }
    }
  }

  if (!queued->replicated && flow->native_multicast &&
      t->flexicast_native_source) {
    struct sockaddr *group = (struct sockaddr *)&t->flexicast_group_addr;
    struct sockaddr_storage source = multicast_source_address(t);
    size_t fd_index = transport_path_socket_for_source(
        t->local_addrs, t->num_fds, (struct sockaddr *)&source);
    int result = submit_protected_packet(t, fd_index, group,
                                         (struct sockaddr *)&source, queued);
    if (result > 0) {
      account_protected_packet(t, flow, queued, true);
      return FLEXICAST_DISPATCH_OK;
    }
    if (result == 0) {
      flow->dispatch_retry_at_ms = now + 10;
      return FLEXICAST_DISPATCH_BLOCKED;
    }
    t->stats.flexicast_fallbacks++;
  }
  queued->replicated = true;
  while (queued->next_member < flow->member_count) {
    transport_flexicast_member_t *member = &flow->members[queued->next_member];
    if (!member->listening ||
        member->payload_delivery_id == queued->delivery_id ||
        !transport_publish_recipient_eligible(t, member->conn,
                                              &flow->track_id)) {
      queued->next_member++;
      continue;
    }
    if (queued->packet_size > flow->pacing_tokens)
      return FLEXICAST_DISPATCH_BLOCKED;
    struct sockaddr_storage destination;
    size_t fd_index = transport_path_socket_for_peer(
        member->conn->quic, t->local_addrs, t->num_fds, &destination);
    int result = submit_protected_packet(
        t, fd_index, (struct sockaddr *)&destination, NULL, queued);
    if (result == 0) {
      flow->dispatch_retry_at_ms = now + 10;
      return FLEXICAST_DISPATCH_BLOCKED;
    }
    if (result > 0) {
      account_protected_packet(t, flow, queued, false);
    } else {
      int complete;
      (void)quicly_flexicast_abandon_datagram(flow->crypto, member->conn->id,
                                              queued->packet_number, &complete);
      t->stats.flexicast_fallbacks++;
      t->stats.flexicast_pacing_dropped++;
    }
    member->payload_delivery_id = queued->delivery_id;
    queued->next_member++;
  }
  /* Removal swaps member slots. Rescan only at the end, avoiding an O(N^2)
   * lookup for normal large-cohort replication while not skipping a moved
   * survivor. The same markers survive key changes. */
  for (size_t i = 0; i < flow->member_count; i++) {
    transport_flexicast_member_t *member = &flow->members[i];
    if (member->listening &&
        member->payload_delivery_id != queued->delivery_id &&
        transport_publish_recipient_eligible(t, member->conn,
                                             &flow->track_id)) {
      queued->next_member = i;
      return FLEXICAST_DISPATCH_BLOCKED;
    }
  }
  return FLEXICAST_DISPATCH_OK;
}

bool transport_flexicast_can_queue(const transport_t *t,
                                   const transport_flexicast_flow_t *flow,
                                   size_t packets, size_t bytes) {
  if (!t || !flow || packets > TRANSPORT_FLEXICAST_QUEUE_CAPACITY ||
      flow->data_queue.count > TRANSPORT_FLEXICAST_QUEUE_CAPACITY ||
      packets > TRANSPORT_FLEXICAST_QUEUE_CAPACITY - flow->data_queue.count ||
      bytes > t->limits.max_egress_bytes_per_socket ||
      flow->data_queue.bytes > t->limits.max_egress_bytes_per_socket ||
      flow->repair_queue.bytes > t->limits.max_egress_bytes_per_socket ||
      flow->repair_queue.bytes >
          t->limits.max_egress_bytes_per_socket - flow->data_queue.bytes ||
      bytes > t->limits.max_egress_bytes_per_socket - flow->data_queue.bytes -
                  flow->repair_queue.bytes)
    return false;
  return true;
}

static bool queue_payload(transport_t *t, transport_flexicast_flow_t *flow,
                          ptls_iovec_t payload) {
  if (payload.len > SIZE_MAX - 128U ||
      !transport_flexicast_can_queue(t, flow, 1, payload.len)) {
    t->stats.flexicast_pacing_backpressure++;
    return false;
  }
  uint8_t *copy = malloc(payload.len);
  if (!copy)
    return false;
  memcpy(copy, payload.base, payload.len);
  transport_flexicast_queued_payload_t queued = {.data = copy,
                                                 .size = payload.len,
                                                 .enqueued_at_ms =
                                                     transport_get_time_ms()};
  if (!tf_queue_push(&flow->data_queue, &queued)) {
    free(copy);
    return false;
  }
  t->stats.flexicast_payloads_accepted++;
  t->stats.flexicast_plaintext_bytes_accepted += payload.len;
  return true;
}

bool transport_flexicast_send_payload(transport_t *t,
                                      transport_flexicast_flow_t *flow,
                                      ptls_iovec_t payload) {
  if (!t || !flow || !flow->source || !flow->crypto || !payload.base ||
      pacing_cost(flow, payload.len) == 0 ||
      pacing_cost(flow, payload.len) > t->limits.max_udp_payload_size ||
      flow->listening_count == 0 || !queue_payload(t, flow, payload))
    return false;
  /* Immediate and deferred publication share exactly the same admission,
   * rekey, pacing, socket-selection and accounting path. */
  tf_drain_paced_payloads(t, flow);
  if (flow->data_queue.count != 0)
    t->stats.flexicast_pacing_delays++;
  return true;
}

static bool repair_has_priority(const transport_flexicast_flow_t *flow,
                                uint64_t repair_cost) {
  if (flow->repair_queue.count == 0)
    return false;
  if (flow->data_queue.count == 0 || flow->repair_priority_available)
    return true;
  return repair_cost <= UINT64_MAX / 3U &&
         flow->data_airtime_since_repair >= repair_cost * 3U;
}

typedef struct {
  transport_flexicast_queued_payload_t *payload;
  size_t cost;
  bool repair;
} flexicast_queue_selection_t;

static flexicast_queue_selection_t
select_queued_payload(transport_flexicast_flow_t *flow) {
  transport_flexicast_queued_payload_t *repair =
      queue_front(&flow->repair_queue);
  size_t repair_cost = repair ? pacing_cost(flow, repair->size) : SIZE_MAX;
  bool use_repair = repair_has_priority(flow, fanout_cost(flow, repair_cost));
  transport_flexicast_queued_payload_t *data_head =
      queue_front(&flow->data_queue);
  if (data_head && data_head->delivery_id != 0)
    use_repair = false;
  else if (repair && repair->delivery_id != 0)
    use_repair = true;
  transport_flexicast_queued_payload_t *payload =
      use_repair ? repair : queue_front(&flow->data_queue);
  if (!payload)
    payload = repair;
  if (!payload)
    return (flexicast_queue_selection_t){0};

  size_t cost = pacing_cost(flow, payload->size);
  if (use_repair && payload->delivery_id == 0 && cost > flow->pacing_tokens &&
      flow->data_queue.count != 0) {
    transport_flexicast_queued_payload_t *data = queue_front(&flow->data_queue);
    size_t data_cost = pacing_cost(flow, data->size);
    if (data_cost < cost) {
      payload = data;
      cost = data_cost;
      use_repair = false;
    }
  }
  return (flexicast_queue_selection_t){
      .payload = payload, .cost = cost, .repair = use_repair};
}

static void account_data_airtime(transport_flexicast_flow_t *flow,
                                 size_t cost) {
  uint64_t maximum = fanout_cost(flow, flow->pacing_burst_bytes);
  if (maximum <= UINT64_MAX / 4U)
    maximum *= 4U;
  else
    maximum = UINT64_MAX;
  uint64_t current = flow->data_airtime_since_repair < maximum
                         ? flow->data_airtime_since_repair
                         : maximum;
  flow->data_airtime_since_repair =
      cost >= maximum - current ? maximum : current + cost;
}

static void
record_sent_repair(transport_flexicast_flow_t *flow,
                   const transport_flexicast_queued_payload_t *queued,
                   int64_t now_ms) {
  transport_flexicast_recent_repair_t *recent =
      &flow->recent_repairs[flow->next_recent_repair];
  *recent = (transport_flexicast_recent_repair_t){
      .active = true,
      .group_id = queued->group_id,
      .object_id = queued->object_id,
      .symbol_index = queued->symbol_index,
      .mode = queued->repair_mode,
      .expires_at_ms =
          now_ms <= INT64_MAX - TRANSPORT_FLEXICAST_REPAIR_REISSUE_MS
              ? now_ms + TRANSPORT_FLEXICAST_REPAIR_REISSUE_MS
              : INT64_MAX};
  flow->next_recent_repair =
      (flow->next_recent_repair + 1U) % TRANSPORT_FLEXICAST_RECENT_REPAIRS;
}

void tf_drain_paced_payloads(transport_t *t, transport_flexicast_flow_t *flow) {
  if (flow->data_queue.count == 0 && flow->repair_queue.count == 0)
    return;
  if (flow->rekey_pending)
    return;
  if (transport_flexicast_listening_members(flow) == 0) {
    bool awaiting_rekey_ready = false;
    for (size_t i = 0; i < flow->member_count; i++)
      awaiting_rekey_ready |= flow->members[i].conn && flow->members[i].joined;
    if (!awaiting_rekey_ready)
      t->stats.flexicast_pacing_dropped += tf_clear_flow_queue(flow);
    return;
  }
  refresh_pacer(t, flow, transport_get_time_ms());
  while (flow->data_queue.count != 0 || flow->repair_queue.count != 0) {
    flexicast_queue_selection_t selection = select_queued_payload(flow);
    transport_flexicast_queued_payload_t *queued = selection.payload;
    if (!queued || !queued->data)
      break;
    size_t cost = selection.cost;
    bool is_repair = selection.repair;
    if (cost > flow->pacing_tokens)
      break;
    uint64_t before = queued->airtime_bytes;
    flexicast_dispatch_result_t result = dispatch_payload(t, flow, queued);
    uint64_t physical = queued->airtime_bytes - before;
    t->stats.flexicast_physical_bytes_sent += physical;
    account_controller_airtime(flow, physical, is_repair);
    if (is_repair) {
      t->stats.repair_physical_bytes_sent += physical;
      if (physical != 0)
        flow->last_repair_sent_ms = transport_get_time_ms();
    } else {
      account_data_airtime(flow, physical);
    }
    if (result == FLEXICAST_DISPATCH_BLOCKED)
      break;
    if (result == FLEXICAST_DISPATCH_OK && is_repair) {
      record_sent_repair(flow, queued, transport_get_time_ms());
      flow->repair_priority_available = false;
      flow->data_airtime_since_repair = 0;
    } else if (result == FLEXICAST_DISPATCH_FAILED) {
      t->stats.flexicast_pacing_dropped++;
    }
    queue_pop(is_repair ? &flow->repair_queue : &flow->data_queue);
    if (result != FLEXICAST_DISPATCH_OK)
      break;
  }
}

bool transport_flexicast_track_ready(transport_t *t,
                                     const moq_track_id_t *track) {
  if (!t || !track)
    return false;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (!flow->active || !flow->source ||
        !transport_track_id_equal(&flow->track_id, track) ||
        transport_flexicast_listening_members(flow) == 0)
      continue;
    refresh_pacer(t, flow, transport_get_time_ms());
    if (flow->data_queue.count >=
            TRANSPORT_FLEXICAST_QUEUE_CAPACITY * 3U / 4U ||
        flow->data_queue.bytes + flow->repair_queue.bytes >=
            t->limits.max_egress_bytes_per_socket * 3U / 4U ||
        (flow->data_queue.count != 0 &&
         flow->pacing_tokens < t->limits.max_udp_payload_size))
      return false;
  }
  return true;
}

int64_t transport_flexicast_get_first_timeout(transport_t *t) {
  if (!t || !t->flexicast_enabled)
    return INT64_MAX;
  int64_t now = transport_get_time_ms();
  int64_t first_timeout = INT64_MAX;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (!flow->active || flow->source || !flow->crypto)
      continue;
    int64_t deadline = quicly_flexicast_get_ack_deadline(flow->crypto);
    if (deadline < first_timeout)
      first_timeout = deadline;
  }
  if (!t->is_server)
    return first_timeout;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (!flow->active || !flow->source || !flow->crypto)
      continue;
    if (flow->rekey_pending) {
      if (flow->rekey_ready_at_ms < first_timeout)
        first_timeout = flow->rekey_ready_at_ms;
      continue;
    }
    for (size_t member_index = 0; member_index < flow->member_count;
         member_index++) {
      const transport_flexicast_member_t *member = &flow->members[member_index];
      if (member->joined && !member->listening &&
          member->ready_deadline_ms > 0 &&
          member->ready_deadline_ms < first_timeout)
        first_timeout = member->ready_deadline_ms;
    }
    if (flow->feedback_outstanding_count != 0) {
      quicly_flexicast_cc_output_t output;
      quicly_flexicast_cc_get_flow_output(flow->crypto, &output);
      if (output.next_timeout < first_timeout)
        first_timeout = output.next_timeout;
    }
    for (size_t pending_index = 0;
         pending_index < TRANSPORT_FLEXICAST_PENDING_REPAIRS; pending_index++) {
      const transport_flexicast_pending_repair_t *pending =
          &flow->pending_repairs[pending_index];
      if (pending->active && pending->ready_at_ms < first_timeout)
        first_timeout = pending->ready_at_ms;
    }
    for (size_t observation_index = 0;
         observation_index < TRANSPORT_FLEXICAST_SHADOW_OBSERVATIONS;
         observation_index++) {
      const transport_flexicast_shadow_observation_t *observation =
          &flow->shadow_observations[observation_index];
      if (observation->active && observation->ready_at_ms < first_timeout)
        first_timeout = observation->ready_at_ms;
    }
    if ((flow->data_queue.count == 0 && flow->repair_queue.count == 0) ||
        transport_flexicast_listening_members(flow) == 0)
      continue;
    refresh_pacer(t, flow, now);
    flexicast_queue_selection_t selection = select_queued_payload(flow);
    if (!selection.payload)
      continue;
    size_t cost = selection.cost;
    if (cost <= flow->pacing_tokens) {
      int64_t deadline =
          flow->dispatch_retry_at_ms > now ? flow->dispatch_retry_at_ms : now;
      if (deadline < first_timeout)
        first_timeout = deadline;
      continue;
    }
    if (flow->pacing_rate_bytes_per_second == 0)
      continue;
    uint64_t deficit = cost - flow->pacing_tokens;
    uint64_t delay =
        (deficit * 1000U + flow->pacing_rate_bytes_per_second - 1U) /
        flow->pacing_rate_bytes_per_second;
    if (delay == 0)
      delay = 1;
    int64_t timeout =
        delay > (uint64_t)(INT64_MAX - now) ? INT64_MAX : now + (int64_t)delay;
    if (timeout < first_timeout)
      first_timeout = timeout;
  }
  return first_timeout;
}
