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

static bool repair_queue_can_accept(const transport_t *t,
                                    const transport_flexicast_flow_t *flow,
                                    size_t packets, size_t bytes) {
  if (!t || !flow || packets > TRANSPORT_FLEXICAST_REPAIR_QUEUE_CAPACITY ||
      flow->repair_queue.count > TRANSPORT_FLEXICAST_REPAIR_QUEUE_CAPACITY ||
      packets > TRANSPORT_FLEXICAST_REPAIR_QUEUE_CAPACITY -
                    flow->repair_queue.count ||
      bytes > t->limits.max_egress_bytes_per_socket ||
      flow->data_queue.bytes > t->limits.max_egress_bytes_per_socket ||
      flow->repair_queue.bytes > t->limits.max_egress_bytes_per_socket ||
      flow->data_queue.bytes >
          t->limits.max_egress_bytes_per_socket - flow->repair_queue.bytes ||
      bytes > t->limits.max_egress_bytes_per_socket - flow->data_queue.bytes -
                  flow->repair_queue.bytes)
    return false;
  return true;
}

static bool queue_repair_payload(transport_t *t,
                                 transport_flexicast_flow_t *flow,
                                 ptls_iovec_t payload, uint64_t group_id,
                                 uint64_t object_id, uint16_t symbol_index,
                                 transport_repair_mode_t mode, int64_t now) {
  if (payload.len > SIZE_MAX - 128U ||
      !repair_queue_can_accept(t, flow, 1, payload.len))
    return false;
  uint8_t *copy = malloc(payload.len);
  if (!copy)
    return false;
  memcpy(copy, payload.base, payload.len);
  bool was_empty = flow->repair_queue.count == 0;
  transport_flexicast_queued_payload_t queued = {.data = copy,
                                                 .size = payload.len,
                                                 .enqueued_at_ms = now,
                                                 .group_id = group_id,
                                                 .object_id = object_id,
                                                 .symbol_index = symbol_index,
                                                 .repair_mode = mode};
  if (!tf_queue_push(&flow->repair_queue, &queued)) {
    free(copy);
    return false;
  }
  if (was_empty && (flow->last_repair_sent_ms == 0 ||
                    now - flow->last_repair_sent_ms >=
                        TRANSPORT_FLEXICAST_REPAIR_PRIORITY_IDLE_MS))
    flow->repair_priority_available = true;
  t->stats.flexicast_payloads_accepted++;
  t->stats.flexicast_plaintext_bytes_accepted += payload.len;
  t->stats.flexicast_pacing_delays++;
  return true;
}

static transport_flexicast_pending_repair_t *
find_pending_repair(transport_flexicast_flow_t *flow, uint64_t group_id,
                    uint64_t object_id, transport_repair_mode_t mode) {
  for (size_t i = 0; i < TRANSPORT_FLEXICAST_PENDING_REPAIRS; i++) {
    transport_flexicast_pending_repair_t *pending = &flow->pending_repairs[i];
    if (pending->active && pending->group_id == group_id &&
        pending->object_id == object_id && pending->mode == mode)
      return pending;
  }
  return NULL;
}

static transport_flexicast_repair_requester_t *
requester_store_find(transport_flexicast_requester_store_t *store,
                     uint64_t request_id, uint64_t member_id) {
  for (size_t i = 0; i < store->count; i++) {
    transport_flexicast_repair_requester_t *requester = &store->entries[i];
    if (requester->request_id == request_id &&
        requester->member_id == member_id)
      return requester;
  }
  return NULL;
}

static transport_flexicast_repair_requester_t *
requester_store_append(transport_flexicast_requester_store_t *store) {
  if (store->count < store->capacity)
    return &store->entries[store->count++];
  if (store->capacity >= TRANSPORT_FLEXICAST_REPAIR_REQUESTERS)
    return NULL;
  size_t capacity = store->capacity == 0 ? 16U : store->capacity * 2U;
  if (capacity > TRANSPORT_FLEXICAST_REPAIR_REQUESTERS)
    capacity = TRANSPORT_FLEXICAST_REPAIR_REQUESTERS;
  if (capacity > SIZE_MAX / sizeof(*store->entries))
    return NULL;
  transport_flexicast_repair_requester_t *requesters =
      realloc(store->entries, capacity * sizeof(*requesters));
  if (!requesters)
    return NULL;
  store->entries = requesters;
  store->capacity = capacity;
  return &store->entries[store->count++];
}

static void get_requester_delivery_stats(const transport_flexicast_flow_t *flow,
                                         uint64_t member_id,
                                         uint64_t *delivery_rate,
                                         int64_t *last_feedback) {
  *delivery_rate = 0;
  *last_feedback = 0;
  if (!flow->crypto)
    return;
  quicly_flexicast_member_stats_t stats;
  if (quicly_flexicast_get_member_stats(flow->crypto, member_id, &stats) ==
      QUICLY_FLEXICAST_OK) {
    *delivery_rate = stats.delivery_rate_bytes_per_second;
    *last_feedback = stats.last_feedback_at;
  }
}

static void
record_requested_symbols(transport_flexicast_repair_requester_t *requester,
                         transport_repair_mode_t mode, bool whole_object,
                         size_t deficit, const uint16_t *missing,
                         size_t missing_count) {
  if (!requester || mode != TRANSPORT_REPAIR_MODE_INDEXED)
    return;
  if (whole_object) {
    if (deficit > QLINQ_WIRE_MAX_NACK_SYMBOLS)
      deficit = QLINQ_WIRE_MAX_NACK_SYMBOLS;
    for (size_t i = 0; i < deficit; i++)
      requester->requested_symbols[i / 64U] |= UINT64_C(1) << (i % 64U);
  } else {
    for (size_t i = 0; missing && i < missing_count; i++)
      if (missing[i] < QLINQ_WIRE_MAX_NACK_SYMBOLS)
        requester->requested_symbols[missing[i] / 64U] |= UINT64_C(1)
                                                          << (missing[i] % 64U);
  }
}

static size_t
requester_store_remove(transport_flexicast_requester_store_t *store,
                       uint64_t request_id) {
  size_t removed = 0;
  for (size_t i = 0; i < store->count;) {
    if (store->entries[i].request_id != request_id) {
      i++;
      continue;
    }
    store->entries[i] = store->entries[--store->count];
    removed++;
  }
  if (store->count == 0) {
    free(store->entries);
    memset(store, 0, sizeof(*store));
  }
  return removed;
}

static void observe_repair_requester(
    transport_t *t, transport_flexicast_flow_t *flow,
    transport_flexicast_pending_repair_t *pending, uint64_t member_id,
    size_t deficit, transport_repair_mode_t mode, bool whole_object,
    const uint16_t *missing, size_t missing_count, int64_t now_ms) {
  if (deficit == 0)
    return;
  if (deficit > UINT16_MAX)
    deficit = UINT16_MAX;

  uint64_t delivery_rate;
  int64_t last_feedback;
  get_requester_delivery_stats(flow, member_id, &delivery_rate, &last_feedback);
  uint64_t feedback_age = last_feedback > 0 && now_ms > last_feedback
                              ? (uint64_t)(now_ms - last_feedback)
                              : 0;

  transport_flexicast_repair_requester_t *requester = requester_store_find(
      &flow->repair_requesters, pending->intent_id, member_id);
  if (requester) {
    if (pending->retained_deficit_sum >= requester->deficit)
      pending->retained_deficit_sum -= requester->deficit;
    if (deficit < requester->deficit && !requester->shared_repair_useful) {
      requester->shared_repair_useful = true;
      pending->shared_useful_requesters++;
    }
    requester->deficit = (uint16_t)deficit;
    requester->delivery_rate_bytes_per_second = delivery_rate;
    requester->last_feedback_ms = last_feedback;
    requester->last_request_ms = now_ms;
    memset(requester->requested_symbols, 0,
           sizeof(requester->requested_symbols));
    pending->retained_deficit_sum =
        tf_saturating_add_u64(pending->retained_deficit_sum, (uint64_t)deficit);
    t->stats.repair_requester_updates++;
  } else if (!(requester = requester_store_append(&flow->repair_requesters))) {
    pending->overflow_requests++;
    pending->overflow_deficit_sum =
        tf_saturating_add_u64(pending->overflow_deficit_sum, (uint64_t)deficit);
    t->stats.repair_requester_overflow++;
  } else {
    *requester = (transport_flexicast_repair_requester_t){
        .request_id = pending->intent_id,
        .member_id = member_id,
        .deficit = (uint16_t)deficit,
        .delivery_rate_bytes_per_second = delivery_rate,
        .first_request_ms = now_ms,
        .last_request_ms = now_ms,
        .last_feedback_ms = last_feedback,
        .shared_repair_useful = true};
    pending->retained_requesters++;
    pending->shared_useful_requesters++;
    pending->retained_deficit_sum =
        tf_saturating_add_u64(pending->retained_deficit_sum, (uint64_t)deficit);
    if (flow->repair_requesters.count > t->stats.repair_requester_records_peak)
      t->stats.repair_requester_records_peak = flow->repair_requesters.count;
  }
  if (deficit > pending->maximum_requester_deficit)
    pending->maximum_requester_deficit = (uint16_t)deficit;
  if (feedback_age > pending->oldest_feedback_age_ms)
    pending->oldest_feedback_age_ms = feedback_age;
  if (delivery_rate != 0 &&
      (pending->minimum_delivery_rate_bytes_per_second == 0 ||
       delivery_rate < pending->minimum_delivery_rate_bytes_per_second))
    pending->minimum_delivery_rate_bytes_per_second = delivery_rate;

  record_requested_symbols(requester, mode, whole_object, deficit, missing,
                           missing_count);
}

static void expire_repair_requesters(transport_t *t,
                                     transport_flexicast_flow_t *flow,
                                     uint64_t intent_id) {
  size_t expired = requester_store_remove(&flow->repair_requesters, intent_id);
  t->stats.repair_requester_records_expired =
      tf_saturating_add_u64(t->stats.repair_requester_records_expired, expired);
}

static transport_flexicast_shadow_observation_t *
find_shadow_observation(transport_flexicast_flow_t *flow, uint64_t group_id,
                        uint64_t object_id, transport_repair_mode_t mode) {
  for (size_t i = 0; i < TRANSPORT_FLEXICAST_SHADOW_OBSERVATIONS; i++) {
    transport_flexicast_shadow_observation_t *observation =
        &flow->shadow_observations[i];
    if (observation->active && observation->group_id == group_id &&
        observation->object_id == object_id && observation->mode == mode)
      return observation;
  }
  return NULL;
}

static void clear_shadow_observation(
    transport_flexicast_flow_t *flow,
    transport_flexicast_shadow_observation_t *observation) {
  if (!flow || !observation || !observation->active)
    return;
  uint64_t observation_id = observation->observation_id;
  (void)requester_store_remove(&flow->shadow_requesters, observation_id);
  memset(observation, 0, sizeof(*observation));
  if (flow->shadow_observation_count != 0)
    flow->shadow_observation_count--;
}

void transport_flexicast_observe_repair_request(
    transport_t *t, transport_flexicast_flow_t *flow,
    const sent_object_cache_t *object, uint64_t requester_id,
    transport_repair_mode_t mode, bool whole_object, const uint16_t *missing,
    size_t missing_count,
    transport_flexicast_observation_disposition_t disposition, int64_t now_ms) {
  if (!t || !t->repair_shadow_log || !flow || !object || requester_id == 0 ||
      (mode != TRANSPORT_REPAIR_MODE_INDEXED &&
       mode != TRANSPORT_REPAIR_MODE_RATELESS))
    return;
  size_t deficit = whole_object ? object->data_symbols : missing_count;
  if (deficit == 0)
    return;
  if (deficit > UINT16_MAX)
    deficit = UINT16_MAX;

  transport_flexicast_shadow_observation_t *observation =
      find_shadow_observation(flow, object->group_id, object->object_id, mode);
  if (!observation) {
    for (size_t i = 0; i < TRANSPORT_FLEXICAST_SHADOW_OBSERVATIONS; i++) {
      if (!flow->shadow_observations[i].active) {
        observation = &flow->shadow_observations[i];
        break;
      }
    }
    if (!observation) {
      t->stats.repair_shadow_observation_overflow++;
      return;
    }
    if (++flow->next_shadow_observation_id == 0)
      flow->next_shadow_observation_id = 1;
    *observation = (transport_flexicast_shadow_observation_t){
        .active = true,
        .observation_id = flow->next_shadow_observation_id,
        .group_id = object->group_id,
        .object_id = object->object_id,
        .mode = mode,
        .first_request_ms = now_ms,
        .ready_at_ms = now_ms + TRANSPORT_FLEXICAST_SHADOW_OBSERVATION_MS,
        .cohort_member_count = transport_flexicast_listening_members(flow)};
    flow->shadow_observation_count++;
  }
  size_t cohort_members = transport_flexicast_listening_members(flow);
  if (cohort_members > observation->cohort_member_count)
    observation->cohort_member_count = cohort_members;
  switch (disposition) {
  case TRANSPORT_FLEXICAST_OBS_ACCEPTED:
    observation->accepted_requests++;
    break;
  case TRANSPORT_FLEXICAST_OBS_SUPPRESSED:
    observation->suppressed_requests++;
    break;
  case TRANSPORT_FLEXICAST_OBS_THROTTLED:
    observation->throttled_requests++;
    break;
  }

  transport_flexicast_repair_requester_t *requester = requester_store_find(
      &flow->shadow_requesters, observation->observation_id, requester_id);
  if (!requester) {
    requester = requester_store_append(&flow->shadow_requesters);
    if (!requester) {
      observation->overflow_requests++;
      t->stats.repair_shadow_observation_overflow++;
      return;
    }
    *requester = (transport_flexicast_repair_requester_t){
        .request_id = observation->observation_id,
        .member_id = requester_id,
        .deficit = (uint16_t)deficit,
        .first_request_ms = now_ms,
        .last_request_ms = now_ms};
  } else {
    if (deficit > requester->deficit)
      requester->deficit = (uint16_t)deficit;
    requester->last_request_ms = now_ms;
  }

  get_requester_delivery_stats(flow, requester_id,
                               &requester->delivery_rate_bytes_per_second,
                               &requester->last_feedback_ms);
  record_requested_symbols(requester, mode, whole_object, deficit, missing,
                           missing_count);
}

static bool repair_symbol_is_covered(const transport_flexicast_flow_t *flow,
                                     uint64_t group_id, uint64_t object_id,
                                     uint16_t symbol_index, int64_t now_ms) {
  for (size_t i = 0; i < flow->repair_queue.count; i++) {
    const transport_flexicast_queued_payload_t *queued =
        tf_queue_at_const(&flow->repair_queue, i);
    if (queued->group_id == group_id && queued->object_id == object_id &&
        queued->symbol_index == symbol_index)
      return true;
  }
  for (size_t i = 0; i < TRANSPORT_FLEXICAST_RECENT_REPAIRS; i++) {
    const transport_flexicast_recent_repair_t *recent =
        &flow->recent_repairs[i];
    if (recent->active && recent->expires_at_ms > now_ms &&
        recent->group_id == group_id && recent->object_id == object_id &&
        recent->symbol_index == symbol_index)
      return true;
  }
  return false;
}

size_t tf_repair_symbol_count(const uint64_t *symbols) {
  size_t count = 0;
  for (size_t i = 0; i < QLINQ_WIRE_MAX_NACK_SYMBOLS / 64U; i++) {
    uint64_t word = symbols[i];
    while (word != 0) {
      word &= word - 1U;
      count++;
    }
  }
  return count;
}

static size_t
rateless_repair_count_covered(const transport_flexicast_flow_t *flow,
                              uint64_t group_id, uint64_t object_id,
                              int64_t now_ms) {
  size_t count = 0;
  for (size_t i = 0; i < flow->repair_queue.count; i++) {
    const transport_flexicast_queued_payload_t *queued =
        tf_queue_at_const(&flow->repair_queue, i);
    if (queued->group_id == group_id && queued->object_id == object_id &&
        queued->repair_mode == TRANSPORT_REPAIR_MODE_RATELESS)
      count++;
  }
  for (size_t i = 0; i < TRANSPORT_FLEXICAST_RECENT_REPAIRS; i++) {
    const transport_flexicast_recent_repair_t *recent =
        &flow->recent_repairs[i];
    if (recent->active && recent->expires_at_ms > now_ms &&
        recent->group_id == group_id && recent->object_id == object_id &&
        recent->mode == TRANSPORT_REPAIR_MODE_RATELESS)
      count++;
  }
  return count;
}

static transport_conn_t *find_connection_by_id(transport_t *t,
                                               uint64_t member_id) {
  if (!t || member_id > UINT32_MAX)
    return NULL;
  size_t count = t->is_server ? t->conn_count : (t->client_conn ? 1U : 0U);
  for (size_t i = 0; i < count; i++) {
    transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
    if (conn && conn->id == (uint32_t)member_id)
      return conn;
  }
  return NULL;
}

static uint32_t shared_delivery_ppm(const transport_flexicast_flow_t *flow,
                                    uint64_t delivery_rate) {
  if (!flow || flow->pacing_rate_bytes_per_second == 0 || delivery_rate == 0)
    return 0;
  __extension__ typedef unsigned __int128 wide_t;
  wide_t scaled = (wide_t)delivery_rate * 1000000U;
  scaled /= flow->pacing_rate_bytes_per_second;
  return scaled >= 1000000U ? 1000000U : (uint32_t)scaled;
}

static bool build_shadow_observation_snapshot(
    transport_t *t, transport_flexicast_flow_t *flow,
    const transport_flexicast_shadow_observation_t *observation,
    const sent_object_cache_t *object, int64_t now,
    transport_repair_planner_snapshot_t *snapshot,
    transport_repair_planner_requester_t **allocated) {
  if (!t || !flow || !observation || !object || !snapshot || !allocated)
    return false;
  size_t count = 0;
  for (size_t i = 0; i < flow->shadow_requesters.count; i++)
    if (flow->shadow_requesters.entries[i].request_id ==
        observation->observation_id)
      count++;
  if (count == 0)
    return false;
  transport_repair_planner_requester_t *requesters =
      calloc(count, sizeof(*requesters));
  if (!requesters)
    return false;

  size_t output = 0;
  size_t cohort_members = observation->cohort_member_count;
  size_t current_members = transport_flexicast_listening_members(flow);
  if (current_members > cohort_members)
    cohort_members = current_members;
  bool incomplete = observation->overflow_requests != 0 ||
                    observation->throttled_requests != 0;
  for (size_t i = 0; i < flow->shadow_requesters.count; i++) {
    const transport_flexicast_repair_requester_t *source =
        &flow->shadow_requesters.entries[i];
    if (source->request_id != observation->observation_id)
      continue;
    transport_repair_planner_requester_t *requester = &requesters[output++];
    requester->member_id = source->member_id;
    requester->deficit = source->deficit;
    requester->feedback_age_ms =
        source->last_feedback_ms > 0 && now > source->last_feedback_ms
            ? (uint64_t)(now - source->last_feedback_ms)
            : 0;
    requester->shared_delivery_probability_ppm =
        shared_delivery_ppm(flow, source->delivery_rate_bytes_per_second);
    memcpy(requester->requested_symbols, source->requested_symbols,
           sizeof(requester->requested_symbols));

    transport_conn_t *conn = find_connection_by_id(t, source->member_id);
    if (!conn) {
      incomplete = true;
      continue;
    }
    requester->path_count = t->num_fds;
    for (size_t path = 0; path < requester->path_count; path++) {
      const path_state_t *state = &conn->path_states[path];
      transport_repair_planner_path_t *entry = &requester->paths[path];
      entry->resource_id = t->local_ifindices[path];
      entry->measurement_known = state->initialized && state->b_ewma > 0;
      entry->estimate.b = state->b_ewma > 0 ? state->b_ewma : FP_FROM_INT(100);
      entry->estimate.l = state->l_ewma;
      entry->estimate.p = state->p_ewma;
      entry->estimate.q = state->q_ewma;
    }
  }

  *snapshot = (transport_repair_planner_snapshot_t){
      .version = TRANSPORT_REPAIR_PLANNER_VERSION,
      .intent_id = observation->observation_id,
      .group_id = observation->group_id,
      .object_id = observation->object_id,
      .mode = observation->mode,
      .symbol_size = object->symbol_size,
      .packet_overhead = QLINQ_WIRE_FEC_HEADER_SIZE + 128U,
      .deadline_ms = t->repair_shadow_deadline_ms,
      .shared_rate_bytes_per_second = flow->pacing_rate_bytes_per_second,
      .shared_resource_id = flow->interface_index,
      .shared_physical_copies = flow->native_multicast ? 1U : cohort_members,
      .cohort_member_count = cohort_members,
      .observation_window_ms = TRANSPORT_FLEXICAST_SHADOW_OBSERVATION_MS,
      .observation_age_ms =
          now > observation->first_request_ms
              ? (uint64_t)(now - observation->first_request_ms)
              : 0,
      .accepted_request_count = observation->accepted_requests,
      .suppressed_request_count = observation->suppressed_requests,
      .throttled_request_count = observation->throttled_requests,
      .observation_overflow_count = observation->overflow_requests,
      .incomplete_requester_state = incomplete,
      .requesters = requesters,
      .requester_count = count};
  *allocated = requesters;
  return true;
}

void tf_emit_ready_shadow_observations(transport_t *t,
                                       transport_flexicast_flow_t *flow,
                                       int64_t now) {
  if (!t || !flow || !t->repair_shadow_log)
    return;
  for (size_t index = 0; index < TRANSPORT_FLEXICAST_SHADOW_OBSERVATIONS;
       index++) {
    transport_flexicast_shadow_observation_t *observation =
        &flow->shadow_observations[index];
    if (!observation->active || now < observation->ready_at_ms)
      continue;
    sent_object_cache_t *object = transport_sent_cache_find(
        &t->sent_cache, &flow->track_id, observation->group_id,
        observation->object_id);
    if (!object) {
      clear_shadow_observation(flow, observation);
      continue;
    }
    transport_repair_planner_snapshot_t snapshot;
    transport_repair_planner_requester_t *requesters = NULL;
    transport_repair_planner_evaluation_t evaluation;
    if (!build_shadow_observation_snapshot(t, flow, observation, object, now,
                                           &snapshot, &requesters) ||
        !transport_repair_planner_evaluate(&snapshot, &evaluation)) {
      t->stats.repair_shadow_log_errors++;
      free(requesters);
      clear_shadow_observation(flow, observation);
      continue;
    }
    t->stats.repair_shadow_plans_evaluated++;
    switch (evaluation.chosen.action) {
    case TRANSPORT_REPAIR_PLAN_ALL_SHARED:
      t->stats.repair_shadow_all_shared++;
      break;
    case TRANSPORT_REPAIR_PLAN_ALL_UNICAST:
      t->stats.repair_shadow_all_unicast++;
      break;
    case TRANSPORT_REPAIR_PLAN_MIXED:
      t->stats.repair_shadow_mixed++;
      break;
    }
    if (evaluation.chosen.uncertain || evaluation.chosen.approximate)
      t->stats.repair_shadow_uncertain++;
    if (!evaluation.chosen.feasible)
      t->stats.repair_shadow_infeasible++;
    t->stats.repair_shadow_last_airtime_us =
        evaluation.chosen.aggregate_airtime_us;
    t->stats.repair_shadow_last_physical_bytes =
        evaluation.chosen.physical_bytes;
    t->stats.repair_shadow_last_savings_ppm =
        evaluation.chosen_savings_vs_shared_ppm;
    if (t->repair_shadow_log &&
        (!transport_repair_planner_record_write(t->repair_shadow_log, &snapshot,
                                                &evaluation) ||
         fflush(t->repair_shadow_log) != 0))
      t->stats.repair_shadow_log_errors++;
    free(requesters);
    clear_shadow_observation(flow, observation);
  }
}

static void clear_pending_repair(transport_t *t,
                                 transport_flexicast_flow_t *flow,
                                 transport_flexicast_pending_repair_t *pending);

bool transport_flexicast_schedule_repair(
    transport_t *t, transport_flexicast_flow_t *flow,
    const sent_object_cache_t *object, uint64_t requester_id,
    transport_repair_mode_t mode, bool whole_object, const uint16_t *missing,
    size_t missing_count, int64_t now_ms) {
  if (!t || !flow || !flow->source || !object ||
      !transport_track_id_equal(&flow->track_id, &object->track_id) ||
      (mode != TRANSPORT_REPAIR_MODE_INDEXED &&
       mode != TRANSPORT_REPAIR_MODE_RATELESS) ||
      (mode == TRANSPORT_REPAIR_MODE_INDEXED && !whole_object &&
       (!missing || missing_count == 0)) ||
      (mode == TRANSPORT_REPAIR_MODE_RATELESS && !whole_object &&
       missing_count == 0))
    return false;
  if (mode == TRANSPORT_REPAIR_MODE_INDEXED && !whole_object)
    for (size_t i = 0; i < missing_count; i++)
      if (missing[i] >= QLINQ_WIRE_MAX_NACK_SYMBOLS)
        return false;

  size_t requester_deficit =
      whole_object ? object->data_symbols : missing_count;
  if (requester_deficit > TRANSPORT_REPAIR_MAX_SYMBOLS)
    requester_deficit = TRANSPORT_REPAIR_MAX_SYMBOLS;
  transport_flexicast_pending_repair_t *pending =
      find_pending_repair(flow, object->group_id, object->object_id, mode);
  bool merging = pending != NULL;
  if (mode == TRANSPORT_REPAIR_MODE_RATELESS) {
    size_t covered =
        t->flexicast_repair_route == TRANSPORT_FLEXICAST_REPAIR_SHARED
            ? rateless_repair_count_covered(flow, object->group_id,
                                            object->object_id, now_ms)
            : 0;
    if (requester_deficit <= covered) {
      t->stats.repair_requests_merged++;
      return true;
    }
    missing_count = requester_deficit - covered;
  }
  if (!pending) {
    bool fully_queued =
        t->flexicast_repair_route == TRANSPORT_FLEXICAST_REPAIR_SHARED;
    if (mode == TRANSPORT_REPAIR_MODE_RATELESS) {
      fully_queued = false;
    } else if (whole_object) {
      size_t count = object->data_symbols;
      if (count > TRANSPORT_REPAIR_MAX_SYMBOLS)
        count = TRANSPORT_REPAIR_MAX_SYMBOLS;
      for (size_t i = 0; i < count; i++)
        fully_queued &= repair_symbol_is_covered(
            flow, object->group_id, object->object_id, (uint16_t)i, now_ms);
    } else {
      for (size_t i = 0; i < missing_count; i++)
        fully_queued &= repair_symbol_is_covered(
            flow, object->group_id, object->object_id, missing[i], now_ms);
    }
    if (fully_queued) {
      t->stats.repair_requests_merged++;
      return true;
    }
  }
  if (!pending) {
    for (size_t i = 0; i < TRANSPORT_FLEXICAST_PENDING_REPAIRS; i++) {
      if (!flow->pending_repairs[i].active) {
        pending = &flow->pending_repairs[i];
        break;
      }
    }
    if (!pending) {
      t->stats.repair_queue_backpressure++;
      return false;
    }
    memset(pending, 0, sizeof(*pending));
    pending->active = true;
    if (++flow->next_repair_intent_id == 0)
      flow->next_repair_intent_id = 1;
    pending->intent_id = flow->next_repair_intent_id;
    pending->group_id = object->group_id;
    pending->object_id = object->object_id;
    pending->mode = mode;
    pending->first_request_ms = now_ms;
    pending->ready_at_ms = now_ms + TRANSPORT_FLEXICAST_REPAIR_HOLDOFF_MS;
    flow->pending_repair_count++;
  }

  size_t before = tf_pending_repair_symbol_count(pending);
  if (mode == TRANSPORT_REPAIR_MODE_RATELESS) {
    if (missing_count > pending->requested_dof)
      pending->requested_dof = (uint16_t)missing_count;
  } else if (whole_object) {
    size_t count = object->data_symbols;
    if (count > TRANSPORT_REPAIR_MAX_SYMBOLS)
      count = TRANSPORT_REPAIR_MAX_SYMBOLS;
    for (size_t i = 0; i < count; i++)
      if (!repair_symbol_is_covered(flow, object->group_id, object->object_id,
                                    (uint16_t)i, now_ms))
        pending->requested_symbols[i / 64U] |= UINT64_C(1) << (i % 64U);
  } else {
    for (size_t i = 0; i < missing_count; i++) {
      if (!repair_symbol_is_covered(flow, object->group_id, object->object_id,
                                    missing[i], now_ms))
        pending->requested_symbols[missing[i] / 64U] |= UINT64_C(1)
                                                        << (missing[i] % 64U);
    }
  }
  size_t after = tf_pending_repair_symbol_count(pending);
  if (merging || after == before)
    t->stats.repair_requests_merged++;
  observe_repair_requester(t, flow, pending, requester_id, requester_deficit,
                           mode, whole_object, missing, missing_count, now_ms);
  if (after == 0)
    clear_pending_repair(t, flow, pending);
  return true;
}

static void
clear_pending_repair(transport_t *t, transport_flexicast_flow_t *flow,
                     transport_flexicast_pending_repair_t *pending) {
  if (!pending->active)
    return;
  expire_repair_requesters(t, flow, pending->intent_id);
  memset(pending, 0, sizeof(*pending));
  if (flow->pending_repair_count != 0)
    flow->pending_repair_count--;
}

size_t tf_cancel_flow_repairs(transport_t *t, transport_flexicast_flow_t *flow,
                              bool entire_track, uint64_t group_id,
                              uint64_t object_id) {
  size_t pending_symbols = 0;
  for (size_t i = 0; i < TRANSPORT_FLEXICAST_PENDING_REPAIRS; i++) {
    transport_flexicast_pending_repair_t *pending = &flow->pending_repairs[i];
    if (!pending->active || (!entire_track && (pending->group_id != group_id ||
                                               pending->object_id > object_id)))
      continue;
    pending_symbols += tf_pending_repair_symbol_count(pending);
    clear_pending_repair(t, flow, pending);
  }
  for (size_t i = 0; i < TRANSPORT_FLEXICAST_RECENT_REPAIRS; i++) {
    transport_flexicast_recent_repair_t *recent = &flow->recent_repairs[i];
    if (recent->active && (entire_track || (recent->group_id == group_id &&
                                            recent->object_id <= object_id)))
      memset(recent, 0, sizeof(*recent));
  }
  for (size_t i = 0; i < TRANSPORT_FLEXICAST_SHADOW_OBSERVATIONS; i++) {
    transport_flexicast_shadow_observation_t *observation =
        &flow->shadow_observations[i];
    if (observation->active &&
        (entire_track || (observation->group_id == group_id &&
                          observation->object_id <= object_id)))
      clear_shadow_observation(flow, observation);
  }

  transport_flexicast_queued_payload_t
      retained[TRANSPORT_FLEXICAST_REPAIR_QUEUE_CAPACITY] = {0};
  size_t retained_count = 0;
  size_t retained_bytes = 0;
  size_t cancelled = 0;
  for (size_t i = 0; i < flow->repair_queue.count; i++) {
    transport_flexicast_queued_payload_t *queued =
        tf_queue_at(&flow->repair_queue, i);
    if (entire_track ||
        (queued->group_id == group_id && queued->object_id <= object_id)) {
      free(queued->data);
      free(queued->packet);
      cancelled++;
    } else {
      retained[retained_count++] = *queued;
      retained_bytes += queued->size;
    }
    memset(queued, 0, sizeof(*queued));
  }
  if (retained_count != 0)
    memcpy(flow->repair_queue.entries, retained,
           retained_count * sizeof(*retained));
  flow->repair_queue.head = 0;
  flow->repair_queue.count = retained_count;
  flow->repair_queue.bytes = retained_bytes;
  if (retained_count == 0) {
    flow->repair_priority_available = false;
    flow->data_airtime_since_repair = 0;
  }
  t->stats.repair_packets_cancelled += cancelled;
  t->stats.repair_pending_symbols_cancelled += pending_symbols;
  return cancelled + pending_symbols;
}

size_t transport_flexicast_cancel_repairs_through(transport_t *t,
                                                  const moq_track_id_t *track,
                                                  uint64_t group_id,
                                                  uint64_t object_id) {
  if (!t || !track)
    return 0;
  size_t cancelled = 0;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (flow->active && flow->source &&
        transport_track_id_equal(&flow->track_id, track))
      cancelled += tf_cancel_flow_repairs(t, flow, false, group_id, object_id);
  }
  return cancelled;
}

size_t transport_flexicast_cancel_track_repairs(transport_t *t,
                                                const moq_track_id_t *track) {
  if (!t || !track)
    return 0;
  size_t cancelled = 0;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (flow->active && flow->source &&
        transport_track_id_equal(&flow->track_id, track))
      cancelled += tf_cancel_flow_repairs(t, flow, true, 0, 0);
  }
  return cancelled;
}

static bool requester_needs_repair_symbol(
    const transport_flexicast_repair_requester_t *requester,
    transport_repair_mode_t mode, uint16_t symbol_index,
    size_t rateless_ordinal) {
  if (mode == TRANSPORT_REPAIR_MODE_RATELESS)
    return rateless_ordinal < requester->deficit;
  return symbol_index < QLINQ_WIRE_MAX_NACK_SYMBOLS &&
         (requester->requested_symbols[symbol_index / 64U] &
          (UINT64_C(1) << (symbol_index % 64U))) != 0;
}

static bool
unicast_repair_can_accept(transport_t *t, transport_flexicast_flow_t *flow,
                          const transport_flexicast_pending_repair_t *pending,
                          const uint16_t *indices, size_t count) {
  size_t matched = 0;
  for (size_t r = 0; r < flow->repair_requesters.count; r++) {
    const transport_flexicast_repair_requester_t *requester =
        &flow->repair_requesters.entries[r];
    if (requester->request_id != pending->intent_id)
      continue;
    transport_conn_t *conn = find_connection_by_id(t, requester->member_id);
    if (!conn || !conn->quic)
      return false;
    size_t needed = 0;
    for (size_t i = 0; i < count; i++) {
      uint16_t symbol_index =
          pending->mode == TRANSPORT_REPAIR_MODE_RATELESS ? 0 : indices[i];
      if (requester_needs_repair_symbol(requester, pending->mode, symbol_index,
                                        i))
        needed++;
    }
    if (needed > QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY ||
        conn->queued_datagrams[0] > QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY - needed)
      return false;
    matched++;
  }
  return matched != 0;
}

static bool
queue_unicast_repair_symbol(transport_t *t, transport_flexicast_flow_t *flow,
                            const transport_flexicast_pending_repair_t *pending,
                            ptls_iovec_t packet, uint16_t symbol_index,
                            size_t rateless_ordinal, size_t *transmissions) {
  bool matched = false;
  for (size_t r = 0; r < flow->repair_requesters.count; r++) {
    const transport_flexicast_repair_requester_t *requester =
        &flow->repair_requesters.entries[r];
    if (requester->request_id != pending->intent_id ||
        !requester_needs_repair_symbol(requester, pending->mode, symbol_index,
                                       rateless_ordinal))
      continue;
    transport_conn_t *conn = find_connection_by_id(t, requester->member_id);
    if (!conn || !transport_queue_datagram(conn, 0, packet))
      return false;
    (*transmissions)++;
    matched = true;
  }
  return matched;
}

void tf_materialize_pending_repairs(transport_t *t,
                                    transport_flexicast_flow_t *flow,
                                    int64_t now) {
  for (size_t pending_index = 0;
       pending_index < TRANSPORT_FLEXICAST_PENDING_REPAIRS; pending_index++) {
    transport_flexicast_pending_repair_t *pending =
        &flow->pending_repairs[pending_index];
    if (!pending->active || now < pending->ready_at_ms)
      continue;
    sent_object_cache_t *object = transport_sent_cache_find(
        &t->sent_cache, &flow->track_id, pending->group_id, pending->object_id);
    if (!object) {
      clear_pending_repair(t, flow, pending);
      continue;
    }
    uint16_t indices[TRANSPORT_REPAIR_MAX_SYMBOLS];
    size_t count = 0;
    if (pending->mode == TRANSPORT_REPAIR_MODE_RATELESS) {
      count = pending->requested_dof;
    } else {
      for (size_t word_index = 0;
           word_index < QLINQ_WIRE_MAX_NACK_SYMBOLS / 64U &&
           count < TRANSPORT_REPAIR_MAX_SYMBOLS;
           word_index++) {
        uint64_t word = pending->requested_symbols[word_index];
        for (uint16_t bit = 0;
             bit < 64U && count < TRANSPORT_REPAIR_MAX_SYMBOLS; bit++)
          if ((word & (UINT64_C(1) << bit)) != 0)
            indices[count++] = (uint16_t)(word_index * 64U + bit);
      }
    }
    if (count == 0) {
      clear_pending_repair(t, flow, pending);
      continue;
    }
    size_t packet_size = QLINQ_WIRE_FEC_HEADER_SIZE + object->symbol_size;
    bool forced_unicast =
        t->flexicast_repair_route == TRANSPORT_FLEXICAST_REPAIR_UNICAST;
    bool capacity_available =
        forced_unicast
            ? unicast_repair_can_accept(t, flow, pending, indices, count)
            : repair_queue_can_accept(t, flow, count, packet_size * count);
    if (packet_size > SIZE_MAX / count || !capacity_available) {
      if (!pending->backpressure_reported) {
        t->stats.repair_queue_backpressure++;
        pending->backpressure_reported = true;
      }
      pending->ready_at_ms = now + 10;
      continue;
    }

    transport_repair_batch_t repair;
    bool systematic_fallback = false;
    bool built = pending->mode == TRANSPORT_REPAIR_MODE_RATELESS
                     ? transport_repair_build_rateless(&t->fec_cache, object,
                                                       count, &repair)
                     : transport_repair_build(&t->fec_cache, object, false,
                                              indices, count, &repair);
    if (!built && pending->mode == TRANSPORT_REPAIR_MODE_RATELESS &&
        object->next_repair_symbol >= QLINQ_FEC_MAX_TOTAL_SYMBOLS) {
      t->stats.repair_rateless_exhausted++;
      built = transport_repair_build_systematic_fallback(&t->fec_cache, object,
                                                         count, &repair);
      systematic_fallback = built;
    }
    if (!built) {
      clear_pending_repair(t, flow, pending);
      continue;
    }
    size_t queued = 0, unicast_transmissions = 0;
    for (size_t i = 0; i < repair.count; i++) {
      uint8_t packet[QLINQ_WIRE_FEC_HEADER_SIZE + QLINQ_FEC_MAX_SYMBOL_SIZE];
      size_t encoded_size = QLINQ_WIRE_FEC_HEADER_SIZE + repair.symbol_size;
      qlinq_wire_fec_header_t header = {.alias = flow->alias,
                                        .is_keyframe = object->is_keyframe,
                                        .priority = object->priority,
                                        .path_id = 0,
                                        .group_id = object->group_id,
                                        .object_id = object->object_id,
                                        .symbol_index = repair.indices[i],
                                        .total_symbols = repair.total_symbols,
                                        .data_symbols = object->data_symbols,
                                        .symbol_size = repair.symbol_size,
                                        .original_size = (uint32_t)object->size,
                                        .send_time_ns =
                                            transport_get_time_ns()};
      if (qlinq_wire_encode_fec_header(packet, sizeof(packet), &header) !=
              QLINQ_WIRE_OK ||
          encoded_size > sizeof(packet))
        break;
      memcpy(packet + QLINQ_WIRE_FEC_HEADER_SIZE,
             repair.symbols + i * repair.symbol_size, repair.symbol_size);
      bool sent =
          forced_unicast
              ? queue_unicast_repair_symbol(
                    t, flow, pending, ptls_iovec_init(packet, encoded_size),
                    repair.indices[i], i, &unicast_transmissions)
              : queue_repair_payload(t, flow,
                                     ptls_iovec_init(packet, encoded_size),
                                     object->group_id, object->object_id,
                                     repair.indices[i], pending->mode, now);
      if (!sent)
        break;
      if (pending->mode == TRANSPORT_REPAIR_MODE_RATELESS) {
        if (pending->requested_dof != 0)
          pending->requested_dof--;
      } else {
        pending->requested_symbols[repair.indices[i] / 64U] &=
            ~(UINT64_C(1) << (repair.indices[i] % 64U));
      }
      queued++;
    }
    if (queued != 0 && pending->mode == TRANSPORT_REPAIR_MODE_RATELESS) {
      bool committed =
          systematic_fallback
              ? transport_repair_commit_systematic_fallback(object, &repair,
                                                            queued)
              : transport_repair_commit_rateless(object, &repair, queued);
      /* Repair allocation is transactional: only symbols admitted to an
       * egress queue consume an ESI (or advance the systematic fallback). */
      if (!committed) {
        t->stats.repair_commit_failures++;
        clear_pending_repair(t, flow, pending);
      }
    }
    transport_repair_batch_destroy(&repair);
    if (queued != 0) {
      size_t physical_symbols = forced_unicast ? unicast_transmissions : queued;
      t->stats.repair_symbols_sent += physical_symbols;
      if (forced_unicast) {
        t->stats.repair_unicast_symbols_sent += unicast_transmissions;
        uint64_t unicast_bytes =
            unicast_transmissions > UINT64_MAX / packet_size
                ? UINT64_MAX
                : (uint64_t)unicast_transmissions * packet_size;
        t->stats.repair_unicast_payload_bytes_queued = tf_saturating_add_u64(
            t->stats.repair_unicast_payload_bytes_queued, unicast_bytes);
      } else {
        t->stats.repair_multicast_symbols_sent += queued;
      }
      if (pending->mode == TRANSPORT_REPAIR_MODE_RATELESS)
        t->stats.repair_rateless_symbols_sent += physical_symbols;
      t->stats.repair_batches_emitted++;
      pending->backpressure_reported = false;
    }
    if (tf_pending_repair_symbol_count(pending) == 0)
      clear_pending_repair(t, flow, pending);
    else
      pending->ready_at_ms = now;
  }
}
