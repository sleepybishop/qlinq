#include "transport_repair_planner.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  bool valid;
  bool uncertain;
  uint64_t physical_bytes;
  uint64_t aggregate_airtime_us;
  uint64_t completion_us;
  size_t symbols;
  transport_repair_planner_resource_cost_t
      resources[TRANSPORT_REPAIR_PLANNER_MAX_RESOURCES];
  size_t resource_count;
} requester_cost_t;

static uint64_t saturating_add_u64(uint64_t a, uint64_t b) {
  return b > UINT64_MAX - a ? UINT64_MAX : a + b;
}

static uint64_t saturating_mul_u64(uint64_t a, uint64_t b) {
  return a != 0 && b > UINT64_MAX / a ? UINT64_MAX : a * b;
}

static uint64_t divide_ceil_u64(uint64_t numerator, uint64_t denominator) {
  if (denominator == 0)
    return UINT64_MAX;
  return numerator / denominator + (numerator % denominator != 0);
}

static size_t bit_count_words(const uint64_t *words) {
  size_t count = 0;
  for (size_t i = 0; i < QLINQ_WIRE_MAX_NACK_SYMBOLS / 64U; i++)
    count += (size_t)__builtin_popcountll(words[i]);
  return count;
}

static bool snapshot_has_unknown_resource(
    const transport_repair_planner_snapshot_t *snapshot) {
  if (snapshot->shared_resource_id == 0)
    return true;
  for (size_t i = 0; i < snapshot->requester_count; i++) {
    const transport_repair_planner_requester_t *requester =
        &snapshot->requesters[i];
    for (size_t p = 0; p < requester->path_count; p++)
      if (requester->paths[p].resource_id == 0)
        return true;
  }
  return false;
}

static bool
add_resource_cost(transport_repair_planner_resource_cost_t *resources,
                  size_t *resource_count, uint64_t resource_id, uint64_t bytes,
                  uint64_t airtime_us) {
  for (size_t i = 0; i < *resource_count; i++) {
    if (resources[i].resource_id != resource_id)
      continue;
    resources[i].physical_bytes =
        saturating_add_u64(resources[i].physical_bytes, bytes);
    resources[i].airtime_us =
        saturating_add_u64(resources[i].airtime_us, airtime_us);
    return true;
  }
  if (*resource_count >= TRANSPORT_REPAIR_PLANNER_MAX_RESOURCES)
    return false;
  resources[*resource_count] =
      (transport_repair_planner_resource_cost_t){.resource_id = resource_id,
                                                 .physical_bytes = bytes,
                                                 .airtime_us = airtime_us};
  (*resource_count)++;
  return true;
}

static uint64_t fp_seconds_to_us(fp_t seconds) {
  if (seconds <= 0)
    return 0;
  fp_wide_t scaled = (fp_wide_t)seconds * 1000000;
  scaled = (scaled + FP_ONE - 1) / FP_ONE;
  return scaled > UINT64_MAX ? UINT64_MAX : (uint64_t)scaled;
}

static uint64_t packets_at_rate_to_us(size_t packets, fp_t packets_per_second) {
  if (packets_per_second <= 0)
    return UINT64_MAX;
  fp_wide_t numerator = (fp_wide_t)packets * 1000000 * FP_ONE;
  fp_wide_t result = (numerator + packets_per_second - 1) / packets_per_second;
  return result > UINT64_MAX ? UINT64_MAX : (uint64_t)result;
}

static bool
build_requester_cost(const transport_repair_planner_snapshot_t *snapshot,
                     const transport_repair_planner_requester_t *requester,
                     bool collapse_resources, requester_cost_t *cost) {
  memset(cost, 0, sizeof(*cost));
  if (requester->deficit == 0 || requester->path_count == 0 ||
      requester->path_count > TRANSPORT_MAX_PATHS)
    return false;

  path_t paths[TRANSPORT_MAX_PATHS];
  for (size_t i = 0; i < requester->path_count; i++) {
    paths[i] = requester->paths[i].estimate;
    if (!requester->paths[i].measurement_known)
      cost->uncertain = true;
  }

  pathflow_context_t context = {0};
  fp_t completion = pathflow_optimize(
      &context, requester->path_count, requester->deficit, paths,
      FP_FROM_FLOAT(10.0f), 95, PATHFLOW_SOLVER_GREEDY);
  if (completion == PATHFLOW_ERROR)
    return false;

  uint64_t packet_bytes =
      saturating_add_u64(snapshot->symbol_size, snapshot->packet_overhead);
  for (size_t i = 0; i < requester->path_count; i++) {
    if (paths[i].x == 0)
      continue;
    uint64_t bytes = saturating_mul_u64(paths[i].x, packet_bytes);
    uint64_t airtime_us = packets_at_rate_to_us(paths[i].x, paths[i].b);
    uint64_t resource_id =
        collapse_resources ? 0 : requester->paths[i].resource_id;
    if (airtime_us == UINT64_MAX ||
        !add_resource_cost(cost->resources, &cost->resource_count, resource_id,
                           bytes, airtime_us))
      return false;
    cost->physical_bytes = saturating_add_u64(cost->physical_bytes, bytes);
    cost->aggregate_airtime_us =
        saturating_add_u64(cost->aggregate_airtime_us, airtime_us);
    cost->symbols += paths[i].x;
  }
  cost->completion_us = fp_seconds_to_us(completion);
  cost->valid = cost->symbols != 0;
  return cost->valid;
}

static uint64_t member_hash_add(uint64_t hash, uint64_t member_id) {
  for (size_t byte = 0; byte < sizeof(member_id); byte++) {
    hash ^= (member_id >> (byte * 8U)) & 0xffU;
    hash *= UINT64_C(1099511628211);
  }
  return hash;
}

static bool
candidate_add_requester_cost(transport_repair_planner_candidate_t *candidate,
                             const requester_cost_t *requester) {
  if (!requester->valid)
    return false;
  candidate->physical_bytes =
      saturating_add_u64(candidate->physical_bytes, requester->physical_bytes);
  candidate->aggregate_airtime_us = saturating_add_u64(
      candidate->aggregate_airtime_us, requester->aggregate_airtime_us);
  if (requester->completion_us > candidate->predicted_completion_us)
    candidate->predicted_completion_us = requester->completion_us;
  candidate->unicast_symbols += requester->symbols;
  candidate->unicast_requesters++;
  candidate->uncertain |= requester->uncertain;
  for (size_t i = 0; i < requester->resource_count; i++)
    if (!add_resource_cost(candidate->resources, &candidate->resource_count,
                           requester->resources[i].resource_id,
                           requester->resources[i].physical_bytes,
                           requester->resources[i].airtime_us))
      return false;
  return true;
}

static void
finalize_candidate(const transport_repair_planner_snapshot_t *snapshot,
                   transport_repair_planner_candidate_t *candidate) {
  uint64_t deadline_us = saturating_mul_u64(snapshot->deadline_ms, 1000U);
  for (size_t i = 0; i < candidate->resource_count; i++) {
    if (candidate->resources[i].airtime_us > candidate->predicted_completion_us)
      candidate->predicted_completion_us = candidate->resources[i].airtime_us;
    if (deadline_us != 0 && candidate->resources[i].airtime_us > deadline_us)
      candidate->feasible = false;
  }
}

static bool build_candidate(const transport_repair_planner_snapshot_t *snapshot,
                            const requester_cost_t *unicast_costs,
                            uint64_t shared_mask, bool exact_mask,
                            bool collapse_resources,
                            transport_repair_planner_candidate_t *candidate) {
  transport_repair_plan_action_t action = TRANSPORT_REPAIR_PLAN_MIXED;
  if (shared_mask == 0)
    action = TRANSPORT_REPAIR_PLAN_ALL_UNICAST;
  else if (exact_mask &&
           shared_mask ==
               (snapshot->requester_count == 64
                    ? UINT64_MAX
                    : (UINT64_C(1) << snapshot->requester_count) - 1U))
    action = TRANSPORT_REPAIR_PLAN_ALL_SHARED;
  memset(candidate, 0, sizeof(*candidate));
  candidate->action = action;
  candidate->valid = true;
  candidate->feasible = true;
  candidate->uncertain = collapse_resources;
  candidate->uncertain |= snapshot->incomplete_requester_state;
  candidate->shared_member_hash = UINT64_C(1469598103934665603);

  uint64_t requested_union[QLINQ_WIRE_MAX_NACK_SYMBOLS / 64U] = {0};
  size_t maximum_deficit = 0;
  uint32_t minimum_delivery_ppm = 1000000U;
  for (size_t i = 0; i < snapshot->requester_count; i++) {
    bool shared =
        shared_mask != 0 &&
        (!exact_mask || (i < 64 && (shared_mask & (UINT64_C(1) << i)) != 0));
    const transport_repair_planner_requester_t *requester =
        &snapshot->requesters[i];
    candidate->innovative_deliveries = saturating_add_u64(
        candidate->innovative_deliveries, requester->deficit);
    if (!shared) {
      if (!candidate_add_requester_cost(candidate, &unicast_costs[i])) {
        candidate->valid = false;
        candidate->feasible = false;
        return false;
      }
      continue;
    }
    candidate->shared_requesters++;
    candidate->shared_member_hash =
        member_hash_add(candidate->shared_member_hash, requester->member_id);
    if (requester->deficit > maximum_deficit)
      maximum_deficit = requester->deficit;
    if (requester->shared_delivery_probability_ppm == 0) {
      candidate->uncertain = true;
    } else if (requester->shared_delivery_probability_ppm <
               minimum_delivery_ppm) {
      minimum_delivery_ppm = requester->shared_delivery_probability_ppm;
    }
    if (snapshot->mode == TRANSPORT_REPAIR_MODE_INDEXED)
      for (size_t word = 0; word < QLINQ_WIRE_MAX_NACK_SYMBOLS / 64U; word++)
        requested_union[word] |= requester->requested_symbols[word];
  }

  if (candidate->shared_requesters != 0) {
    size_t logical_symbols = snapshot->mode == TRANSPORT_REPAIR_MODE_INDEXED
                                 ? bit_count_words(requested_union)
                                 : maximum_deficit;
    if (logical_symbols == 0 || snapshot->shared_rate_bytes_per_second == 0) {
      candidate->valid = false;
      candidate->feasible = false;
      return false;
    }
    if (minimum_delivery_ppm == 0)
      minimum_delivery_ppm = 1000000U;
    uint64_t physical_symbols = divide_ceil_u64(
        saturating_mul_u64(logical_symbols, 1000000U), minimum_delivery_ppm);
    uint64_t packet_bytes =
        saturating_add_u64(snapshot->symbol_size, snapshot->packet_overhead);
    uint64_t copies = snapshot->shared_physical_copies == 0
                          ? 1
                          : snapshot->shared_physical_copies;
    uint64_t bytes = saturating_mul_u64(
        saturating_mul_u64(physical_symbols, packet_bytes), copies);
    uint64_t airtime_us =
        divide_ceil_u64(saturating_mul_u64(bytes, 1000000U),
                        snapshot->shared_rate_bytes_per_second);
    uint64_t resource_id =
        collapse_resources ? 0 : snapshot->shared_resource_id;
    if (airtime_us == UINT64_MAX ||
        !add_resource_cost(candidate->resources, &candidate->resource_count,
                           resource_id, bytes, airtime_us)) {
      candidate->valid = false;
      candidate->feasible = false;
      return false;
    }
    candidate->shared_symbols = (size_t)physical_symbols;
    candidate->physical_bytes =
        saturating_add_u64(candidate->physical_bytes, bytes);
    candidate->aggregate_airtime_us =
        saturating_add_u64(candidate->aggregate_airtime_us, airtime_us);
  }

  finalize_candidate(snapshot, candidate);
  return true;
}

static bool candidates_share_single_resource(
    const transport_repair_planner_candidate_t *left,
    const transport_repair_planner_candidate_t *right) {
  return left->resource_count == 1 && right->resource_count == 1 &&
         left->resources[0].resource_id == right->resources[0].resource_id;
}

static bool
candidate_better(const transport_repair_planner_candidate_t *candidate,
                 const transport_repair_planner_candidate_t *best) {
  if (!candidate->valid)
    return false;
  if (!best->valid)
    return true;
  if (candidate->feasible != best->feasible)
    return candidate->feasible;
  /* Controller rates bound completion and feasibility, but they are not PHY
   * rates. When both candidates consume the same single physical resource,
   * expected bytes are proportional to radio airtime and must be the primary
   * cost. Comparing controller-derived durations here incorrectly rewards a
   * faster QUIC controller for sending more copies over the same radio. */
  bool same_physical_resource =
      candidates_share_single_resource(candidate, best);
  if (same_physical_resource &&
      candidate->physical_bytes != best->physical_bytes)
    return candidate->physical_bytes < best->physical_bytes;
  if (candidate->aggregate_airtime_us != best->aggregate_airtime_us)
    return candidate->aggregate_airtime_us < best->aggregate_airtime_us;
  if (candidate->physical_bytes != best->physical_bytes)
    return candidate->physical_bytes < best->physical_bytes;
  /* Preserve the frozen all-shared behavior on an exact tie. */
  return candidate->action < best->action;
}

static void
evaluate_large_prefixes(const transport_repair_planner_snapshot_t *snapshot,
                        const requester_cost_t *unicast_costs,
                        bool collapse_resources,
                        transport_repair_planner_candidate_t *mixed) {
  size_t *order = calloc(snapshot->requester_count, sizeof(*order));
  transport_repair_planner_requester_t *copy =
      calloc(snapshot->requester_count, sizeof(*copy));
  requester_cost_t *copy_costs =
      calloc(snapshot->requester_count, sizeof(*copy_costs));
  if (!order || !copy || !copy_costs) {
    free(order);
    free(copy);
    free(copy_costs);
    return;
  }
  for (size_t i = 0; i < snapshot->requester_count; i++) {
    order[i] = i;
    size_t position = i;
    while (position > 0) {
      size_t left = order[position - 1U];
      uint64_t left_score = unicast_costs[left].aggregate_airtime_us;
      uint64_t right_score =
          unicast_costs[order[position]].aggregate_airtime_us;
      if (left_score > right_score ||
          (left_score == right_score &&
           snapshot->requesters[left].member_id <
               snapshot->requesters[order[position]].member_id))
        break;
      size_t temporary = order[position - 1U];
      order[position - 1U] = order[position];
      order[position] = temporary;
      position--;
    }
  }
  for (size_t i = 0; i < snapshot->requester_count; i++) {
    size_t source = order[i];
    copy[i] = snapshot->requesters[source];
    copy_costs[i] = unicast_costs[source];
  }

  /* Large cohorts use deterministic prefixes ordered by avoided unicast
   * airtime. They remain shadow-only and are explicitly marked approximate. */
  for (size_t prefix = 1; prefix < snapshot->requester_count; prefix++) {
    transport_repair_planner_snapshot_t ordered = *snapshot;
    ordered.requesters = copy;
    ordered.requester_count = prefix;
    transport_repair_planner_candidate_t candidate;
    if (build_candidate(&ordered, copy_costs, 1, false, collapse_resources,
                        &candidate)) {
      /* Add the excluded requesters' unicast actions. */
      for (size_t i = prefix; i < snapshot->requester_count; i++)
        if (!candidate_add_requester_cost(&candidate, &copy_costs[i])) {
          candidate.valid = false;
          break;
        }
      for (size_t i = prefix; i < snapshot->requester_count; i++)
        candidate.innovative_deliveries = saturating_add_u64(
            candidate.innovative_deliveries, copy[i].deficit);
      candidate.action = TRANSPORT_REPAIR_PLAN_MIXED;
      candidate.approximate = true;
      candidate.uncertain = true;
      finalize_candidate(snapshot, &candidate);
      if (candidate_better(&candidate, mixed))
        *mixed = candidate;
    }
  }
  free(order);
  free(copy);
  free(copy_costs);
}

bool transport_repair_planner_evaluate(
    const transport_repair_planner_snapshot_t *snapshot,
    transport_repair_planner_evaluation_t *evaluation) {
  if (!snapshot || !evaluation ||
      snapshot->version != TRANSPORT_REPAIR_PLANNER_VERSION ||
      !snapshot->requesters || snapshot->requester_count == 0 ||
      snapshot->requester_count > TRANSPORT_REPAIR_PLANNER_MAX_REQUESTERS ||
      (snapshot->cohort_member_count != 0 &&
       snapshot->requester_count > snapshot->cohort_member_count) ||
      snapshot->symbol_size == 0 ||
      (snapshot->mode != TRANSPORT_REPAIR_MODE_INDEXED &&
       snapshot->mode != TRANSPORT_REPAIR_MODE_RATELESS))
    return false;
  memset(evaluation, 0, sizeof(*evaluation));

  bool collapse_resources = snapshot_has_unknown_resource(snapshot);
  requester_cost_t *unicast_costs =
      calloc(snapshot->requester_count, sizeof(*unicast_costs));
  if (!unicast_costs)
    return false;
  for (size_t i = 0; i < snapshot->requester_count; i++)
    build_requester_cost(snapshot, &snapshot->requesters[i], collapse_resources,
                         &unicast_costs[i]);

  uint64_t all_mask =
      snapshot->requester_count <= 64
          ? (snapshot->requester_count == 64
                 ? UINT64_MAX
                 : (UINT64_C(1) << snapshot->requester_count) - 1U)
          : 1;
  build_candidate(snapshot, unicast_costs, all_mask,
                  snapshot->requester_count <= 64, collapse_resources,
                  &evaluation->all_shared);
  evaluation->all_shared.action = TRANSPORT_REPAIR_PLAN_ALL_SHARED;
  build_candidate(snapshot, unicast_costs, 0, true, collapse_resources,
                  &evaluation->all_unicast);
  evaluation->all_unicast.action = TRANSPORT_REPAIR_PLAN_ALL_UNICAST;

  if (snapshot->requester_count <= TRANSPORT_REPAIR_PLANNER_EXACT_REQUESTERS) {
    uint64_t limit = UINT64_C(1) << snapshot->requester_count;
    for (uint64_t mask = 1; mask + 1U < limit; mask++) {
      transport_repair_planner_candidate_t candidate;
      if (build_candidate(snapshot, unicast_costs, mask, true,
                          collapse_resources, &candidate) &&
          candidate_better(&candidate, &evaluation->mixed))
        evaluation->mixed = candidate;
    }
  } else {
    evaluate_large_prefixes(snapshot, unicast_costs, collapse_resources,
                            &evaluation->mixed);
  }

  evaluation->chosen = evaluation->all_shared;
  if (candidate_better(&evaluation->all_unicast, &evaluation->chosen))
    evaluation->chosen = evaluation->all_unicast;
  if (candidate_better(&evaluation->mixed, &evaluation->chosen))
    evaluation->chosen = evaluation->mixed;
  if (!evaluation->chosen.valid) {
    free(unicast_costs);
    return false;
  }
  if (evaluation->all_shared.valid) {
    bool same_resource = candidates_share_single_resource(
        &evaluation->chosen, &evaluation->all_shared);
    uint64_t chosen_cost = same_resource
                               ? evaluation->chosen.physical_bytes
                               : evaluation->chosen.aggregate_airtime_us;
    uint64_t shared_cost = same_resource
                               ? evaluation->all_shared.physical_bytes
                               : evaluation->all_shared.aggregate_airtime_us;
    if (chosen_cost < shared_cost && shared_cost != 0) {
      uint64_t saved = shared_cost - chosen_cost;
      fp_wide_t ppm = (fp_wide_t)saved * 1000000 / shared_cost;
      evaluation->chosen_savings_vs_shared_ppm =
          ppm > UINT32_MAX ? UINT32_MAX : (uint32_t)ppm;
    }
  }
  free(unicast_costs);
  return true;
}

const char *
transport_repair_plan_action_name(transport_repair_plan_action_t action) {
  switch (action) {
  case TRANSPORT_REPAIR_PLAN_ALL_SHARED:
    return "all-shared";
  case TRANSPORT_REPAIR_PLAN_ALL_UNICAST:
    return "all-unicast";
  case TRANSPORT_REPAIR_PLAN_MIXED:
    return "mixed";
  default:
    return "unknown";
  }
}

#define PLANNER_RECORD_MAGIC UINT64_C(0x3152344d50524c51)

static bool write_bytes(FILE *output, const void *data, size_t size) {
  return output && fwrite(data, 1, size, output) == size;
}

static bool read_bytes(FILE *input, void *data, size_t size) {
  return input && fread(data, 1, size, input) == size;
}

static bool write_u8(FILE *output, uint8_t value) {
  return write_bytes(output, &value, sizeof(value));
}

static bool write_u32(FILE *output, uint32_t value) {
  uint8_t encoded[4];
  for (size_t i = 0; i < sizeof(encoded); i++)
    encoded[i] = (uint8_t)(value >> (i * 8U));
  return write_bytes(output, encoded, sizeof(encoded));
}

static bool write_u64(FILE *output, uint64_t value) {
  uint8_t encoded[8];
  for (size_t i = 0; i < sizeof(encoded); i++)
    encoded[i] = (uint8_t)(value >> (i * 8U));
  return write_bytes(output, encoded, sizeof(encoded));
}

static bool read_u8(FILE *input, uint8_t *value) {
  return read_bytes(input, value, sizeof(*value));
}

static bool read_u32(FILE *input, uint32_t *value) {
  uint8_t encoded[4];
  if (!read_bytes(input, encoded, sizeof(encoded)))
    return false;
  *value = 0;
  for (size_t i = 0; i < sizeof(encoded); i++)
    *value |= (uint32_t)encoded[i] << (i * 8U);
  return true;
}

static bool read_u64(FILE *input, uint64_t *value) {
  uint8_t encoded[8];
  if (!read_bytes(input, encoded, sizeof(encoded)))
    return false;
  *value = 0;
  for (size_t i = 0; i < sizeof(encoded); i++)
    *value |= (uint64_t)encoded[i] << (i * 8U);
  return true;
}

bool transport_repair_planner_record_write(
    FILE *output, const transport_repair_planner_snapshot_t *snapshot,
    const transport_repair_planner_evaluation_t *evaluation) {
  if (!output || !snapshot || !evaluation || !snapshot->requesters ||
      snapshot->requester_count > TRANSPORT_REPAIR_PLANNER_MAX_REQUESTERS)
    return false;
  if (!write_u64(output, PLANNER_RECORD_MAGIC) ||
      !write_u32(output, snapshot->version) ||
      !write_u64(output, snapshot->intent_id) ||
      !write_u64(output, snapshot->group_id) ||
      !write_u64(output, snapshot->object_id) ||
      !write_u32(output, (uint32_t)snapshot->mode) ||
      !write_u64(output, snapshot->symbol_size) ||
      !write_u64(output, snapshot->packet_overhead) ||
      !write_u64(output, snapshot->deadline_ms) ||
      !write_u64(output, snapshot->shared_rate_bytes_per_second) ||
      !write_u64(output, snapshot->shared_resource_id) ||
      !write_u64(output, snapshot->shared_physical_copies) ||
      !write_u64(output, snapshot->cohort_member_count) ||
      !write_u64(output, snapshot->observation_window_ms) ||
      !write_u64(output, snapshot->observation_age_ms) ||
      !write_u64(output, snapshot->accepted_request_count) ||
      !write_u64(output, snapshot->suppressed_request_count) ||
      !write_u64(output, snapshot->throttled_request_count) ||
      !write_u64(output, snapshot->observation_overflow_count) ||
      !write_u8(output, snapshot->incomplete_requester_state ? 1U : 0U) ||
      !write_u64(output, snapshot->requester_count))
    return false;
  for (size_t i = 0; i < snapshot->requester_count; i++) {
    const transport_repair_planner_requester_t *requester =
        &snapshot->requesters[i];
    if (!write_u64(output, requester->member_id) ||
        !write_u32(output, requester->deficit) ||
        !write_u64(output, requester->feedback_age_ms) ||
        !write_u32(output, requester->shared_delivery_probability_ppm))
      return false;
    for (size_t word = 0; word < QLINQ_WIRE_MAX_NACK_SYMBOLS / 64U; word++)
      if (!write_u64(output, requester->requested_symbols[word]))
        return false;
    if (!write_u64(output, requester->path_count))
      return false;
    for (size_t path = 0; path < requester->path_count; path++) {
      const transport_repair_planner_path_t *entry = &requester->paths[path];
      if (!write_u64(output, entry->resource_id) ||
          !write_u64(output, (uint64_t)entry->estimate.b) ||
          !write_u64(output, (uint64_t)entry->estimate.p) ||
          !write_u64(output, (uint64_t)entry->estimate.l) ||
          !write_u64(output, entry->estimate.q) ||
          !write_u8(output, entry->measurement_known ? 1U : 0U))
        return false;
    }
  }
  return write_u32(output, (uint32_t)evaluation->chosen.action) &&
         write_u8(output, evaluation->chosen.feasible ? 1U : 0U) &&
         write_u8(output, evaluation->chosen.uncertain ? 1U : 0U) &&
         write_u8(output, evaluation->chosen.approximate ? 1U : 0U) &&
         write_u64(output, evaluation->chosen.aggregate_airtime_us) &&
         write_u64(output, evaluation->chosen.physical_bytes) &&
         write_u64(output, evaluation->chosen.shared_member_hash) &&
         write_u32(output, evaluation->chosen_savings_vs_shared_ppm);
}

bool transport_repair_planner_record_read(
    FILE *input, transport_repair_planner_snapshot_t *snapshot,
    transport_repair_planner_recorded_result_t *recorded) {
  if (!input || !snapshot || !recorded)
    return false;
  memset(snapshot, 0, sizeof(*snapshot));
  memset(recorded, 0, sizeof(*recorded));
  uint64_t magic = 0, requester_count = 0, value = 0;
  uint32_t mode = 0, action = 0;
  uint8_t boolean = 0;
  if (!read_u64(input, &magic))
    return false;
  if (magic != PLANNER_RECORD_MAGIC || !read_u32(input, &snapshot->version) ||
      !read_u64(input, &snapshot->intent_id) ||
      !read_u64(input, &snapshot->group_id) ||
      !read_u64(input, &snapshot->object_id) || !read_u32(input, &mode) ||
      !read_u64(input, &value))
    return false;
  snapshot->mode = (transport_repair_mode_t)mode;
  snapshot->symbol_size = (size_t)value;
  if (!read_u64(input, &value))
    return false;
  snapshot->packet_overhead = (size_t)value;
  if (!read_u64(input, &snapshot->deadline_ms) ||
      !read_u64(input, &snapshot->shared_rate_bytes_per_second) ||
      !read_u64(input, &snapshot->shared_resource_id) ||
      !read_u64(input, &value))
    return false;
  snapshot->shared_physical_copies = (size_t)value;
  if (!read_u64(input, &value))
    return false;
  snapshot->cohort_member_count = (size_t)value;
  if (!read_u64(input, &snapshot->observation_window_ms) ||
      !read_u64(input, &snapshot->observation_age_ms) ||
      !read_u64(input, &value))
    return false;
  snapshot->accepted_request_count = (size_t)value;
  if (!read_u64(input, &value))
    return false;
  snapshot->suppressed_request_count = (size_t)value;
  if (!read_u64(input, &value))
    return false;
  snapshot->throttled_request_count = (size_t)value;
  if (!read_u64(input, &value))
    return false;
  snapshot->observation_overflow_count = (size_t)value;
  if (!read_u8(input, &boolean) || !read_u64(input, &requester_count) ||
      requester_count == 0 ||
      requester_count > TRANSPORT_REPAIR_PLANNER_MAX_REQUESTERS ||
      (snapshot->cohort_member_count != 0 &&
       requester_count > snapshot->cohort_member_count))
    return false;
  snapshot->incomplete_requester_state = boolean != 0;
  transport_repair_planner_requester_t *requesters =
      calloc((size_t)requester_count, sizeof(*requesters));
  if (!requesters)
    return false;
  snapshot->requesters = requesters;
  snapshot->requester_count = (size_t)requester_count;
  for (size_t i = 0; i < snapshot->requester_count; i++) {
    transport_repair_planner_requester_t *requester = &requesters[i];
    uint32_t deficit = 0;
    if (!read_u64(input, &requester->member_id) || !read_u32(input, &deficit) ||
        !read_u64(input, &requester->feedback_age_ms) ||
        !read_u32(input, &requester->shared_delivery_probability_ppm))
      goto Error;
    requester->deficit = (uint16_t)deficit;
    for (size_t word = 0; word < QLINQ_WIRE_MAX_NACK_SYMBOLS / 64U; word++)
      if (!read_u64(input, &requester->requested_symbols[word]))
        goto Error;
    if (!read_u64(input, &value) || value > TRANSPORT_MAX_PATHS)
      goto Error;
    requester->path_count = (size_t)value;
    for (size_t path = 0; path < requester->path_count; path++) {
      transport_repair_planner_path_t *entry = &requester->paths[path];
      uint64_t b = 0, p = 0, l = 0, q = 0;
      if (!read_u64(input, &entry->resource_id) || !read_u64(input, &b) ||
          !read_u64(input, &p) || !read_u64(input, &l) ||
          !read_u64(input, &q) || !read_u8(input, &boolean))
        goto Error;
      entry->estimate.b = (fp_t)b;
      entry->estimate.p = (fp_t)p;
      entry->estimate.l = (fp_t)l;
      entry->estimate.q = (size_t)q;
      entry->measurement_known = boolean != 0;
    }
  }
  if (!read_u32(input, &action) || !read_u8(input, &boolean))
    goto Error;
  recorded->feasible = boolean != 0;
  if (!read_u8(input, &boolean))
    goto Error;
  recorded->uncertain = boolean != 0;
  if (!read_u8(input, &boolean))
    goto Error;
  recorded->approximate = boolean != 0;
  if (!read_u64(input, &recorded->aggregate_airtime_us) ||
      !read_u64(input, &recorded->physical_bytes) ||
      !read_u64(input, &recorded->shared_member_hash) ||
      !read_u32(input, &recorded->savings_vs_shared_ppm))
    goto Error;
  recorded->action = (transport_repair_plan_action_t)action;
  return true;

Error:
  transport_repair_planner_record_destroy(snapshot);
  return false;
}

void transport_repair_planner_record_destroy(
    transport_repair_planner_snapshot_t *snapshot) {
  if (!snapshot)
    return;
  free((void *)snapshot->requesters);
  memset(snapshot, 0, sizeof(*snapshot));
}
