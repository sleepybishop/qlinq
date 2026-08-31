#ifndef QLINQ_TRANSPORT_REPAIR_PLANNER_H
#define QLINQ_TRANSPORT_REPAIR_PLANNER_H

#include "pathflow.h"
#include "transport.h"
#include "transport_wire.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#define TRANSPORT_REPAIR_PLANNER_VERSION 3U
#define TRANSPORT_REPAIR_PLANNER_MAX_REQUESTERS 1024U
#define TRANSPORT_REPAIR_PLANNER_DEFAULT_DEADLINE_MS 1000U
#define TRANSPORT_REPAIR_PLANNER_MAX_RESOURCES (TRANSPORT_MAX_PATHS + 1U)
#define TRANSPORT_REPAIR_PLANNER_EXACT_REQUESTERS 16U

typedef enum {
  TRANSPORT_REPAIR_PLAN_ALL_SHARED = 0,
  TRANSPORT_REPAIR_PLAN_ALL_UNICAST = 1,
  TRANSPORT_REPAIR_PLAN_MIXED = 2
} transport_repair_plan_action_t;

typedef struct {
  uint64_t resource_id;
  path_t estimate;
  bool measurement_known;
} transport_repair_planner_path_t;

typedef struct {
  uint64_t member_id;
  uint16_t deficit;
  uint64_t feedback_age_ms;
  uint32_t shared_delivery_probability_ppm;
  uint64_t requested_symbols[QLINQ_WIRE_MAX_NACK_SYMBOLS / 64U];
  transport_repair_planner_path_t paths[TRANSPORT_MAX_PATHS];
  size_t path_count;
} transport_repair_planner_requester_t;

/* All pointers are borrowed and immutable for the duration of one evaluation.
 * A zero resource ID means that the relationship is unknown. If any action in
 * a snapshot has an unknown resource, the evaluator conservatively maps every
 * action to one shared resource and marks the result uncertain. */
typedef struct {
  uint32_t version;
  uint64_t intent_id;
  uint64_t group_id;
  uint64_t object_id;
  transport_repair_mode_t mode;
  size_t symbol_size;
  size_t packet_overhead;
  uint64_t deadline_ms;
  uint64_t shared_rate_bytes_per_second;
  uint64_t shared_resource_id;
  size_t shared_physical_copies;
  /* Number of members eligible to receive the shared repair. A requester
   * snapshot that covers fewer members is explicitly censored unless the
   * caller can prove the remaining members are complete. */
  size_t cohort_member_count;
  uint64_t observation_window_ms;
  uint64_t observation_age_ms;
  size_t accepted_request_count;
  size_t suppressed_request_count;
  size_t throttled_request_count;
  size_t observation_overflow_count;
  bool incomplete_requester_state;
  const transport_repair_planner_requester_t *requesters;
  size_t requester_count;
} transport_repair_planner_snapshot_t;

typedef struct {
  uint64_t resource_id;
  uint64_t physical_bytes;
  uint64_t airtime_us;
} transport_repair_planner_resource_cost_t;

typedef struct {
  transport_repair_plan_action_t action;
  bool valid;
  bool feasible;
  bool uncertain;
  bool approximate;
  uint64_t physical_bytes;
  uint64_t aggregate_airtime_us;
  uint64_t predicted_completion_us;
  uint64_t innovative_deliveries;
  size_t shared_symbols;
  size_t unicast_symbols;
  size_t shared_requesters;
  size_t unicast_requesters;
  uint64_t shared_member_hash;
  transport_repair_planner_resource_cost_t
      resources[TRANSPORT_REPAIR_PLANNER_MAX_RESOURCES];
  size_t resource_count;
} transport_repair_planner_candidate_t;

typedef struct {
  transport_repair_planner_candidate_t all_shared;
  transport_repair_planner_candidate_t all_unicast;
  transport_repair_planner_candidate_t mixed;
  transport_repair_planner_candidate_t chosen;
  uint32_t chosen_savings_vs_shared_ppm;
} transport_repair_planner_evaluation_t;

typedef struct {
  transport_repair_plan_action_t action;
  bool feasible;
  bool uncertain;
  bool approximate;
  uint64_t aggregate_airtime_us;
  uint64_t physical_bytes;
  uint64_t shared_member_hash;
  uint32_t savings_vs_shared_ppm;
} transport_repair_planner_recorded_result_t;

bool transport_repair_planner_evaluate(
    const transport_repair_planner_snapshot_t *snapshot,
    transport_repair_planner_evaluation_t *evaluation);

const char *transport_repair_plan_action_name(
    transport_repair_plan_action_t action);

/* Versioned local experiment record, not a network wire format. The reader
 * allocates snapshot->requesters; release it with the matching destroy call. */
bool transport_repair_planner_record_write(
    FILE *output, const transport_repair_planner_snapshot_t *snapshot,
    const transport_repair_planner_evaluation_t *evaluation);
bool transport_repair_planner_record_read(
    FILE *input, transport_repair_planner_snapshot_t *snapshot,
    transport_repair_planner_recorded_result_t *recorded);
void transport_repair_planner_record_destroy(
    transport_repair_planner_snapshot_t *snapshot);

#endif
