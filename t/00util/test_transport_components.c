#include "transport_config.h"
#include "transport_egress.h"
#include "transport_fec_state.h"
#include "transport_internal.h"
#include "transport_memory.h"
#include "transport_paths.h"
#include "transport_repair.h"
#include "transport_repair_planner.h"
#include "transport_scheduler.h"
#include "transport_subscriptions.h"

#include "transport_udp.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#define CHECK(condition, message)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "transport component test failed: %s\n", message);       \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static int test_recovery_cache_protection(void) {
  transport_sent_cache_t cache = {0};
  uint8_t payload[] = {1, 2, 3};
  moq_object_t object = {
      .track_id = {.type = MOQ_TRACK_DATA, .name = "protected"},
      .data = payload,
      .size = sizeof(payload)};
  CHECK(transport_sent_cache_store(&cache, &object, 2, 1, 3, false),
        "retain required recovery object");
  for (size_t i = 1; i < TRANSPORT_SENT_CACHE_SIZE; i++) {
    object.object_id = i;
    CHECK(transport_sent_cache_store(&cache, &object, 2, 1, 3, true),
          "fill best-effort cache entries");
  }
  object.object_id = TRANSPORT_SENT_CACHE_SIZE;
  CHECK(transport_sent_cache_store(&cache, &object, 2, 1, 3, true),
        "best-effort replacement can skip protected entry");
  CHECK(transport_sent_cache_find(&cache, &object.track_id, 0, 0) != NULL &&
            transport_sent_cache_find(&cache, &object.track_id, 0, 1) == NULL,
        "evict best-effort entry instead of recovery obligation");
  /* Promote existing entries, then ensure best-effort retries cannot revoke
   * the recovery protection. */
  for (size_t i = 2; i <= TRANSPORT_SENT_CACHE_SIZE; i++) {
    object.object_id = i;
    CHECK(transport_sent_cache_store(&cache, &object, 2, 1, 3, false) &&
              transport_sent_cache_store(&cache, &object, 2, 1, 3, true),
          "retry preserves promoted recovery protection");
  }
  object.object_id++;
  CHECK(!transport_sent_cache_store(&cache, &object, 2, 1, 3, true),
        "reject best-effort admission when every entry is protected");
  CHECK(transport_sent_cache_release_through(&cache, &object.track_id, 0, 0) ==
            1,
        "checkpoint releases protected entry");
  CHECK(transport_sent_cache_store(&cache, &object, 2, 1, 3, true),
        "released entry admits new publication");
  object.object_id++;
  CHECK(transport_sent_cache_store(&cache, &object, 2, 1, 3, true),
        "reused entry no longer inherits old protection");
  CHECK(transport_sent_cache_release_track(&cache, &object.track_id) ==
            TRANSPORT_SENT_CACHE_SIZE,
        "track release retires protected and best-effort entries");
  transport_sent_cache_destroy(&cache);
  return 0;
}

static int test_udp_batch_boundaries(void) {
  static const struct {
    size_t count;
    size_t lengths[3];
  } cases[] = {{3, {40, 40, 40}}, {3, {80, 80, 40}}, {2, {40, 80}},
               {3, {80, 40, 80}}, {2, {40, 0}},      {2, {0, 40}},
               {3, {80, 0, 40}}};
  int sender = socket(AF_INET, SOCK_DGRAM, 0);
  int receiver = socket(AF_INET, SOCK_DGRAM, 0);
  CHECK(sender >= 0 && receiver >= 0, "UDP batch sockets");
  struct sockaddr_in address = {.sin_family = AF_INET,
                                .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  socklen_t address_len = sizeof(address);
  CHECK(bind(receiver, (struct sockaddr *)&address, address_len) == 0 &&
            getsockname(receiver, (struct sockaddr *)&address, &address_len) ==
                0,
        "UDP batch receiver address");
  struct timeval timeout = {.tv_sec = 1};
  CHECK(setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) == 0,
        "UDP batch receive deadline");
  uint8_t payloads[3][80], received[256];
  for (size_t i = 0; i < 3; i++)
    for (size_t j = 0; j < sizeof(payloads[i]); j++)
      payloads[i][j] = (uint8_t)(i * 23 + j);
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    struct iovec datagrams[3];
    for (size_t i = 0; i < cases[c].count; i++)
      datagrams[i] = (struct iovec){.iov_base = payloads[i],
                                    .iov_len = cases[c].lengths[i]};
    CHECK(transport_udp_send_batch(sender, (struct sockaddr *)&address,
                                   address_len, datagrams,
                                   cases[c].count) == (ssize_t)cases[c].count,
          "UDP batch reports complete datagrams");
    for (size_t i = 0; i < cases[c].count; i++) {
      ssize_t size = recv(receiver, received, sizeof(received), MSG_TRUNC);
      if (size != (ssize_t)datagrams[i].iov_len)
        fprintf(stderr,
                "UDP batch case %zu datagram %zu: received %zd, expected %zu\n",
                c, i, size, datagrams[i].iov_len);
      CHECK(size == (ssize_t)datagrams[i].iov_len &&
                memcmp(received, datagrams[i].iov_base, datagrams[i].iov_len) ==
                    0,
            "UDP batch preserves each datagram's length and contents");
    }
    CHECK(recv(receiver, received, sizeof(received), MSG_DONTWAIT) < 0 &&
              (errno == EAGAIN || errno == EWOULDBLOCK),
          "UDP batch does not create extra datagrams");
  }
  close(sender);
  close(receiver);
  return 0;
}

static int test_assembler_growth_budget(void) {
  transport_t *transport = calloc(1, sizeof(*transport));
  frame_assembler_t assembler = {0}, other = {0};
  const uint16_t symbol_size = 64;
  size_t small = transport_assembler_required_bytes(8, symbol_size);
  size_t large = transport_assembler_required_bytes(16, symbol_size);
  CHECK(transport, "assembler budget fixture");
  transport->limits.max_assembler_memory_bytes = small + large;
  CHECK(transport_grow_assembler(transport, &assembler, 8, symbol_size) &&
            transport_grow_assembler(transport, &other, 8, symbol_size),
        "two assemblers share one allocation budget");
  assembler.total_symbols = 8;
  assembler.symbol_size = symbol_size;
  assembler.received_count = 2;
  assembler.received_mask[0] = assembler.received_mask[7] = true;
  memset(assembler.buffers[0], 13, symbol_size);
  memset(assembler.buffers[7], 29, symbol_size);
  uint8_t *old_storage = assembler.buffer_storage;
  uint8_t **old_pointers = assembler.buffers;
  /* Replacement fits after freeing the old buffers, but exceeds the shared
   * cap while both old and new buffers are live. */
  CHECK(
      !transport_grow_assembler(transport, &assembler, 16, symbol_size),
      "assembler growth reserves new allocation before crediting old storage");
  CHECK(transport->stats.resource_limit_errors == 1 &&
            transport->assembler_memory_bytes == 2 * small &&
            assembler.buffer_storage == old_storage &&
            assembler.buffers == old_pointers &&
            assembler.capacity_symbols == 8 && assembler.received_count == 2 &&
            assembler.received_mask[0] && assembler.received_mask[7] &&
            assembler.buffers[0][symbol_size - 1] == 13 &&
            assembler.buffers[7][symbol_size - 1] == 29,
        "rejected growth preserves incomplete data, allocation and charge");
  CHECK(transport_grow_assembler(transport, &assembler, 8, symbol_size) &&
            transport->stats.resource_limit_errors == 1,
        "capacity reuse needs no duplicate allocation allowance");
  transport_release_assembler(transport, &other);
  CHECK(transport->assembler_memory_bytes == small &&
            transport_grow_assembler(transport, &assembler, 16, symbol_size),
        "released peer allocation makes exact transient headroom available");
  CHECK(transport->assembler_memory_bytes == large &&
            assembler.capacity_symbols == 16 && assembler.received_count == 2 &&
            assembler.received_mask[0] && assembler.received_mask[7] &&
            assembler.buffers[0][symbol_size - 1] == 13 &&
            assembler.buffers[7][symbol_size - 1] == 29,
        "successful growth retains partial data and retires old charge");
  transport_release_assembler(transport, &assembler);
  CHECK(!transport->assembler_memory_bytes && !assembler.buffers &&
            !assembler.buffer_storage && !assembler.capacity_symbols,
        "terminal assembler release restores the shared budget");
  fprintf(stderr,
          "assembler growth budget: old=%zu new=%zu limit=%zu "
          "rejected_with_peer=1 recovery_preserved=1 final_bytes=0\n",
          small, large, small + large);
  free(transport);
  return 0;
}

static int test_subscription_state_lifetime(void) {
  transport_subscription_table_t table = {0};
  CHECK(transport_subscriptions_init(&table, 2), "sparse subscription fixture");
  for (size_t alias = 0; alias <= UINT8_MAX; alias++)
    CHECK(!transport_subscriptions_get_state(&table, alias),
          "inactive aliases allocate no recovery state");
  CHECK(transport_subscriptions_add(&table, MOQ_TRACK_DATA,
                                    MOQ_TRACK_FLAG_FEC_RATELESS, "one", 8),
        "allocate active state");
  transport_subscription_state_t *state =
      transport_subscriptions_get_state(&table, 8);
  CHECK(state != NULL, "active state exists");
  state->object_gap.pending_mask = 3;
  CHECK(!transport_subscriptions_add(&table, MOQ_TRACK_DATA, 0, "other", 8) &&
            transport_subscriptions_get_state(&table, 8) == state &&
            state->object_gap.pending_mask == 3,
        "alias collision preserves incumbent recovery state");
  CHECK(transport_subscriptions_add(&table, MOQ_TRACK_DATA,
                                    MOQ_TRACK_FLAG_FEC_RATELESS, "one", 9) &&
            !transport_subscriptions_get_state(&table, 8) &&
            transport_subscriptions_get_state(&table, 9)
                    ->object_gap.pending_mask == 0,
        "alias remap retires obsolete recovery state");
  transport_subscriptions_remove(&table, MOQ_TRACK_DATA, "one");
  CHECK(!transport_subscriptions_get_state(&table, 9),
        "unsubscribe releases recovery state");
  CHECK(transport_subscriptions_add(&table, MOQ_TRACK_DATA, 0, "two", 9) &&
            transport_subscriptions_get_state(&table, 9)
                    ->object_gap.pending_mask == 0,
        "reused alias starts without obsolete gaps");
  CHECK(transport_subscriptions_init(&table, 1) &&
            !transport_subscriptions_get_state(&table, 9),
        "reinitialization releases prior active state");
  transport_subscriptions_destroy(&table);
  return 0;
}

int main(void) {
  CHECK(test_subscription_state_lifetime() == 0,
        "sparse recovery state lifetime");
  CHECK(test_assembler_growth_budget() == 0,
        "assembler transient allocation budget");
  CHECK(test_udp_batch_boundaries() == 0, "UDP batch boundaries");
  CHECK(test_recovery_cache_protection() == 0, "recovery cache protection");
  transport_limits_t configured = {0};
  transport_limits_t resolved_limits;
  char limit_error[128];
  CHECK(transport_limits_resolve(&configured, &resolved_limits, limit_error,
                                 sizeof(limit_error)),
        "default limit resolution");
  CHECK(resolved_limits.max_connections == TRANSPORT_DEFAULT_MAX_CONNECTIONS &&
            resolved_limits.max_subscriptions_per_connection ==
                TRANSPORT_DEFAULT_MAX_SUBSCRIPTIONS &&
            resolved_limits.max_aggregate_repair_requests_per_second ==
                TRANSPORT_DEFAULT_MAX_AGGREGATE_REPAIR_REQUESTS_PER_SECOND &&
            resolved_limits.max_udp_payload_size == 1280,
        "default limits");
  configured.max_connections = 1000;
  CHECK(transport_limits_resolve(&configured, &resolved_limits, limit_error,
                                 sizeof(limit_error)) &&
            resolved_limits.max_connections == 1000,
        "thousand-node connection limit");
  configured.max_connections = TRANSPORT_HARD_MAX_CONNECTIONS + 1U;
  CHECK(!transport_limits_resolve(&configured, &resolved_limits, limit_error,
                                  sizeof(limit_error)),
        "connection hard limit rejection");
  configured.max_connections = 0;
  configured.max_aggregate_repair_requests_per_second = UINT16_MAX + 1U;
  CHECK(!transport_limits_resolve(&configured, &resolved_limits, limit_error,
                                  sizeof(limit_error)),
        "aggregate repair hard limit rejection");
  configured.max_aggregate_repair_requests_per_second = 0;
  configured.max_egress_packets_per_socket = 63;
  CHECK(!transport_limits_resolve(&configured, &resolved_limits, limit_error,
                                  sizeof(limit_error)),
        "unsafe egress limit rejection");

  transport_egress_t egress;
  CHECK(transport_egress_init(&egress, 64, 64U * 1500U), "egress init");
  CHECK(transport_egress_can_accept(&egress, 64, 64U * 1500U) &&
            !transport_egress_can_accept(&egress, 65, 64U * 1500U),
        "egress reservation bounds");
  transport_egress_destroy(&egress);

  arena_t arena;
  CHECK(transport_arena_init(&arena, 64), "arena init");
  CHECK(transport_arena_alloc(&arena, 16) != NULL, "arena allocation");
  CHECK(transport_arena_alloc(&arena, 128) != NULL, "arena fallback");
  CHECK(arena.fallback_count == 1, "arena fallback ownership");
  transport_arena_reset(&arena);
  CHECK(arena.offset == 0 && arena.fallback_count == 0, "arena reset");
  transport_arena_destroy(&arena);

  frame_assembler_t assembler = {0};
  CHECK(transport_assembler_grow(&assembler, 2, 8), "assembler allocation");
  CHECK(transport_assembler_capacity_bytes(&assembler) ==
            transport_assembler_required_bytes(2, 8),
        "assembler memory accounting");
  memset(assembler.buffers[0], 0x5a, 8);
  assembler.received_mask[0] = true;
  assembler.total_symbols = 2;
  assembler.symbol_size = 8;
  CHECK(transport_assembler_grow(&assembler, 4, 16), "assembler growth");
  CHECK(assembler.buffers[0][0] == 0x5a && assembler.received_mask[0],
        "assembler growth preserves state");
  transport_assembler_release(&assembler);
  CHECK(assembler.buffers == NULL, "assembler release");

  transport_subscription_table_t subscriptions = {0};
  moq_track_id_t track = {
      .type = MOQ_TRACK_DATA, .flags = MOQ_TRACK_FLAG_RELIABLE, .name = "data"};
  CHECK(transport_subscriptions_add(&subscriptions, track.type, track.flags,
                                    track.name, 8),
        "subscription add");
  uint8_t alias = 0;
  CHECK(transport_subscriptions_find_alias(&subscriptions, &track, &alias) ==
                0 &&
            alias == 8,
        "subscription alias lookup");
  moq_track_id_t resolved;
  CHECK(transport_subscriptions_find_by_alias(&subscriptions, 8, &resolved) ==
                0 &&
            strcmp(resolved.name, track.name) == 0,
        "subscription track lookup");
  quicly_stream_t *fake_stream = (quicly_stream_t *)(uintptr_t)1;
  CHECK(transport_subscriptions_bind_stream(&subscriptions, 8, fake_stream),
        "subscription stream binding");
  transport_subscriptions_clear_stream(&subscriptions, fake_stream);
  CHECK(transport_subscriptions_find(&subscriptions, &track)->stream == NULL &&
            transport_subscriptions_find(&subscriptions, &track)
                    ->ingress_stream == NULL,
        "subscription stream clearing");
  CHECK(transport_subscriptions_next_alias(&subscriptions, 8) == 9,
        "subscription next alias");
  transport_subscriptions_remove(&subscriptions, track.type, track.name);
  CHECK(!transport_subscriptions_contains(&subscriptions, &track),
        "subscription removal");
  transport_subscriptions_destroy(&subscriptions);

  transport_subscription_table_t bounded_subscriptions = {0};
  CHECK(transport_subscriptions_init(&bounded_subscriptions, 1),
        "bounded subscription init");
  CHECK(transport_subscriptions_add(&bounded_subscriptions, MOQ_TRACK_DATA, 0,
                                    "one", 8) &&
            !transport_subscriptions_add(&bounded_subscriptions, MOQ_TRACK_DATA,
                                         0, "alias-collision", 8) &&
            !transport_subscriptions_add(&bounded_subscriptions, MOQ_TRACK_DATA,
                                         0, "two", 9),
        "subscription capacity");
  transport_subscriptions_destroy(&bounded_subscriptions);

  path_t paths[3] = {{.x = 2}, {.x = 1}, {.x = 3}};
  CHECK(transport_path_select_physical(paths, 3, 0) == 0 &&
            transport_path_select_physical(paths, 3, 2) == 1 &&
            transport_path_select_physical(paths, 3, 5) == 2,
        "physical path selection");

  path_state_t path_states[2] = {
      {.b_ewma = FP_FROM_INT(100), .l_ewma = FP_FROM_FLOAT(0.01f)},
      {.b_ewma = FP_FROM_INT(50), .l_ewma = FP_FROM_FLOAT(0.02f)}};
  pathflow_context_t scheduler_context = {0};
  size_t round_robin = 0;
  transport_schedule_t schedule;
  CHECK(transport_schedule_build(&scheduler_context, NULL, path_states, 2, 5,
                                 1100, false, 1, &round_robin, &schedule) &&
            schedule.paths[0].x == 3 && schedule.paths[1].x == 2 &&
            schedule.parity_symbols == 0,
        "non-FEC schedule distribution");
  CHECK(transport_schedule_build(&scheduler_context, NULL, path_states, 2, 1,
                                 1100, true, 1, &round_robin, &schedule) &&
            schedule.paths[0].x == 1 && round_robin == 1,
        "single-symbol round robin schedule");

  transport_repair_planner_requester_t planner_requesters[2] = {0};
  for (size_t i = 0; i < 2; i++) {
    planner_requesters[i].member_id = i + 1U;
    planner_requesters[i].deficit = 4;
    planner_requesters[i].shared_delivery_probability_ppm = 1000000U;
    planner_requesters[i].path_count = 1;
    planner_requesters[i].paths[0] =
        (transport_repair_planner_path_t){
            .resource_id = 1,
            .estimate = {.b = FP_FROM_INT(100), .p = 0, .l = 0, .q = 0},
            .measurement_known = true};
  }
  transport_repair_planner_snapshot_t planner_snapshot = {
      .version = TRANSPORT_REPAIR_PLANNER_VERSION,
      .intent_id = 1,
      .group_id = 10,
      .object_id = 20,
      .mode = TRANSPORT_REPAIR_MODE_RATELESS,
      .symbol_size = 1000,
      .deadline_ms = 1000,
      .shared_rate_bytes_per_second = 1000,
      .shared_resource_id = 1,
      .cohort_member_count = 2,
      .observation_window_ms = 500,
      .observation_age_ms = 501,
      .accepted_request_count = 1,
      .suppressed_request_count = 1,
      .requesters = planner_requesters,
      .requester_count = 2};
  transport_repair_planner_evaluation_t planner_evaluation;
  CHECK(transport_repair_planner_evaluate(&planner_snapshot,
                                          &planner_evaluation) &&
            planner_evaluation.chosen.action ==
                TRANSPORT_REPAIR_PLAN_ALL_UNICAST &&
            planner_evaluation.all_unicast.aggregate_airtime_us <
                planner_evaluation.all_shared.aggregate_airtime_us,
        "shadow planner selects lower-cost requester unicast repair");

  planner_snapshot.shared_rate_bytes_per_second = 100000;
  planner_requesters[0].paths[0].estimate.b = FP_FROM_INT(1);
  planner_requesters[1].paths[0].estimate.b = FP_FROM_INT(1);
  CHECK(transport_repair_planner_evaluate(&planner_snapshot,
                                          &planner_evaluation) &&
            planner_evaluation.chosen.action ==
                TRANSPORT_REPAIR_PLAN_ALL_SHARED &&
            planner_evaluation.chosen.shared_symbols == 4,
        "shadow planner preserves economical all-shared repair");

  planner_requesters[0].deficit = 2;
  planner_requesters[0].paths[0].estimate.b = FP_FROM_INT(1);
  planner_requesters[1].deficit = 20;
  planner_requesters[1].shared_delivery_probability_ppm = 100000U;
  planner_requesters[1].paths[0].estimate.b = FP_FROM_INT(1000);
  CHECK(transport_repair_planner_evaluate(&planner_snapshot,
                                          &planner_evaluation) &&
            planner_evaluation.chosen.action == TRANSPORT_REPAIR_PLAN_MIXED &&
            planner_evaluation.chosen.shared_requesters == 1 &&
            planner_evaluation.chosen.unicast_requesters == 1 &&
            planner_evaluation.chosen_savings_vs_shared_ppm > 150000U,
        "shadow planner finds a material mixed repair plan");

  planner_snapshot.mode = TRANSPORT_REPAIR_MODE_INDEXED;
  planner_snapshot.shared_rate_bytes_per_second = 100000;
  memset(planner_requesters[0].requested_symbols, 0,
         sizeof(planner_requesters[0].requested_symbols));
  memset(planner_requesters[1].requested_symbols, 0,
         sizeof(planner_requesters[1].requested_symbols));
  planner_requesters[0].deficit = 2;
  planner_requesters[0].shared_delivery_probability_ppm = 1000000U;
  planner_requesters[0].requested_symbols[0] = UINT64_C(0x3);
  planner_requesters[0].paths[0].estimate.b = FP_FROM_INT(1);
  planner_requesters[1].deficit = 2;
  planner_requesters[1].shared_delivery_probability_ppm = 1000000U;
  planner_requesters[1].requested_symbols[0] = UINT64_C(0x6);
  planner_requesters[1].paths[0].estimate.b = FP_FROM_INT(1);
  CHECK(transport_repair_planner_evaluate(&planner_snapshot,
                                          &planner_evaluation) &&
            planner_evaluation.chosen.action ==
                TRANSPORT_REPAIR_PLAN_ALL_SHARED &&
            planner_evaluation.all_shared.shared_symbols == 3,
        "indexed shadow cost uses the selected requester symbol union");

  planner_snapshot.shared_resource_id = 0;
  transport_repair_planner_evaluation_t planner_replay;
  CHECK(transport_repair_planner_evaluate(&planner_snapshot,
                                          &planner_evaluation) &&
            transport_repair_planner_evaluate(&planner_snapshot,
                                              &planner_replay) &&
            planner_evaluation.chosen.uncertain &&
            planner_evaluation.chosen.resource_count == 1 &&
            planner_evaluation.chosen.action == planner_replay.chosen.action &&
            planner_evaluation.chosen.aggregate_airtime_us ==
                planner_replay.chosen.aggregate_airtime_us &&
            planner_evaluation.chosen.physical_bytes ==
                planner_replay.chosen.physical_bytes,
        "unknown resources collapse conservatively and replay deterministically");
  FILE *planner_record = tmpfile();
  transport_repair_planner_snapshot_t recorded_snapshot;
  transport_repair_planner_recorded_result_t recorded_result;
  CHECK(planner_record &&
            transport_repair_planner_record_write(
                planner_record, &planner_snapshot, &planner_evaluation) &&
            fflush(planner_record) == 0 && fseek(planner_record, 0, SEEK_SET) == 0 &&
            transport_repair_planner_record_read(
                planner_record, &recorded_snapshot, &recorded_result) &&
            transport_repair_planner_evaluate(&recorded_snapshot,
                                              &planner_replay) &&
            recorded_result.action == planner_replay.chosen.action &&
            recorded_result.aggregate_airtime_us ==
                planner_replay.chosen.aggregate_airtime_us &&
            recorded_result.physical_bytes ==
                planner_replay.chosen.physical_bytes &&
            recorded_result.shared_member_hash ==
                planner_replay.chosen.shared_member_hash &&
            recorded_result.feasible == planner_replay.chosen.feasible &&
            recorded_result.uncertain == planner_replay.chosen.uncertain &&
            recorded_result.approximate == planner_replay.chosen.approximate,
        "versioned shadow record replays through the same evaluator");
  CHECK(recorded_snapshot.observation_window_ms == 500 &&
            recorded_snapshot.observation_age_ms == 501 &&
            recorded_snapshot.accepted_request_count == 1 &&
            recorded_snapshot.suppressed_request_count == 1,
        "shadow record preserves observation provenance");
  transport_repair_planner_record_destroy(&recorded_snapshot);
  fclose(planner_record);

  transport_repair_planner_requester_t *large_requesters =
      calloc(1000, sizeof(*large_requesters));
  CHECK(large_requesters != NULL, "thousand-requester planner allocation");
  for (size_t i = 0; i < 1000; i++) {
    large_requesters[i].member_id = i + 1U;
    large_requesters[i].deficit = 1;
    large_requesters[i].shared_delivery_probability_ppm = 1000000U;
    large_requesters[i].path_count = 1;
    large_requesters[i].paths[0] =
        (transport_repair_planner_path_t){
            .resource_id = 1,
            .estimate = {.b = FP_FROM_INT(1), .p = 0, .l = 0, .q = 0},
            .measurement_known = true};
  }
  transport_repair_planner_snapshot_t large_snapshot = {
      .version = TRANSPORT_REPAIR_PLANNER_VERSION,
      .intent_id = 1000,
      .mode = TRANSPORT_REPAIR_MODE_RATELESS,
      .symbol_size = 1000,
      .deadline_ms = 10000,
      .shared_rate_bytes_per_second = 1000000,
      .shared_resource_id = 1,
      .cohort_member_count = 1000,
      .requesters = large_requesters,
      .requester_count = 1000};
  CHECK(transport_repair_planner_evaluate(&large_snapshot,
                                          &planner_evaluation) &&
            planner_evaluation.chosen.action ==
                TRANSPORT_REPAIR_PLAN_ALL_SHARED &&
            !planner_evaluation.chosen.uncertain &&
            planner_evaluation.chosen.shared_requesters == 1000 &&
            planner_evaluation.all_shared.resource_count == 1 &&
            planner_evaluation.all_shared.resources[0].resource_id == 1 &&
            planner_evaluation.all_shared.physical_bytes == 1000 &&
            planner_evaluation.all_unicast.resource_count == 1 &&
            planner_evaluation.all_unicast.resources[0].resource_id == 1 &&
            planner_evaluation.all_unicast.physical_bytes == 1000000,
        "thousand-requester planner counts a shared radio once and each "
        "unicast transmission once");
  for (size_t i = 0; i < 1000; i++)
    large_requesters[i].paths[0].resource_id = 2;
  CHECK(transport_repair_planner_evaluate(&large_snapshot,
                                          &planner_evaluation) &&
            planner_evaluation.all_shared.resource_count == 1 &&
            planner_evaluation.all_shared.resources[0].resource_id == 1 &&
            planner_evaluation.all_unicast.resource_count == 1 &&
            planner_evaluation.all_unicast.resources[0].resource_id == 2 &&
            planner_evaluation.all_unicast.physical_bytes == 1000000,
        "thousand-requester planner keeps demonstrably independent multicast "
        "and unicast resources separate");
  free(large_requesters);

  const uint8_t object_data[] = {1, 2, 3, 4};
  moq_object_t object = {.track_id = track,
                         .group_id = 10,
                         .object_id = 20,
                         .data = object_data,
                         .size = sizeof(object_data),
                         .priority = 2};
  transport_sent_cache_t sent_cache = {0};
  CHECK(transport_sent_cache_store(&sent_cache, &object, 3, 2, 2, false),
        "sent-object cache store");
  sent_object_cache_t *cached =
      transport_sent_cache_find(&sent_cache, &track, 10, 20);
  CHECK(cached && cached->size == sizeof(object_data) && cached->data[3] == 4,
        "sent-object cache roundtrip");
  CHECK(transport_sent_cache_release_through(&sent_cache, &track, 10, 20) ==
                1 &&
            transport_sent_cache_find(&sent_cache, &track, 10, 20) == NULL,
        "sent-object cache checkpoint release");
  CHECK(transport_sent_cache_store(&sent_cache, &object, 3, 2, 2, false),
        "sent-object cache reuse after release");
  cached = transport_sent_cache_find(&sent_cache, &track, 10, 20);

  uint16_t missing_symbol = 1;
  transport_repair_batch_t repair;
  transport_fec_cache_t repair_fec_cache = {0};
  CHECK(transport_repair_build(&repair_fec_cache, cached, false,
                               &missing_symbol, 1, &repair),
        "repair batch build");
  CHECK(repair.count == 1 && repair.indices[0] == 1 &&
            repair.symbols[0] == object_data[2],
        "repair returns requested data symbol");
  transport_repair_batch_destroy(&repair);

  moq_track_id_t rateless_track = {.type = MOQ_TRACK_DATA,
                                   .flags = MOQ_TRACK_FLAG_FEC_RATELESS,
                                   .name = "rateless-data"};
  moq_object_t rateless_object = object;
  rateless_object.track_id = rateless_track;
  transport_sent_cache_t rateless_cache = {0};
  CHECK(transport_sent_cache_store(&rateless_cache, &rateless_object, 2, 2, 2,
                                   false),
        "rateless sent-object cache store");
  sent_object_cache_t *rateless_cached = transport_sent_cache_find(
      &rateless_cache, &rateless_track, object.group_id, object.object_id);
  CHECK(rateless_cached && rateless_cached->next_repair_symbol == 2 &&
            transport_repair_build_rateless(&repair_fec_cache, rateless_cached,
                                            2, &repair) &&
            repair.count == 2 && repair.indices[0] == 2 &&
            repair.indices[1] == 3 && repair.total_symbols == 4 &&
            rateless_cached->next_repair_symbol == 2,
        "rateless repair reserves fresh monotonic ESIs transactionally");
  uint8_t decode_data_0[2] = {1, 2};
  uint8_t decode_data_1[2] = {0};
  uint8_t decode_repair_0[2];
  uint8_t decode_repair_1[2];
  memcpy(decode_repair_0, repair.symbols, 2);
  memcpy(decode_repair_1, repair.symbols + 2, 2);
  uint8_t *decode_blocks[] = {decode_data_0, decode_data_1, decode_repair_0,
                              decode_repair_1};
  bool decode_missing[] = {false, true, false, false};
  fec_t *rateless_decoder =
      transport_fec_cache_get(&repair_fec_cache, FEC_RAPTORQ, 2, 2, 2);
  CHECK(rateless_decoder &&
            fec_decode(rateless_decoder, decode_blocks, decode_missing) &&
            decode_data_1[0] == 3 && decode_data_1[1] == 4,
        "fresh rateless repair recovers a missing source symbol");
  CHECK(transport_repair_commit_rateless(rateless_cached, &repair, 2) &&
            rateless_cached->next_repair_symbol == 4,
        "rateless repair consumes only admitted ESIs");
  transport_repair_batch_destroy(&repair);
  CHECK(transport_repair_build_rateless(&repair_fec_cache, rateless_cached, 3,
                                        &repair) &&
            repair.indices[0] == 4 && repair.indices[2] == 6 &&
            rateless_cached->next_repair_symbol == 4 &&
            transport_repair_commit_rateless(rateless_cached, &repair, 1) &&
            rateless_cached->next_repair_symbol == 5,
        "partial admission leaves unused rateless ESIs available");
  transport_repair_batch_destroy(&repair);
  CHECK(transport_repair_build_rateless(&repair_fec_cache, rateless_cached, 2,
                                        &repair) &&
            repair.indices[0] == 5 && repair.indices[1] == 6 &&
            transport_repair_commit_rateless(rateless_cached, &repair, 2) &&
            rateless_cached->next_repair_symbol == 7,
        "subsequent rateless repair begins after the admitted prefix");
  transport_repair_batch_destroy(&repair);
  rateless_cached->next_repair_symbol = QLINQ_FEC_MAX_TOTAL_SYMBOLS - 1U;
  CHECK(transport_repair_build_rateless(&repair_fec_cache, rateless_cached, 4,
                                        &repair) &&
            repair.count == 1 &&
            repair.indices[0] == QLINQ_FEC_MAX_TOTAL_SYMBOLS - 1U &&
            rateless_cached->next_repair_symbol ==
                QLINQ_FEC_MAX_TOTAL_SYMBOLS - 1U &&
            transport_repair_commit_rateless(rateless_cached, &repair, 1) &&
            rateless_cached->next_repair_symbol == QLINQ_FEC_MAX_TOTAL_SYMBOLS,
        "rateless admission truncates safely at the ESI bound");
  transport_repair_batch_destroy(&repair);
  CHECK(!transport_repair_build_rateless(&repair_fec_cache, rateless_cached, 1,
                                         &repair),
        "rateless allocation reports ESI exhaustion");
  CHECK(transport_repair_build_systematic_fallback(
            &repair_fec_cache, rateless_cached, 4, &repair) &&
            repair.count == 2 && repair.indices[0] == 0 &&
            repair.indices[1] == 1 && repair.symbols[0] == object_data[0] &&
            repair.symbols[2] == object_data[2] &&
            rateless_cached->next_systematic_repair_symbol == 0 &&
            transport_repair_commit_systematic_fallback(rateless_cached,
                                                        &repair, 1) &&
            rateless_cached->next_systematic_repair_symbol == 1,
        "ESI exhaustion falls back to admitted systematic source symbols");
  transport_repair_batch_destroy(&repair);
  CHECK(transport_repair_build_systematic_fallback(
            &repair_fec_cache, rateless_cached, 2, &repair) &&
            repair.indices[0] == 1 && repair.indices[1] == 0 &&
            transport_repair_commit_systematic_fallback(rateless_cached,
                                                        &repair, 2) &&
            rateless_cached->next_systematic_repair_symbol == 1,
        "systematic exhaustion fallback cycles across every source symbol");
  transport_repair_batch_destroy(&repair);

  transport_t negotiation_transport = {0};
  transport_conn_t negotiation_conn = {.transport = &negotiation_transport};
  negotiation_transport.owner_thread = pthread_self();
  negotiation_transport.client_conn = &negotiation_conn;
  negotiation_transport.repair_mode = TRANSPORT_REPAIR_MODE_AUTO;
  negotiation_conn.peer_capabilities = QLINQ_WIRE_CAP_FEC_RATELESS;
  CHECK(transport_get_effective_repair_mode(
            &negotiation_transport, &negotiation_conn, &rateless_track) ==
            TRANSPORT_REPAIR_MODE_INDEXED,
        "legacy rateless peer falls back to indexed repair");
  negotiation_conn.peer_capabilities |= QLINQ_WIRE_CAP_RATELESS_REPAIR;
  CHECK(transport_get_effective_repair_mode(
            &negotiation_transport, &negotiation_conn, &rateless_track) ==
            TRANSPORT_REPAIR_MODE_RATELESS,
        "rateless repair capability enables degree-of-freedom requests");
  negotiation_transport.repair_mode = TRANSPORT_REPAIR_MODE_INDEXED;
  CHECK(transport_get_effective_repair_mode(
            &negotiation_transport, &negotiation_conn, &rateless_track) ==
            TRANSPORT_REPAIR_MODE_INDEXED,
        "explicit indexed preference overrides rateless capability");

  transport_repair_limiter_t limiter = {0};
  CHECK(transport_repair_limiter_take(&limiter, 4, 100) &&
            transport_repair_limiter_take(&limiter, 4, 100) &&
            transport_repair_limiter_take(&limiter, 4, 100) &&
            transport_repair_limiter_take(&limiter, 4, 100) &&
            !transport_repair_limiter_take(&limiter, 4, 100) &&
            transport_repair_limiter_take(&limiter, 4, 350),
        "repair limiter burst and smooth refill");
  transport_repair_limiter_t cohort_limiter = {0};
  size_t cohort_accepted = 0;
  for (size_t receiver = 0; receiver < 1000; receiver++)
    cohort_accepted += transport_repair_limiter_take(
        &cohort_limiter,
        TRANSPORT_DEFAULT_MAX_AGGREGATE_REPAIR_REQUESTS_PER_SECOND, 100);
  CHECK(cohort_accepted ==
            TRANSPORT_DEFAULT_MAX_AGGREGATE_REPAIR_REQUESTS_PER_SECOND,
        "thousand-receiver repair burst is source bounded");
  size_t cohort_recovered = 0;
  for (size_t receiver = 0;
       receiver < TRANSPORT_DEFAULT_MAX_AGGREGATE_REPAIR_REQUESTS_PER_SECOND;
       receiver++)
    cohort_recovered += transport_repair_limiter_take(
        &cohort_limiter,
        TRANSPORT_DEFAULT_MAX_AGGREGATE_REPAIR_REQUESTS_PER_SECOND, 1100);
  CHECK(cohort_recovered ==
            TRANSPORT_DEFAULT_MAX_AGGREGATE_REPAIR_REQUESTS_PER_SECOND,
        "aggregate throttle refills and cannot permanently suppress recovery");

  transport_repair_suppression_t suppression = {0};
  uint16_t request_a[] = {1, 7};
  uint16_t request_b[] = {1, 8};
  uint64_t fingerprint_a =
      transport_repair_request_fingerprint(0, request_a, 2);
  uint64_t fingerprint_b =
      transport_repair_request_fingerprint(0, request_b, 2);
  CHECK(
      transport_repair_request_fingerprint(QLINQ_WIRE_NACK_RATELESS, NULL, 3) !=
          transport_repair_request_fingerprint(QLINQ_WIRE_NACK_RATELESS, NULL,
                                               4),
      "rateless suppression fingerprint includes requested deficit");
  transport_repair_suppression_record(&suppression, 9, 10, fingerprint_a, 125);
  CHECK(transport_repair_suppression_contains(&suppression, 9, 10,
                                              fingerprint_a, 124) &&
            !transport_repair_suppression_contains(&suppression, 9, 10,
                                                   fingerprint_b, 124) &&
            !transport_repair_suppression_contains(&suppression, 9, 10,
                                                   fingerprint_a, 125),
        "repair suppression is exact and expires");
  uint16_t unordered_request[] = {7, 1, 7};
  CHECK(transport_repair_normalize_indices(unordered_request, 3) == 2 &&
            unordered_request[0] == 1 && unordered_request[1] == 7 &&
            transport_repair_request_fingerprint(0, unordered_request, 2) ==
                fingerprint_a,
        "repair request normalization canonicalizes suppression keys");

  CHECK(transport_repair_build(&repair_fec_cache, cached, true, NULL, 0,
                               &repair) &&
            repair.count == cached->data_symbols,
        "whole-object repair is bounded data retransmission");
  transport_repair_batch_destroy(&repair);

  transport_t *scheduler_transport = calloc(1, sizeof(*scheduler_transport));
  CHECK(scheduler_transport != NULL, "repair scheduler allocation");
  transport_flexicast_flow_t scheduler_flow = {
      .active = true, .source = true, .track_id = cached->track_id};
  uint16_t first_request[] = {3, 1};
  uint16_t overlapping_request[] = {2, 3};
  CHECK(transport_flexicast_schedule_repair(
            scheduler_transport, &scheduler_flow, cached, 0,
            TRANSPORT_REPAIR_MODE_INDEXED, false, first_request, 2, 100) &&
            transport_flexicast_schedule_repair(
                scheduler_transport, &scheduler_flow, cached, 2,
                TRANSPORT_REPAIR_MODE_INDEXED, false, overlapping_request, 2,
                105),
        "repair requests enter aggregation holdoff");
  transport_flexicast_pending_repair_t *pending =
      &scheduler_flow.pending_repairs[0];
  CHECK(
      TRANSPORT_FLEXICAST_REPAIR_HOLDOFF_MS == QLINQ_FEC_NACK_DELAY_MS &&
          scheduler_flow.pending_repair_count == 1 && pending->active &&
          pending->ready_at_ms == 100 + TRANSPORT_FLEXICAST_REPAIR_HOLDOFF_MS &&
          (pending->requested_symbols[0] &
           ((UINT64_C(1) << 1U) | (UINT64_C(1) << 2U) | (UINT64_C(1) << 3U))) ==
              ((UINT64_C(1) << 1U) | (UINT64_C(1) << 2U) |
               (UINT64_C(1) << 3U)) &&
          scheduler_transport->stats.repair_requests_merged == 1,
      "repair aggregation spans minimum NACK backoff without extending holdoff");
  CHECK(pending->intent_id != 0 && pending->retained_requesters == 2 &&
            pending->retained_deficit_sum == 4 &&
            pending->shared_useful_requesters == 2 &&
            scheduler_flow.repair_requester_count == 2,
        "repair aggregation retains bounded stable requester identities");
  uint16_t reduced_request = 1;
  CHECK(
      transport_flexicast_schedule_repair(
          scheduler_transport, &scheduler_flow, cached, 0,
          TRANSPORT_REPAIR_MODE_INDEXED, false, &reduced_request, 1, 106) &&
          pending->retained_requesters == 2 &&
          pending->retained_deficit_sum == 3 &&
          scheduler_transport->stats.repair_requester_updates == 1,
      "repeat requester demand updates in place and records deficit progress");
  sent_object_cache_t scheduled_object = *cached;
  for (size_t i = 1; i < TRANSPORT_FLEXICAST_PENDING_REPAIRS; i++) {
    scheduled_object.object_id = 100 + i;
    CHECK(transport_flexicast_schedule_repair(
              scheduler_transport, &scheduler_flow, &scheduled_object, i + 10U,
              TRANSPORT_REPAIR_MODE_INDEXED, false, first_request, 2, 100),
          "bounded repair pending set fill");
  }
  scheduled_object.object_id++;
  CHECK(!transport_flexicast_schedule_repair(
            scheduler_transport, &scheduler_flow, &scheduled_object, 100,
            TRANSPORT_REPAIR_MODE_INDEXED, false, first_request, 2, 100) &&
            scheduler_flow.pending_repair_count ==
                TRANSPORT_FLEXICAST_PENDING_REPAIRS &&
            scheduler_transport->stats.repair_queue_backpressure == 1,
        "repair pending set rejects overflow with backpressure");
  scheduler_transport->flexicast.flows = &scheduler_flow;
  scheduler_transport->flexicast.capacity = 1;
  scheduler_transport->repair_shadow_log = tmpfile();
  CHECK(scheduler_transport->repair_shadow_log != NULL,
        "shadow observation fixture log");
  transport_flexicast_observe_repair_request(
      scheduler_transport, &scheduler_flow, cached, 1,
      TRANSPORT_REPAIR_MODE_INDEXED, false, first_request, 2,
      TRANSPORT_FLEXICAST_OBS_ACCEPTED, 120);
  transport_flexicast_observe_repair_request(
      scheduler_transport, &scheduler_flow, cached, 2,
      TRANSPORT_REPAIR_MODE_INDEXED, false, overlapping_request, 2,
      TRANSPORT_FLEXICAST_OBS_SUPPRESSED, 130);
  CHECK(scheduler_flow.shadow_observation_count == 1 &&
            scheduler_flow.shadow_requester_count == 2 &&
            scheduler_flow.shadow_observations[0].accepted_requests == 1 &&
            scheduler_flow.shadow_observations[0].suppressed_requests == 1 &&
            scheduler_flow.shadow_observations[0].ready_at_ms ==
                120 + TRANSPORT_FLEXICAST_SHADOW_OBSERVATION_MS,
        "shadow observation independently retains accepted and suppressed demand");
  scheduler_flow.repair_queued[0] =
      (transport_flexicast_queued_payload_t){.data = malloc(1),
                                             .size = 1,
                                             .group_id = cached->group_id,
                                             .object_id = cached->object_id,
                                             .symbol_index = 1};
  scheduler_flow.repair_queued[1] =
      (transport_flexicast_queued_payload_t){.data = malloc(1),
                                             .size = 1,
                                             .group_id = cached->group_id,
                                             .object_id = 1000,
                                             .symbol_index = 7};
  CHECK(scheduler_flow.repair_queued[0].data &&
            scheduler_flow.repair_queued[1].data,
        "repair cancellation fixture allocation");
  scheduler_flow.repair_queue_count = 2;
  scheduler_flow.repair_queue_bytes = 2;
  scheduled_object.object_id = 1000;
  uint16_t already_queued = 7;
  CHECK(transport_flexicast_schedule_repair(
            scheduler_transport, &scheduler_flow, &scheduled_object, 101,
            TRANSPORT_REPAIR_MODE_INDEXED, false, &already_queued, 1, 110) &&
            scheduler_flow.pending_repair_count ==
                TRANSPORT_FLEXICAST_PENDING_REPAIRS &&
            scheduler_transport->stats.repair_requests_merged == 3,
        "materialized repair suppresses duplicate scheduling");
  CHECK(transport_flexicast_cancel_repairs_through(
            scheduler_transport, &cached->track_id, cached->group_id,
            cached->object_id) == 4 &&
            scheduler_flow.pending_repair_count ==
                TRANSPORT_FLEXICAST_PENDING_REPAIRS - 1U &&
            scheduler_flow.repair_queue_count == 1 &&
            scheduler_flow.repair_queue_bytes == 1 &&
            scheduler_flow.repair_queued[0].object_id == 1000 &&
            scheduler_transport->stats.repair_packets_cancelled == 1 &&
            scheduler_transport->stats.repair_pending_symbols_cancelled == 3,
        "checkpoint release cancels and compacts obsolete repairs");
  scheduler_flow.recent_repairs[0] =
      (transport_flexicast_recent_repair_t){.active = true,
                                            .group_id = cached->group_id,
                                            .object_id = 2000,
                                            .symbol_index = 9,
                                            .expires_at_ms = 200};
  scheduled_object.object_id = 2000;
  uint16_t recently_sent = 9;
  CHECK(transport_flexicast_schedule_repair(
            scheduler_transport, &scheduler_flow, &scheduled_object, 102,
            TRANSPORT_REPAIR_MODE_INDEXED, false, &recently_sent, 1, 150) &&
            scheduler_flow.pending_repair_count ==
                TRANSPORT_FLEXICAST_PENDING_REPAIRS - 1U &&
            transport_flexicast_schedule_repair(
                scheduler_transport, &scheduler_flow, &scheduled_object, 102,
                TRANSPORT_REPAIR_MODE_INDEXED, false, &recently_sent, 1, 201) &&
            scheduler_flow.pending_repair_count ==
                TRANSPORT_FLEXICAST_PENDING_REPAIRS,
        "recent physical repair delays but does not prevent reissue");
  CHECK(transport_flexicast_cancel_track_repairs(scheduler_transport,
                                                 &cached->track_id) > 0 &&
            scheduler_flow.pending_repair_count == 0 &&
            scheduler_flow.shadow_observation_count == 0 &&
            scheduler_flow.shadow_requester_count == 0 &&
            scheduler_flow.repair_queue_count == 0 &&
            scheduler_flow.repair_queue_bytes == 0 &&
            scheduler_transport->stats.repair_packets_cancelled == 2,
        "track release cancels all remaining repair work");

  transport_flexicast_flow_t rateless_flow = {
      .active = true, .source = true, .track_id = rateless_track};
  rateless_cached->next_repair_symbol = rateless_cached->total_symbols;
  CHECK(transport_flexicast_schedule_repair(
            scheduler_transport, &rateless_flow, rateless_cached, 201,
            TRANSPORT_REPAIR_MODE_RATELESS, false, NULL, 3, 300) &&
            transport_flexicast_schedule_repair(
                scheduler_transport, &rateless_flow, rateless_cached, 202,
                TRANSPORT_REPAIR_MODE_RATELESS, false, NULL, 5, 305) &&
            rateless_flow.pending_repair_count == 1 &&
            rateless_flow.pending_repairs[0].requested_dof == 5 &&
            scheduler_transport->stats.repair_requests_merged >= 3,
        "rateless aggregation takes the maximum receiver deficit");

  transport_flexicast_flow_t covered_rateless_flow = {.active = true,
                                                      .source = true,
                                                      .track_id =
                                                          rateless_track,
                                                      .repair_queue_count = 3};
  for (size_t i = 0; i < covered_rateless_flow.repair_queue_count; i++) {
    covered_rateless_flow.repair_queued[i].group_id = object.group_id;
    covered_rateless_flow.repair_queued[i].object_id = object.object_id;
    covered_rateless_flow.repair_queued[i].repair_mode =
        TRANSPORT_REPAIR_MODE_RATELESS;
  }
  bool duplicates_bounded = true;
  for (size_t i = 0; i < 1000; i++)
    duplicates_bounded &= transport_flexicast_schedule_repair(
        scheduler_transport, &covered_rateless_flow, rateless_cached, i + 1U,
        TRANSPORT_REPAIR_MODE_RATELESS, false, NULL, 3, 310);
  CHECK(duplicates_bounded && covered_rateless_flow.pending_repair_count == 0 &&
            covered_rateless_flow.repair_queue_count == 3,
        "queued rateless degrees of freedom bound duplicate requests");

  transport_flexicast_flow_t mixed_mode_flow = {
      .active = true, .source = true, .track_id = rateless_track};
  uint16_t mixed_index = 1;
  CHECK(transport_flexicast_schedule_repair(
            scheduler_transport, &mixed_mode_flow, rateless_cached, 301,
            TRANSPORT_REPAIR_MODE_INDEXED, false, &mixed_index, 1, 320) &&
            transport_flexicast_schedule_repair(
                scheduler_transport, &mixed_mode_flow, rateless_cached, 302,
                TRANSPORT_REPAIR_MODE_RATELESS, false, NULL, 2, 320) &&
            mixed_mode_flow.pending_repair_count == 2 &&
            mixed_mode_flow.pending_repairs[0].mode !=
                mixed_mode_flow.pending_repairs[1].mode,
        "mixed-capability members retain separate repair intents");

  transport_flexicast_flow_t concentrated_flow = {
      .active = true, .source = true, .track_id = rateless_track};
  bool concentrated_bounded = true;
  for (size_t member = 1;
       member <= TRANSPORT_FLEXICAST_REPAIR_REQUESTERS + 176U; member++)
    concentrated_bounded &= transport_flexicast_schedule_repair(
        scheduler_transport, &concentrated_flow, rateless_cached, member,
        TRANSPORT_REPAIR_MODE_RATELESS, false, NULL, 3, 400);
  pending = &concentrated_flow.pending_repairs[0];
  CHECK(concentrated_bounded && concentrated_flow.pending_repair_count == 1 &&
            concentrated_flow.repair_requester_count ==
                TRANSPORT_FLEXICAST_REPAIR_REQUESTERS &&
            concentrated_flow.repair_requester_capacity ==
                TRANSPORT_FLEXICAST_REPAIR_REQUESTERS &&
            pending->retained_requesters ==
                TRANSPORT_FLEXICAST_REPAIR_REQUESTERS &&
            pending->overflow_requests == 176 &&
            pending->overflow_deficit_sum == 176U * 3U &&
            pending->requested_dof == 3,
        "concentrated 1,000-plus member demand retains a bounded sparse sample "
        "without inflating rateless repair");
  scheduler_transport->flexicast.flows = &concentrated_flow;
  scheduler_transport->flexicast.capacity = 1;
  CHECK(transport_flexicast_cancel_track_repairs(scheduler_transport,
                                                 &rateless_track) == 3 &&
            concentrated_flow.repair_requester_count == 0,
        "repair checkpoint expiry releases requester records with the intent");

  transport_flexicast_flow_t dispersed_flow = {
      .active = true, .source = true, .track_id = cached->track_id};
  bool dispersed_bounded = true;
  for (size_t member = 1; member <= 1000; member++) {
    scheduled_object = *cached;
    scheduled_object.object_id =
        5000U + member % TRANSPORT_FLEXICAST_PENDING_REPAIRS;
    uint16_t missing_symbol = (uint16_t)(member % 8U);
    dispersed_bounded &= transport_flexicast_schedule_repair(
        scheduler_transport, &dispersed_flow, &scheduled_object, member,
        TRANSPORT_REPAIR_MODE_INDEXED, false, &missing_symbol, 1, 500);
  }
  CHECK(dispersed_bounded &&
            dispersed_flow.pending_repair_count ==
                TRANSPORT_FLEXICAST_PENDING_REPAIRS &&
            dispersed_flow.repair_requester_count == 1000 &&
            dispersed_flow.repair_requester_capacity <=
                TRANSPORT_FLEXICAST_REPAIR_REQUESTERS,
        "dispersed thousand-member loss scales with active demand and bounded "
        "intents");
  for (size_t member = 1001; member <= 1050; member++) {
    scheduled_object = *cached;
    scheduled_object.object_id =
        5000U + member % TRANSPORT_FLEXICAST_PENDING_REPAIRS;
    uint16_t missing_symbol = (uint16_t)(member % 8U);
    dispersed_bounded &= transport_flexicast_schedule_repair(
        scheduler_transport, &dispersed_flow, &scheduled_object, member,
        TRANSPORT_REPAIR_MODE_INDEXED, false, &missing_symbol, 1, 501);
  }
  CHECK(dispersed_bounded &&
            dispersed_flow.repair_requester_count ==
                TRANSPORT_FLEXICAST_REPAIR_REQUESTERS &&
            scheduler_transport->stats.repair_requester_overflow >= 202 &&
            scheduler_transport->stats.repair_requester_records_peak ==
                TRANSPORT_FLEXICAST_REPAIR_REQUESTERS,
        "requester metadata overflow preserves aggregate repair scheduling");
  scheduler_transport->flexicast.flows = &dispersed_flow;
  CHECK(transport_flexicast_cancel_track_repairs(scheduler_transport,
                                                 &cached->track_id) > 0 &&
            dispersed_flow.repair_requester_count == 0,
        "dispersed requester state expires at checkpoint release");

  free(scheduler_flow.repair_requesters);
  free(rateless_flow.repair_requesters);
  free(covered_rateless_flow.repair_requesters);
  free(mixed_mode_flow.repair_requesters);
  free(concentrated_flow.repair_requesters);
  free(dispersed_flow.repair_requesters);
  fclose(scheduler_transport->repair_shadow_log);
  free(scheduler_transport);

  transport_fec_cache_destroy(&repair_fec_cache);
  transport_sent_cache_destroy(&sent_cache);
  transport_sent_cache_destroy(&rateless_cache);

  transport_sent_cache_t bounded_cache = {0};
  object.object_id = 0;
  CHECK(transport_sent_cache_store(&bounded_cache, &object, 3, 2, 2, false),
        "bounded sent-object cache initial insert");
  sent_object_cache_t *retry_entry = transport_sent_cache_find(
      &bounded_cache, &object.track_id, object.group_id, object.object_id);
  CHECK(retry_entry &&
            transport_sent_cache_store(&bounded_cache, &object, 4, 2, 2,
                                       false) &&
            transport_sent_cache_find(&bounded_cache, &object.track_id,
                                      object.group_id, object.object_id) ==
                retry_entry &&
            retry_entry->total_symbols == 4 &&
            retry_entry->next_repair_symbol == 4,
        "partial publication retry updates one recovery-cache entry");
  for (uint64_t object_id = 1; object_id < TRANSPORT_SENT_CACHE_SIZE;
       object_id++) {
    object.object_id = object_id;
    CHECK(transport_sent_cache_store(&bounded_cache, &object, 3, 2, 2, false),
          "bounded sent-object cache fill");
  }
  object.object_id = TRANSPORT_SENT_CACHE_SIZE;
  CHECK(
      !transport_sent_cache_has_space(&bounded_cache) &&
          !transport_sent_cache_store(&bounded_cache, &object, 3, 2, 2, false),
      "unacknowledged cache refuses overwrite");
  CHECK(transport_sent_cache_release_through(&bounded_cache, &track, 10, 127) ==
                128 &&
            transport_sent_cache_has_space(&bounded_cache) &&
            transport_sent_cache_store(&bounded_cache, &object, 3, 2, 2, false),
        "checkpoint release restores bounded cache capacity");
  transport_sent_cache_destroy(&bounded_cache);

  /* Entry limits alone admit 256 MiB of retained source payload. Exercise
   * byte pressure well before the entry limit, preserving required repairs. */
  uint8_t *large_payload = malloc(1024U * 1024U);
  CHECK(large_payload != NULL, "source-cache byte-budget fixture allocation");
  memset(large_payload, 0x5a, 1024U * 1024U);
  moq_object_t large_object = object;
  large_object.data = large_payload;
  large_object.size = 1024U * 1024U;
  for (size_t i = 0; i < 16; i++) {
    large_object.object_id = i;
    CHECK(transport_sent_cache_store(&bounded_cache, &large_object, 1024, 1024,
                                     1024, false),
          "source-cache byte-budget fill");
  }
  CHECK(bounded_cache.payload_bytes == TRANSPORT_DEFAULT_RECOVERY_CACHE_BYTES &&
            bounded_cache.peak_payload_bytes ==
                TRANSPORT_DEFAULT_RECOVERY_CACHE_BYTES &&
            bounded_cache.count == 16 && bounded_cache.peak_count == 16,
        "source-cache allocation counters include the full retained payload");
  large_object.object_id = 0;
  sent_object_cache_t *full_retry =
      transport_sent_cache_find(&bounded_cache, &large_object.track_id,
                                large_object.group_id, large_object.object_id);
  CHECK(transport_sent_cache_can_store(&bounded_cache, &large_object, false) &&
            transport_sent_cache_store(&bounded_cache, &large_object, 1024,
                                       1024, 1024, false) &&
            transport_sent_cache_find(&bounded_cache, &large_object.track_id,
                                      large_object.group_id, 0) == full_retry &&
            bounded_cache.payload_bytes ==
                TRANSPORT_DEFAULT_RECOVERY_CACHE_BYTES &&
            bounded_cache.count == 16,
        "a retry at the byte limit reuses its retained allocation");
  large_payload[0] ^= 1;
  CHECK(!transport_sent_cache_can_store(&bounded_cache, &large_object, false) &&
            !transport_sent_cache_store(&bounded_cache, &large_object, 1024,
                                        1024, 1024, false),
        "conflicting identity cannot replace a protected source object");
  large_payload[0] ^= 1;
  large_object.object_id = 16;
  CHECK(!transport_sent_cache_store(&bounded_cache, &large_object, 1024, 1024,
                                    1024, false),
        "source cache must backpressure at 16 MiB before its entry limit");
  CHECK(!transport_sent_cache_store(&bounded_cache, &large_object, 1024, 1024,
                                    1024, true),
        "byte pressure cannot evict protected source objects");
  CHECK(transport_sent_cache_release_through(&bounded_cache,
                                             &large_object.track_id,
                                             large_object.group_id, 0) == 1 &&
            transport_sent_cache_store(&bounded_cache, &large_object, 1024,
                                       1024, 1024, false),
        "checkpoint release restores source-cache byte admission");
  transport_sent_cache_destroy(&bounded_cache);
  CHECK(bounded_cache.payload_bytes == 0 && bounded_cache.count == 0,
        "source-cache destruction clears retained allocation accounting");

  for (size_t i = 0; i < 15; i++) {
    large_object.object_id = i;
    CHECK(transport_sent_cache_store(&bounded_cache, &large_object, 1024, 1024,
                                     1024, false),
          "mixed source-cache protected fill");
  }
  large_object.size = 256U * 1024U;
  for (size_t i = 15; i < 19; i++) {
    large_object.object_id = i;
    CHECK(transport_sent_cache_store(&bounded_cache, &large_object, 256, 256,
                                     1024, true),
          "mixed source-cache best-effort fill");
  }
  large_object.object_id = 19;
  large_object.size = 1024U * 1024U;
  CHECK(
      !transport_sent_cache_can_store(&bounded_cache, &large_object, false) &&
          transport_sent_cache_can_store(&bounded_cache, &large_object, true) &&
          transport_sent_cache_store(&bounded_cache, &large_object, 1024, 1024,
                                     1024, true) &&
          bounded_cache.payload_bytes ==
              TRANSPORT_DEFAULT_RECOVERY_CACHE_BYTES &&
          bounded_cache.peak_payload_bytes ==
              TRANSPORT_DEFAULT_RECOVERY_CACHE_BYTES &&
          bounded_cache.count == 16 && bounded_cache.peak_count == 19,
      "best-effort replacement reclaims multiple payloads within the byte cap");
  for (size_t i = 0; i < 19; i++)
    CHECK((transport_sent_cache_find(&bounded_cache, &large_object.track_id,
                                     large_object.group_id, i) != NULL) ==
              (i < 15),
          "byte reclamation preserves every protected recovery object");
  large_object.data =
      transport_sent_cache_find(&bounded_cache, &large_object.track_id,
                                large_object.group_id, 19)
          ->data;
  large_object.object_id = 20;
  CHECK(!transport_sent_cache_can_store(&bounded_cache, &large_object, true) &&
            !transport_sent_cache_store(&bounded_cache, &large_object, 1024,
                                        1024, 1024, true) &&
            large_object.data[0] == 0x5a && bounded_cache.count == 16,
        "replacement cannot reclaim its own borrowed source allocation");
  large_object.data = large_payload;
  CHECK(transport_sent_cache_release_track(&bounded_cache,
                                           &large_object.track_id) == 16 &&
            bounded_cache.payload_bytes == 0 && bounded_cache.count == 0 &&
            bounded_cache.peak_payload_bytes ==
                TRANSPORT_DEFAULT_RECOVERY_CACHE_BYTES,
        "track release clears current usage and preserves its high-water mark");
  large_object.object_id = 20;
  large_object.size = (size_t)TRANSPORT_DEFAULT_RECOVERY_CACHE_BYTES + 1;
  CHECK(!transport_sent_cache_can_store(&bounded_cache, &large_object, true) &&
            !transport_sent_cache_store(&bounded_cache, &large_object, 1, 1, 1,
                                        true),
        "oversized cache payload fails before reading or allocating its data");
  transport_sent_cache_destroy(&bounded_cache);
  free(large_payload);

  bounded_cache.max_payload_bytes = 6;
  object.size = 4;
  object.object_id = 1000;
  CHECK(transport_sent_cache_store(&bounded_cache, &object, 2, 2, 2, false),
        "custom cache budget");
  object.object_id++;
  CHECK(!transport_sent_cache_store(&bounded_cache, &object, 2, 2, 2, false),
        "custom byte cap enforced");
  transport_sent_cache_destroy(&bounded_cache);

  configured = (transport_limits_t){.max_fec_object_size = 32,
                                    .max_recovery_cache_bytes = 32};
  CHECK(!transport_limits_resolve(&configured, &resolved_limits, limit_error,
                                  sizeof(limit_error)),
        "cache limit cannot prevent reaching one rolling checkpoint");
  configured.max_recovery_cache_bytes = 32 * TRANSPORT_RECOVERY_WINDOW_OBJECTS;
  CHECK(transport_limits_resolve(&configured, &resolved_limits, limit_error,
                                 sizeof(limit_error)) &&
            resolved_limits.max_recovery_cache_bytes ==
                configured.max_recovery_cache_bytes,
        "custom recovery byte limit resolves");
  transport_fec_cache_t fec_cache = {0};
  fec_t *fec = transport_fec_cache_get(&fec_cache, FEC_REED_SOLOMON, 2, 1, 8);
  CHECK(fec != NULL, "FEC cache creation");
  CHECK(transport_fec_cache_get(&fec_cache, FEC_REED_SOLOMON, 2, 1, 8) == fec,
        "FEC cache reuse");
  transport_fec_cache_destroy(&fec_cache);

  printf("===TRANSPORT COMPONENTS OK===\n");
  return 0;
}
