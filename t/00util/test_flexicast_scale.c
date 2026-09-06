#include "transport_flexicast.h"
#include "transport_internal.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define MEMBER_COUNT 1000U
#define MEMBER_INDEX_MEMORY_BUDGET (2U * 1024U * 1024U)
#define MEMBER_INDEX_TIME_BUDGET_NS UINT64_C(2000000000)

static uint64_t monotonic_ns(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
    return 0;
  return (uint64_t)value.tv_sec * UINT64_C(1000000000) +
         (uint64_t)value.tv_nsec;
}

int main(void) {
  transport_flexicast_flow_t flow = {.member_capacity = MEMBER_COUNT};
  max_align_t *identities =
      calloc(MEMBER_COUNT + MEMBER_COUNT / 2U + 1U, sizeof(*identities));
  if (!identities)
    return 1;
  uint64_t started_ns = monotonic_ns();

  for (size_t i = 0; i < MEMBER_COUNT; i++) {
    transport_conn_t *conn = (transport_conn_t *)&identities[i];
    transport_flexicast_member_t *member =
        transport_flexicast_member_add(&flow, conn);
    if (!member || member->conn != conn ||
        transport_flexicast_member_add(&flow, conn) != member) {
      fprintf(stderr, "member insertion failed at %zu\n", i);
      goto Fail;
    }
  }
  if (flow.member_count != MEMBER_COUNT) {
    fprintf(stderr, "unexpected member count after insertion: %zu\n",
            flow.member_count);
    goto Fail;
  }

  for (size_t i = 0; i < MEMBER_COUNT; i += 2U) {
    transport_conn_t *conn = (transport_conn_t *)&identities[i];
    transport_flexicast_member_t *member =
        transport_flexicast_member_find(&flow, conn);
    if (!member || !transport_flexicast_member_remove(NULL, &flow, member) ||
        transport_flexicast_member_find(&flow, conn)) {
      fprintf(stderr, "member removal failed at %zu\n", i);
      goto Fail;
    }
  }

  for (size_t i = 0; i < MEMBER_COUNT / 2U; i++) {
    transport_conn_t *replacement =
        (transport_conn_t *)&identities[MEMBER_COUNT + i];
    if (!transport_flexicast_member_add(&flow, replacement)) {
      fprintf(stderr, "member replacement failed at %zu\n", i);
      goto Fail;
    }
  }
  if (flow.member_count != MEMBER_COUNT ||
      transport_flexicast_member_add(
          &flow,
          (transport_conn_t *)&identities[MEMBER_COUNT + MEMBER_COUNT / 2U])) {
    fprintf(stderr, "member capacity was not enforced\n");
    goto Fail;
  }

  uint64_t finished_ns = monotonic_ns();
  size_t index_memory =
      (MEMBER_COUNT + MEMBER_COUNT / 2U + 1U) * sizeof(*identities) +
      flow.member_capacity * sizeof(*flow.members) +
      flow.member_map_capacity * sizeof(*flow.member_map);
  if (index_memory > MEMBER_INDEX_MEMORY_BUDGET || started_ns == 0 ||
      finished_ns < started_ns ||
      finished_ns - started_ns > MEMBER_INDEX_TIME_BUDGET_NS) {
    fprintf(
        stderr,
        "member index exceeded hardening budget: %zu bytes, %" PRIu64 " ns\n",
        index_memory, finished_ns >= started_ns ? finished_ns - started_ns : 0);
    goto Fail;
  }

  for (size_t i = 1; i < MEMBER_COUNT; i += 2U) {
    transport_conn_t *conn = (transport_conn_t *)&identities[i];
    if (!transport_flexicast_member_find(&flow, conn)) {
      fprintf(stderr, "surviving member lookup failed at %zu\n", i);
      goto Fail;
    }
  }

  transport_flexicast_flow_t recovery_flow = {.member_capacity = 1,
                                              .delivery_epoch = 2};
  transport_t *transport = calloc(1, sizeof(*transport));
  transport_flexicast_member_t *recovery_member =
      transport_flexicast_member_add(&recovery_flow,
                                     (transport_conn_t *)&identities[0]);
  if (!transport || !recovery_member) {
    free(transport);
    free(recovery_flow.members);
    free(recovery_flow.member_map);
    goto Fail;
  }
  recovery_member->listening = true;
  recovery_member->acknowledged_delivery_epoch = 1;
  recovery_flow.listening_count = 0;
  recovery_flow.feedback_outstanding_count = 0;
  if (!transport_flexicast_member_remove(transport, &recovery_flow,
                                         recovery_member) ||
      recovery_flow.listening_count != 0 ||
      recovery_flow.feedback_outstanding_count != 0 ||
      transport->stats.internal_state_recoveries != 1) {
    fprintf(stderr, "inconsistent counters were not recovered safely\n");
    free(transport);
    free(recovery_flow.members);
    free(recovery_flow.member_map);
    goto Fail;
  }
  free(transport);
  free(recovery_flow.members);
  free(recovery_flow.member_map);

  free(flow.members);
  free(flow.member_map);
  free(identities);
  printf("===FLEXICAST SCALE OK===\n");
  return 0;

Fail:
  free(flow.members);
  free(flow.member_map);
  free(identities);
  return 1;
}
