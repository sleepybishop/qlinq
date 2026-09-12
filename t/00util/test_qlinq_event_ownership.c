/* Exercise the real queue and public ownership operations without socket I/O.
 * Including the implementation exposes allocation charges for this audit. */
#include "../../src/common/qlinq.c"

#include <stdio.h>

#define CHECK(test)                                                            \
  do {                                                                         \
    if (!(test)) {                                                             \
      fprintf(stderr, "event ownership line %d: %s\n", __LINE__, #test);       \
      failed = 1;                                                              \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)

static bool enqueue_record(qlinq_context_t *context, uint64_t sequence) {
  uint8_t payload[64];
  memset(payload, 0x5a, sizeof(payload));
  payload[0] = (uint8_t)sequence;
  qlinq_event_t source = {
      .type = QLINQ_EVENT_RECORD,
      .record = {.sequence = sequence, .size = sizeof(payload)}};
  return queue_event(context, &source, payload, sizeof(payload), NULL);
}

static int count_and_ownership(void) {
  int failed = 0;
  qlinq_event_t held[3] = {0};
  qlinq_context_config_t config = {.max_queued_events = 2,
                                   .max_queued_event_bytes = 65536};
  qlinq_context_t *context = qlinq_context_create(&config);
  CHECK(context);
  CHECK(enqueue_record(context, 1) && enqueue_record(context, 2));
  CHECK(!enqueue_record(context, 3));
  CHECK(qlinq_context_last_status(context) == QLINQ_STATUS_RESOURCE_LIMIT);
  size_t allocation = sizeof(qlinq_event_node_t) + 64;
  CHECK(context->queued_events == 2 &&
        context->queued_event_bytes == 2 * allocation);
  CHECK(context->queued_event_bytes < config.max_queued_event_bytes);
  /* Handing events to the caller releases queue capacity. These three held
   * allocations have separate ownership from the two events still queued. */
  for (size_t i = 0; i < 3; ++i) {
    CHECK(qlinq_next_event(context, &held[i]));
    CHECK(held[i].record.sequence == i + 1);
    CHECK(context->queued_events == 1 &&
          context->queued_event_bytes == allocation);
    CHECK(enqueue_record(context, i + 3));
  }
  CHECK(context->queued_events == 2 &&
        context->queued_event_bytes == 2 * allocation);
  qlinq_context_destroy(context); /* Releases the two events still queued. */
  context = NULL;
  for (size_t i = 0; i < 3; ++i) {
    CHECK(held[i].record.size == 64 && held[i]._private != NULL);
    const uint8_t *payload = held[i].record.data;
    CHECK(payload != NULL && payload[0] == i + 1);
    for (size_t j = 1; j < 64; ++j)
      CHECK(payload[j] == 0x5a);
    qlinq_event_release(&held[i]);
    CHECK(held[i]._private == NULL && held[i].record.data == NULL);
  }
cleanup:
  qlinq_context_destroy(context);
  for (size_t i = 0; i < 3; ++i)
    qlinq_event_release(&held[i]);
  return failed;
}

static int bytes_and_message(void) {
  int failed = 0;
  char reason[81];
  memset(reason, 'r', sizeof(reason) - 1);
  reason[sizeof(reason) - 1] = '\0';
  size_t allocation = sizeof(qlinq_event_node_t) + sizeof(reason);
  qlinq_context_config_t config = {
      .max_queued_events = 8, .max_queued_event_bytes = 2 * allocation - 1};
  qlinq_context_t *context = qlinq_context_create(&config);
  qlinq_event_t source = {.type = QLINQ_EVENT_PEER_DISCONNECTED,
                          .disconnect = {.was_ready = true, .outgoing = true}},
                held = {0};
  CHECK(context);
  CHECK(queue_event(context, &source, NULL, 0, reason));
  CHECK(context->queued_event_bytes == allocation);
  CHECK(!queue_event(context, &source, NULL, 0, reason));
  CHECK(context->queued_events == 1 &&
        context->queued_events < config.max_queued_events);
  CHECK(qlinq_context_last_status(context) == QLINQ_STATUS_RESOURCE_LIMIT);
  CHECK(qlinq_next_event(context, &held));
  CHECK(context->queued_events == 0 && context->queued_event_bytes == 0);
  CHECK(queue_event(context, &source, NULL, 0, reason));
  CHECK(!queue_event(context, &source, reason, SIZE_MAX, NULL));
  CHECK(qlinq_context_last_status(context) == QLINQ_STATUS_INVALID);
  CHECK(context->queued_events == 1 &&
        context->queued_event_bytes == allocation);
  memset(reason, 'x', sizeof(reason));
  qlinq_context_destroy(context);
  context = NULL;
  CHECK(held.message != NULL && held.message == held.disconnect.reason);
  CHECK(held.disconnect.was_ready && held.disconnect.outgoing);
  CHECK(strlen(held.message) == 80);
  for (size_t i = 0; i < 80; ++i)
    CHECK(held.message[i] == 'r');
cleanup:
  qlinq_context_destroy(context);
  qlinq_event_release(&held);
  return failed;
}

int main(void) {
  for (size_t i = 0; i < 100; ++i)
    if (count_and_ownership() || bytes_and_message())
      return 1;
  puts("===QLINQ EVENT OWNERSHIP OK===");
  return 0;
}
