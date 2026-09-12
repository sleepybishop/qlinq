#include "qlinq.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

typedef struct {
  qlinq_context_t *ctx[2];
  qlinq_endpoint_t *endpoint[2];
  qlinq_stream_t *publisher, *receiver;
  size_t ready, received;
  bool injecting, overflow, disconnected;
  bool count_pressure, hold_receiver_events;
} fixture_t;

static int64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool pump(fixture_t *f) {
  for (size_t node = 0; node < 2; node++) {
    qlinq_status_t status = qlinq_service(f->ctx[node], 2);
    if (status < QLINQ_STATUS_OK) {
      if (node != 1 || !f->injecting || status != QLINQ_STATUS_RESOURCE_LIMIT)
        return false;
      f->overflow = true;
    }
    if (node == 1 && f->hold_receiver_events)
      continue;
    qlinq_event_t e;
    while (qlinq_next_event(f->ctx[node], &e)) {
      bool valid = true;
      switch (e.type) {
      case QLINQ_EVENT_PEER_READY:
        f->ready++;
        break;
      case QLINQ_EVENT_ERROR:
        valid = node == 1 && f->injecting &&
                e.status == QLINQ_STATUS_RESOURCE_LIMIT;
        if (valid)
          f->overflow = true;
        break;
      case QLINQ_EVENT_PEER_DISCONNECTED:
        valid = f->injecting;
        if (node == 0) {
          valid &= e.disconnect.remote && e.disconnect.application_error &&
                   e.disconnect.error_code == 0x102;
          f->disconnected = true;
        }
        break;
      case QLINQ_EVENT_RECORD:
        valid = node == 1;
        if (f->received == 0) {
          valid &= e.record.size == 4 && memcmp(e.record.data, "warm", 4) == 0;
        } else {
          valid &= f->count_pressure && f->injecting && e.record.size == 64;
          for (size_t i = 0; valid && i < e.record.size; ++i)
            valid &= ((const uint8_t *)e.record.data)[i] == 0x5a;
        }
        f->received++;
        break;
      case QLINQ_EVENT_PEER_REJECTED:
      case QLINQ_EVENT_RECORD_LOST:
        valid = false;
        break;
      default:
        break;
      }
      qlinq_event_release(&e);
      if (!valid)
        return false;
    }
  }
  return true;
}

/* Saturate bytes with one large record, or count with several small records
 * while servicing transport without consuming application events. Decode can
 * complete, but rejected application records cannot produce successful
 * receipts. */
static int run(qlinq_delivery_t delivery, bool count_pressure) {
  fixture_t f = {.count_pressure = count_pressure};
  int result = 1;
#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "event overflow delivery=%d count=%d line=%d: %s\n",     \
              delivery, count_pressure, __LINE__, #condition);                 \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)
  static const uint8_t secret[] = "event-overflow-test";
  qlinq_endpoint_config_t config = {
      .bind_addresses = {"127.0.0.1"},
      .bind_address_count = 1,
      .idle_timeout_ms = 2000,
      .security = {.shared_secret = secret,
                   .shared_secret_size = sizeof(secret),
                   .certificate_file = "t/assets/server.crt",
                   .private_key_file = "t/assets/server.key",
                   .allow_insecure_peer = true},
      .limits = {.max_connections = 1, .max_subscriptions_per_peer = 1}};
  for (size_t node = 0; node < 2; node++) {
    qlinq_context_config_t context = {.max_queued_events =
                                          count_pressure ? 4 : 256,
                                      .max_queued_event_bytes = 32768};
    f.ctx[node] = qlinq_context_create(node == 1 ? &context : NULL);
    CHECK(f.ctx[node]);
    config.port = 19836;
    if (node == 1) {
      config.remote_addresses[0] = "127.0.0.1";
      config.remote_address_count = 1;
    }
    f.endpoint[node] = node == 0 ? qlinq_listen(f.ctx[node], &config)
                                 : qlinq_connect(f.ctx[node], &config);
    CHECK(f.endpoint[node]);
  }
  int64_t deadline = now_ms() + 10000;
  while (f.ready < 2 && now_ms() < deadline)
    CHECK(pump(&f));
  CHECK(f.ready == 2);
  qlinq_stream_config_t stream = {.name = "bounded-events",
                                  .content_type = QLINQ_CONTENT_DATA,
                                  .delivery = delivery};
  f.publisher = qlinq_publish(f.endpoint[0], &stream);
  f.receiver = qlinq_subscribe(f.endpoint[1], &stream);
  CHECK(f.publisher && f.receiver);
  bool admitted = false;
  deadline = now_ms() + 10000;
  while (!admitted && now_ms() < deadline) {
    CHECK(pump(&f));
    qlinq_stream_stats_t stats;
    CHECK(qlinq_stream_get_stats(f.publisher, &stats));
    admitted = stats.subscribers == 1 && stats.writable;
  }
  CHECK(admitted);
  qlinq_record_t record = {.sequence = 1, .data = "warm", .size = 4};
  qlinq_send_result_t sent = qlinq_stream_send(f.publisher, &record);
  CHECK(sent == QLINQ_SEND_SENT || sent == QLINQ_SEND_BUFFERED);
  deadline = now_ms() + 5000;
  while (f.received == 0 && now_ms() < deadline)
    CHECK(pump(&f));
  CHECK(f.received == 1);
  uint8_t payload[40000];
  memset(payload, 0x5a, sizeof(payload));
  f.injecting = true;
  f.hold_receiver_events = count_pressure;
  for (size_t i = 0; i < (count_pressure ? 8 : 1); ++i) {
    record = (qlinq_record_t){.sequence = i + 2,
                              .data = payload,
                              .size = count_pressure ? 64 : sizeof(payload)};
    sent = qlinq_stream_send(f.publisher, &record);
    CHECK(sent == QLINQ_SEND_SENT || sent == QLINQ_SEND_BUFFERED);
  }
  if (count_pressure) {
    deadline = now_ms() + 10000;
    while (!f.overflow && now_ms() < deadline)
      CHECK(pump(&f));
    CHECK(f.overflow); /* The sticky service status must work with no event
                          slot. */
    f.hold_receiver_events = false;
    CHECK(pump(&f));
  }
  deadline = now_ms() + 10000;
  while (!f.disconnected && now_ms() < deadline)
    CHECK(pump(&f));
  CHECK(f.overflow && f.disconnected);
  if (count_pressure)
    CHECK(f.received > 1 && f.received <= 5);
  else
    CHECK(f.received == 1);
  printf("event overflow delivery=%d count=%d records=%zu: explicit "
         "resource-limit close\n",
         delivery, count_pressure, f.received);
  result = 0;
cleanup:
  for (size_t node = 0; node < 2; node++)
    qlinq_context_destroy(f.ctx[node]);
  return result;
#undef CHECK
}

int main(void) {
  for (unsigned count_pressure = 0; count_pressure < 2; count_pressure++)
    if (run(QLINQ_DELIVERY_FIXED_FEC, count_pressure) ||
        run(QLINQ_DELIVERY_RATELESS, count_pressure))
      return 1;
  puts("===QLINQ EVENT OVERFLOW OK===");
  return 0;
}
