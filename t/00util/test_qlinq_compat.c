#include "qlinq.h"
#include "transport_internal.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct {
  transport_t *transport;
  transport_conn_t *conn;
  unsigned received;
  uint8_t flags;
  uint8_t payload[27];
} legacy_t;

static void legacy_event(void *data, const transport_event_t *event) {
  legacy_t *legacy = data;
  if (event->type == TRANSPORT_EVENT_AUTH) {
    assert(event->auth.token_len == 6 &&
           memcmp(event->auth.token, "secret", 6) == 0);
    assert(transport_respond_auth(legacy->transport, event->conn, true));
    legacy->conn = event->conn;
    moq_track_id_t track = {
        .type = MOQ_TRACK_DATA, .flags = legacy->flags, .name = "compat"};
    assert(transport_subscribe_conn(legacy->transport, event->conn, track));
  } else if (event->type == TRANSPORT_EVENT_OBJECT) {
    size_t prefix = (legacy->flags &
                     (MOQ_TRACK_FLAG_FEC_ENABLED | MOQ_TRACK_FLAG_FEC_RATELESS))
                        ? 2
                        : 0;
    assert(event->object.size == sizeof(legacy->payload) + prefix);
    assert(memcmp(event->object.data + prefix, legacy->payload,
                  sizeof(legacy->payload)) == 0);
    legacy->received++;
  }
}

static void run(qlinq_delivery_t mode, uint8_t flags) {
  legacy_t legacy = {.flags = flags, .payload = {'Q', 'S', 'R', 1}};
  /* Looks like the old wrapper's private envelope. It must remain payload. */
  legacy.payload[25] = 1;
  legacy.payload[26] = 'x';
  transport_config_t tc = {.bind_hosts = {"127.0.0.1"},
                           .num_bind_hosts = 1,
                           .port = 19937,
                           .cert_file = "t/assets/server.crt",
                           .key_file = "t/assets/server.key",
                           .allow_insecure_peer = true,
                           .callback = legacy_event,
                           .user_data = &legacy};
  legacy.transport = transport_create(&tc);
  assert(legacy.transport);
  qlinq_context_t *ctx = qlinq_context_create(NULL);
  assert(ctx);
  qlinq_endpoint_config_t config = {.bind_addresses = {"127.0.0.1"},
                                    .bind_address_count = 1,
                                    .remote_addresses = {"127.0.0.1"},
                                    .remote_address_count = 1,
                                    .port = 19937,
                                    .security = {.shared_secret = "secret",
                                                 .shared_secret_size = 6,
                                                 .allow_insecure_peer = true}};
  qlinq_endpoint_t *ep = qlinq_connect(ctx, &config);
  assert(ep);
  qlinq_stream_config_t sc = {
      .content_type = QLINQ_CONTENT_DATA, .delivery = mode, .name = "compat"};
  qlinq_stream_t *pub = qlinq_publish(ep, &sc), *sub = qlinq_subscribe(ep, &sc);
  assert(pub && sub);
  bool ready = false, joined = false;
  qlinq_event_t held = {0};
  for (size_t i = 0; i < 2000; i++) {
    transport_tick(legacy.transport);
    assert(qlinq_service(ctx, 1) >= QLINQ_STATUS_OK);
    qlinq_event_t event;
    while (qlinq_next_event(ctx, &event)) {
      if (event.type == QLINQ_EVENT_PEER_READY) {
        qlinq_peer_info_t info;
        assert(qlinq_endpoint_get_peer(ep, event.peer_id, &info));
        assert(info.ready && info.outgoing && info.authenticated);
        ready = true;
      }
      if (event.type == QLINQ_EVENT_SUBSCRIBER_JOINED)
        joined = true;
      qlinq_event_release(&event);
    }
    transport_track_stats_t stats;
    moq_track_id_t track = {
        .type = MOQ_TRACK_DATA, .flags = flags, .name = "compat"};
    assert(transport_get_track_stats(legacy.transport, &track, &stats));
    if (ready && joined && stats.subscribers == 1)
      break;
  }
  assert(ready && joined && qlinq_stream_is_writable(pub));
  qlinq_record_t record = {.group_id = 1,
                           .sequence = 2,
                           .data = legacy.payload,
                           .size = sizeof(legacy.payload)};
  qlinq_send_result_t sent = qlinq_stream_send(pub, &record);
  assert(sent == QLINQ_SEND_SENT || sent == QLINQ_SEND_BUFFERED);
  moq_object_t object = {
      .track_id = {.type = MOQ_TRACK_DATA, .flags = flags, .name = "compat"},
      .group_id = 2,
      .object_id = 3,
      .data = legacy.payload,
      .size = sizeof(legacy.payload)};
  assert(transport_publish(legacy.transport, &object));
  for (size_t i = 0; i < 2000 && (!held._private || !legacy.received); i++) {
    transport_tick(legacy.transport);
    assert(qlinq_service(ctx, 1) >= QLINQ_STATUS_OK);
    qlinq_event_t event;
    while (qlinq_next_event(ctx, &event)) {
      if (event.type == QLINQ_EVENT_RECORD) {
        assert(!held._private && event.stream == sub);
        assert(event.record.size == sizeof(legacy.payload));
        assert(memcmp(event.record.data, legacy.payload,
                      sizeof(legacy.payload)) == 0);
        held = event;
      } else
        qlinq_event_release(&event);
    }
  }
  assert(held._private && legacy.received == 1);
  qlinq_stream_stats_t stats;
  assert(qlinq_stream_get_stats(pub, &stats) && stats.subscribers == 1 &&
         stats.records_sent == 1);
  qlinq_stream_close(sub);
  record.sequence++;
  sent = qlinq_stream_send(pub, &record);
  assert(sent == QLINQ_SEND_SENT || sent == QLINQ_SEND_BUFFERED);
  for (size_t i = 0; i < 2000 && legacy.received < 2; i++) {
    transport_tick(legacy.transport);
    assert(qlinq_service(ctx, 1) >= QLINQ_STATUS_OK);
    qlinq_event_t event;
    while (qlinq_next_event(ctx, &event))
      qlinq_event_release(&event);
  }
  assert(legacy.received ==
         2); /* Removing the reverse subscription is independent. */
  qlinq_stream_close(pub);
  assert(!qlinq_stream_is_writable(pub) &&
         qlinq_stream_send(pub, &record) == QLINQ_SEND_INVALID);
  assert(qlinq_stream_get_stats(pub, &stats) &&
         stats.state == QLINQ_STREAM_CLOSED);
  assert(qlinq_endpoint_shutdown(ep, "done") == QLINQ_STATUS_OK);
  for (size_t i = 0; i < 2000 && !qlinq_endpoint_is_drained(ep); i++) {
    transport_tick(legacy.transport);
    assert(qlinq_service(ctx, 1) >= QLINQ_STATUS_OK);
    qlinq_event_t event;
    while (qlinq_next_event(ctx, &event))
      qlinq_event_release(&event);
  }
  assert(qlinq_endpoint_is_drained(ep));
  qlinq_endpoint_close(ep);
  qlinq_context_destroy(ctx);
  assert(held.record.size == sizeof(legacy.payload) &&
         memcmp(held.record.data, legacy.payload, sizeof(legacy.payload)) == 0);
  qlinq_event_release(&held);
  transport_destroy(legacy.transport);
}

int main(void) {
  run(QLINQ_DELIVERY_DATAGRAM, 0);
  run(QLINQ_DELIVERY_RELIABLE, MOQ_TRACK_FLAG_RELIABLE);
  run(QLINQ_DELIVERY_FIXED_FEC, MOQ_TRACK_FLAG_FEC_ENABLED);
  run(QLINQ_DELIVERY_RATELESS, MOQ_TRACK_FLAG_FEC_RATELESS);
  puts("===QLINQ COMPATIBILITY OK===");
  return 0;
}
