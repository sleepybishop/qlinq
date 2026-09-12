#include "qlinq.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition, message)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "qlinq reconnect test failed: %s\n", message);           \
      goto Cleanup;                                                            \
    }                                                                          \
  } while (0)

int main(void) {
  static const char secret[] = "qlinq-reconnect-secret";
  qlinq_context_t *context = qlinq_context_create(NULL);
  qlinq_endpoint_t *listener = NULL, *replacement = NULL, *client = NULL;
  qlinq_stream_t *publisher = NULL, *replacement_publisher = NULL;
  qlinq_stream_t *subscription = NULL;
  int result = 1;
  CHECK(context, "create context");

  qlinq_endpoint_config_t listener_config = {
      .bind_addresses = {"127.0.0.1"},
      .bind_address_count = 1,
      .port = 18992,
      .idle_timeout_ms = 500,
      .security = {.shared_secret = secret,
                   .shared_secret_size = sizeof(secret) - 1U,
                   .certificate_file = "t/assets/server.crt",
                   .private_key_file = "t/assets/server.key",
                   .allow_insecure_peer = true}};
  qlinq_endpoint_config_t client_config = {
      .bind_addresses = {"127.0.0.1"},
      .bind_address_count = 1,
      .remote_addresses = {"127.0.0.1"},
      .remote_address_count = 1,
      .port = 18992,
      .idle_timeout_ms = 500,
      .reconnect_enabled = true,
      .reconnect_initial_delay_ms = 10,
      .reconnect_max_delay_ms = 50,
      .security = {.shared_secret = secret,
                   .shared_secret_size = sizeof(secret) - 1U,
                   .allow_insecure_peer = true}};
  listener = qlinq_listen(context, &listener_config);
  client = qlinq_connect(context, &client_config);
  CHECK(listener && client, "create initial endpoints");

  qlinq_stream_config_t stream_config = {.content_type = QLINQ_CONTENT_DATA,
                                         .delivery = QLINQ_DELIVERY_FIXED_FEC,
                                         .name = "api/reconnect"};
  publisher = qlinq_publish(listener, &stream_config);
  subscription = qlinq_subscribe(client, &stream_config);
  CHECK(publisher && subscription, "create initial streams");

  bool joined = false, peer_ready = false;
  qlinq_endpoint_stats_t endpoint_stats = {0};
  for (size_t attempt = 0; attempt < 500 && !(joined && peer_ready);
       attempt++) {
    CHECK(qlinq_service(context, 10) >= QLINQ_STATUS_OK,
          "service initial connection");
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      if (event.type == QLINQ_EVENT_SUBSCRIBER_JOINED &&
          event.stream == publisher)
        joined = true;
      qlinq_event_release(&event);
    }
    if (qlinq_endpoint_get_stats(listener, &endpoint_stats))
      peer_ready = endpoint_stats.active_connections == 1;
  }
  CHECK(joined && peer_ready, "initial peer is ready");

  qlinq_endpoint_close(listener);
  listener = NULL;
  replacement = qlinq_listen(context, &listener_config);
  CHECK(replacement, "restart listener");
  replacement_publisher = qlinq_publish(replacement, &stream_config);
  CHECK(replacement_publisher, "recreate publishing stream");

  bool disconnected_with_reason = false, rejoined = false;
  peer_ready = false;
  for (size_t attempt = 0; attempt < 1000 && !(rejoined && peer_ready);
       attempt++) {
    CHECK(qlinq_service(context, 10) >= QLINQ_STATUS_OK, "service reconnect");
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      if (event.type == QLINQ_EVENT_PEER_DISCONNECTED &&
          event.endpoint == client && event.disconnect.reason &&
          event.disconnect.reason[0] != '\0')
        disconnected_with_reason = true;
      if (event.type == QLINQ_EVENT_SUBSCRIBER_JOINED &&
          event.stream == replacement_publisher)
        rejoined = true;
      qlinq_event_release(&event);
    }
    if (qlinq_endpoint_get_stats(replacement, &endpoint_stats))
      peer_ready = endpoint_stats.active_connections == 1;
  }
  CHECK(rejoined && disconnected_with_reason,
        "client reconnects and exposes the disconnect cause");
  CHECK(qlinq_endpoint_get_stats(client, &endpoint_stats) &&
            endpoint_stats.reconnect_attempts != 0 &&
            endpoint_stats.reconnect_succeeded != 0,
        "reconnect counters are observable");
  CHECK(peer_ready, "subscription reactivates on the new peer");

  static const char payload[] = "record after reconnect";
  qlinq_record_t record = {.group_id = 7,
                           .sequence = 9,
                           .data = payload,
                           .size = sizeof(payload) - 1U};
  qlinq_send_result_t sent = qlinq_stream_send(replacement_publisher, &record);
  CHECK(sent == QLINQ_SEND_SENT || sent == QLINQ_SEND_BUFFERED,
        "publish after reconnect");
  bool received = false;
  for (size_t attempt = 0; attempt < 500 && !received; attempt++) {
    CHECK(qlinq_service(context, 10) >= QLINQ_STATUS_OK,
          "service post-reconnect record");
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      if (event.type == QLINQ_EVENT_RECORD && event.stream == subscription &&
          event.record.size == record.size &&
          memcmp(event.record.data, payload, record.size) == 0)
        received = true;
      qlinq_event_release(&event);
    }
  }
  CHECK(received, "exact delivery continues after reconnect");

  printf("===QLINQ RECONNECT OK===\n");
  result = 0;

Cleanup:
  qlinq_context_destroy(context);
  return result;
}
