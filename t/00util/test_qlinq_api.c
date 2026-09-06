#include "qlinq.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition, message)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "qlinq API test failed: %s\n", message);                 \
      goto Cleanup;                                                            \
    }                                                                          \
  } while (0)

static void count_log(void *user_data, const qlinq_log_event_t *event) {
  size_t *count = user_data;
  if (count && event && event->component && event->message)
    (*count)++;
}

int main(void) {
  static const char secret[] = "qlinq-api-secret";
  static const char first_payload[] = "first record";
  static const char second_payload[] = "second record";
  qlinq_context_t *context = NULL;
  qlinq_endpoint_t *listener = NULL, *client = NULL;
  qlinq_stream_t *publisher = NULL, *subscription = NULL;
  qlinq_stream_t *late_subscription = NULL;
  qlinq_stream_t *fixed_publisher = NULL, *fixed_subscription = NULL;
  qlinq_stream_t *abort_publisher = NULL, *abort_subscription = NULL;
  size_t logs_seen = 0;
  int result = 1;

  qlinq_context_config_t context_config = {.log_callback = count_log,
                                           .log_user_data = &logs_seen};
  context = qlinq_context_create(&context_config);
  CHECK(context, "create context");

  qlinq_endpoint_config_t listener_config = {
      .bind_addresses = {"127.0.0.1"},
      .bind_address_count = 1,
      .port = 18991,
      .security = {.shared_secret = secret,
                   .shared_secret_size = sizeof(secret) - 1U,
                   .certificate_file = "t/assets/server.crt",
                   .private_key_file = "t/assets/server.key",
                   .allow_insecure_peer = true}};
  listener = qlinq_listen(context, &listener_config);
  CHECK(listener, "create listening endpoint");

  qlinq_endpoint_config_t client_config = {
      .bind_addresses = {"127.0.0.1"},
      .bind_address_count = 1,
      .remote_addresses = {"127.0.0.1"},
      .remote_address_count = 1,
      .port = 18991,
      .reconnect_enabled = true,
      .reconnect_initial_delay_ms = 10,
      .reconnect_max_delay_ms = 100,
      .security = {.shared_secret = secret,
                   .shared_secret_size = sizeof(secret) - 1U,
                   .allow_insecure_peer = true}};
  client = qlinq_connect(context, &client_config);
  CHECK(client, "create connecting endpoint");

  qlinq_stream_config_t stream_config = {.content_type = QLINQ_CONTENT_DATA,
                                         .delivery = QLINQ_DELIVERY_RATELESS,
                                         .name = "api/records"};
  publisher = qlinq_publish(listener, &stream_config);
  subscription = qlinq_subscribe(client, &stream_config);
  CHECK(publisher && subscription, "open publishing and subscribed streams");

  bool subscriber_joined = false, writable_event = false;
  for (size_t attempt = 0; attempt < 500 && !subscriber_joined; attempt++) {
    CHECK(qlinq_service(context, 10) >= QLINQ_STATUS_OK,
          "service connection setup");
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      if (event.type == QLINQ_EVENT_SUBSCRIBER_JOINED &&
          event.stream == publisher && event.peer_id != 0)
        subscriber_joined = true;
      if (event.type == QLINQ_EVENT_STREAM_WRITABLE &&
          event.stream == publisher)
        writable_event = true;
      qlinq_event_release(&event);
    }
  }
  CHECK(subscriber_joined, "authenticated subscriber joined publisher");
  CHECK(writable_event, "publisher emitted initial writable transition");
  CHECK(qlinq_stream_is_writable(publisher), "publisher is writable");
  qlinq_stream_stats_t stream_stats;
  CHECK(qlinq_stream_get_stats(publisher, &stream_stats) &&
            stream_stats.state == QLINQ_STREAM_OPEN &&
            stream_stats.subscribers == 1 && stream_stats.writable,
        "query open publishing stream state");

  qlinq_record_t first = {.group_id = UINT64_C(0x1011121314151617),
                          .sequence = UINT64_C(0x2122232425262728),
                          .data = first_payload,
                          .size = sizeof(first_payload) - 1U,
                          .keyframe = true,
                          .priority = 2};
  qlinq_record_t second = {.group_id = UINT64_C(0x3132333435363738),
                           .sequence = UINT64_C(0x4142434445464748),
                           .data = second_payload,
                           .size = sizeof(second_payload) - 1U,
                           .priority = 1};
  qlinq_send_result_t first_send = qlinq_stream_send(publisher, &first);
  qlinq_send_result_t second_send = qlinq_stream_send(publisher, &second);
  CHECK((first_send == QLINQ_SEND_SENT || first_send == QLINQ_SEND_BUFFERED) &&
            (second_send == QLINQ_SEND_SENT ||
             second_send == QLINQ_SEND_BUFFERED),
        "queue records");
  CHECK(qlinq_stream_finish(publisher) == QLINQ_STATUS_OK,
        "finish finite stream");

  bool got_first = false, got_second = false;
  bool receiver_finished = false, publisher_drained = false;
  for (size_t attempt = 0;
       attempt < 500 &&
       !(got_first && got_second && receiver_finished && publisher_drained);
       attempt++) {
    CHECK(qlinq_service(context, 10) >= QLINQ_STATUS_OK,
          "service record delivery");
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      if (event.type == QLINQ_EVENT_RECORD && event.stream == subscription &&
          strcmp(event.stream_name, "api/records") == 0) {
        if (event.record.sequence == first.sequence &&
            event.record.group_id == first.group_id && event.record.keyframe &&
            event.record.priority == first.priority &&
            event.record.size == first.size &&
            memcmp(event.record.data, first.data, first.size) == 0)
          got_first = true;
        if (event.record.sequence == second.sequence &&
            event.record.group_id == second.group_id &&
            event.record.priority == second.priority &&
            event.record.size == second.size &&
            memcmp(event.record.data, second.data, second.size) == 0)
          got_second = true;
      }
      if (event.type == QLINQ_EVENT_STREAM_FINISHED &&
          event.stream == subscription)
        receiver_finished = true;
      if (event.type == QLINQ_EVENT_STREAM_DRAINED &&
          event.stream == publisher && event.completion.peers_total == 1 &&
          event.completion.peers_completed == 1 &&
          event.completion.peers_failed == 0)
        publisher_drained = true;
      qlinq_event_release(&event);
    }
  }
  CHECK(got_first && got_second, "receive owned records with metadata");
  CHECK(receiver_finished, "receiver observes recovered stream completion");
  CHECK(publisher_drained, "publisher observes confirmed cohort drain");
  CHECK(qlinq_stream_get_stats(publisher, &stream_stats) &&
            stream_stats.state == QLINQ_STREAM_FINISHED &&
            stream_stats.records_sent == 2 &&
            stream_stats.confirmations_pending == 0 &&
            stream_stats.confirmations_completed == 1 &&
            stream_stats.confirmations_failed == 0,
        "query drained publishing stream state");
  CHECK(qlinq_stream_get_stats(subscription, &stream_stats) &&
            stream_stats.state == QLINQ_STREAM_FINISHED &&
            stream_stats.records_received == 2,
        "query finished subscribed stream state");

  qlinq_stream_close(subscription);
  late_subscription = qlinq_subscribe(client, &stream_config);
  CHECK(late_subscription, "subscribe after transfer completion");
  bool late_aborted = false;
  for (size_t attempt = 0; attempt < 500 && !late_aborted; attempt++) {
    CHECK(qlinq_service(context, 10) >= QLINQ_STATUS_OK,
          "service late subscription rejection");
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      if (event.type == QLINQ_EVENT_STREAM_ABORTED &&
          event.stream == late_subscription)
        late_aborted = true;
      qlinq_event_release(&event);
    }
  }
  CHECK(late_aborted, "completed transfer rejects a late subscriber");

  qlinq_stream_config_t fixed_config = {.content_type = QLINQ_CONTENT_DATA,
                                        .delivery = QLINQ_DELIVERY_FEC,
                                        .name = "api/fixed-fec"};
  fixed_publisher = qlinq_publish(listener, &fixed_config);
  fixed_subscription = qlinq_subscribe(client, &fixed_config);
  CHECK(fixed_publisher && fixed_subscription, "open fixed-FEC streams");
  bool fixed_joined = false;
  for (size_t attempt = 0; attempt < 500 && !fixed_joined; attempt++) {
    CHECK(qlinq_service(context, 10) >= QLINQ_STATUS_OK,
          "service fixed-FEC stream setup");
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      if (event.type == QLINQ_EVENT_SUBSCRIBER_JOINED &&
          event.stream == fixed_publisher)
        fixed_joined = true;
      qlinq_event_release(&event);
    }
  }
  CHECK(fixed_joined, "fixed-FEC subscriber joined");
  qlinq_record_t fixed_record = {.group_id = 9,
                                 .sequence = 1,
                                 .data = first_payload,
                                 .size = sizeof(first_payload) - 1U};
  qlinq_send_result_t fixed_send =
      qlinq_stream_send(fixed_publisher, &fixed_record);
  CHECK(fixed_send == QLINQ_SEND_SENT || fixed_send == QLINQ_SEND_BUFFERED,
        "queue fixed-FEC record");
  CHECK(qlinq_stream_finish(fixed_publisher) == QLINQ_STATUS_OK,
        "finish fixed-FEC stream");
  bool fixed_record_received = false, fixed_finished = false,
       fixed_drained = false;
  for (size_t attempt = 0; attempt < 500 && !(fixed_record_received &&
                                              fixed_finished && fixed_drained);
       attempt++) {
    CHECK(qlinq_service(context, 10) >= QLINQ_STATUS_OK,
          "service fixed-FEC completion");
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      if (event.type == QLINQ_EVENT_RECORD &&
          event.stream == fixed_subscription &&
          event.record.sequence == fixed_record.sequence)
        fixed_record_received = true;
      if (event.type == QLINQ_EVENT_STREAM_FINISHED &&
          event.stream == fixed_subscription)
        fixed_finished = true;
      if (event.type == QLINQ_EVENT_STREAM_DRAINED &&
          event.stream == fixed_publisher &&
          event.completion.peers_completed == 1)
        fixed_drained = true;
      qlinq_event_release(&event);
    }
  }
  CHECK(fixed_record_received && fixed_finished && fixed_drained,
        "fixed-FEC stream completes and drains");

  qlinq_stream_config_t abort_config = {.content_type = QLINQ_CONTENT_DATA,
                                        .delivery = QLINQ_DELIVERY_RATELESS,
                                        .name = "api/abort"};
  abort_publisher = qlinq_publish(listener, &abort_config);
  abort_subscription = qlinq_subscribe(client, &abort_config);
  CHECK(abort_publisher && abort_subscription, "open abort test streams");
  bool abort_joined = false;
  for (size_t attempt = 0; attempt < 500 && !abort_joined; attempt++) {
    CHECK(qlinq_service(context, 10) >= QLINQ_STATUS_OK,
          "service abort stream setup");
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      if (event.type == QLINQ_EVENT_SUBSCRIBER_JOINED &&
          event.stream == abort_publisher)
        abort_joined = true;
      qlinq_event_release(&event);
    }
  }
  CHECK(abort_joined, "abort stream subscriber joined");
  CHECK(qlinq_stream_finish(abort_publisher) == QLINQ_STATUS_OK,
        "start completion before abort");
  CHECK(qlinq_stream_abort(abort_publisher) == QLINQ_STATUS_OK,
        "abort finishing publishing stream");
  bool local_aborted = false, remote_aborted = false;
  for (size_t attempt = 0; attempt < 500 && !(local_aborted && remote_aborted);
       attempt++) {
    CHECK(qlinq_service(context, 10) >= QLINQ_STATUS_OK,
          "service stream abort");
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      if (event.type == QLINQ_EVENT_STREAM_ABORTED &&
          event.stream == abort_publisher)
        local_aborted = true;
      if (event.type == QLINQ_EVENT_STREAM_ABORTED &&
          event.stream == abort_subscription)
        remote_aborted = true;
      qlinq_event_release(&event);
    }
  }
  CHECK(local_aborted && remote_aborted,
        "abort is visible to publisher and subscriber");
  CHECK(qlinq_stream_get_stats(abort_subscription, &stream_stats) &&
            stream_stats.state == QLINQ_STREAM_ABORTED,
        "query aborted subscribed stream state");

  qlinq_endpoint_stats_t stats;
  CHECK(qlinq_endpoint_get_stats(client, &stats) &&
            stats.active_connections == 1,
        "query endpoint statistics");
  CHECK(logs_seen != 0, "structured transport logs reach the application");
  CHECK(qlinq_endpoint_reload_credentials(listener, "t/assets/server.crt",
                                          "t/assets/server.key") ==
            QLINQ_STATUS_OK,
        "atomically reload endpoint credentials");
  CHECK(qlinq_endpoint_shutdown(client, "API hardening test") ==
                QLINQ_STATUS_OK &&
            qlinq_endpoint_shutdown(listener, "API hardening test") ==
                QLINQ_STATUS_OK,
        "start graceful endpoint shutdown");
  bool client_drained = false, listener_drained = false;
  bool disconnect_detail = false;
  for (size_t attempt = 0;
       attempt < 500 && !(client_drained && listener_drained); attempt++) {
    CHECK(qlinq_service(context, 10) >= QLINQ_STATUS_OK,
          "service graceful endpoint shutdown");
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      if (event.type == QLINQ_EVENT_PEER_DISCONNECTED &&
          event.disconnect.reason && event.disconnect.reason[0] != '\0')
        disconnect_detail = true;
      qlinq_event_release(&event);
    }
    client_drained = qlinq_endpoint_is_drained(client);
    listener_drained = qlinq_endpoint_is_drained(listener);
  }
  CHECK(client_drained && listener_drained,
        "graceful endpoint shutdown reaches drained state");
  CHECK(disconnect_detail, "disconnect event owns structured close details");

  printf("===QLINQ API OK===\n");
  result = 0;

Cleanup:
  qlinq_context_destroy(context);
  return result;
}
