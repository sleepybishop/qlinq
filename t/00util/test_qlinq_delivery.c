#include "qlinq.h"

#include <stdio.h>
#include <string.h>

/* Exercise the public event boundary: transport-only tests cannot detect a
 * received object's descriptor no longer matching its application stream. */
static int run_delivery(qlinq_delivery_t delivery, qlinq_content_type_t content,
                        bool group) {
  qlinq_context_t *context = qlinq_context_create(NULL);
  if (!context)
    return 1;
  int failed = 1;
  qlinq_endpoint_config_t source = {
      .bind_addresses = {"127.0.0.1"},
      .bind_address_count = 1,
      .port = 19762,
      .group_delivery = {.enabled = group},
      .security = {.shared_secret = "delivery",
                   .shared_secret_size = 8,
                   .certificate_file = "t/assets/server.crt",
                   .private_key_file = "t/assets/server.key",
                   .allow_insecure_peer = true}};
  qlinq_endpoint_config_t receiver = {
      .bind_addresses = {"127.0.0.1"},
      .bind_address_count = 1,
      .remote_addresses = {"127.0.0.1"},
      .remote_address_count = 1,
      .port = 19762,
      .group_delivery = {.enabled = group},
      .security = {.shared_secret = "delivery",
                   .shared_secret_size = 8,
                   .allow_insecure_peer = true}};
  qlinq_endpoint_t *listener = qlinq_listen(context, &source);
  qlinq_endpoint_t *client = qlinq_connect(context, &receiver);
  if (!listener || !client)
    goto Exit;
  qlinq_stream_config_t config = {
      .content_type = content, .delivery = delivery, .name = "delivery"};
  qlinq_stream_t *publisher = qlinq_publish(listener, &config);
  qlinq_stream_t *subscriber = qlinq_subscribe(client, &config);
  if (!publisher || !subscriber)
    goto Exit;
  bool joined = false, ready = false;
  for (size_t attempt = 0; attempt < 500; attempt++) {
    if (qlinq_service(context, 10) < QLINQ_STATUS_OK)
      goto Exit;
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      if (event.type == QLINQ_EVENT_SUBSCRIBER_JOINED)
        joined = true;
      qlinq_event_release(&event);
    }
    qlinq_endpoint_stats_t stats;
    if (joined && qlinq_endpoint_get_stats(listener, &stats) &&
        (!group || delivery == QLINQ_DELIVERY_RELIABLE ||
         stats.active_group_members == 1)) {
      ready = true;
      break;
    }
  }
  if (!ready)
    goto Exit;
  uint8_t payload[1400];
  for (size_t i = 0; i < sizeof(payload); i++)
    payload[i] = (uint8_t)i;
  qlinq_record_t record = {.data = payload,
                           .size = sizeof(payload),
                           .group_id = 17,
                           .sequence = 23,
                           .priority = 1};
  qlinq_send_result_t sent = qlinq_stream_send(publisher, &record);
  if (sent != QLINQ_SEND_SENT && sent != QLINQ_SEND_BUFFERED)
    goto Exit;
  bool finite =
      content == QLINQ_CONTENT_DATA && (delivery == QLINQ_DELIVERY_FIXED_FEC ||
                                        delivery == QLINQ_DELIVERY_RATELESS);
  if (finite && qlinq_stream_finish(publisher) != QLINQ_STATUS_OK)
    goto Exit;
  bool received = false, finished = !finite;
  for (size_t attempt = 0; attempt < 500 && !(received && finished);
       attempt++) {
    if (qlinq_service(context, 10) < QLINQ_STATUS_OK)
      goto Exit;
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      bool valid = true;
      if (event.type == QLINQ_EVENT_RECORD) {
        valid = event.stream == subscriber && event.delivery == delivery &&
                event.content_type == content && event.record.sequence == 23 &&
                event.record.group_id == 17 &&
                event.record.size == sizeof(payload) &&
                memcmp(event.record.data, payload, sizeof(payload)) == 0;
        received |= valid;
      }
      if (event.type == QLINQ_EVENT_STREAM_FINISHED &&
          event.stream == subscriber)
        finished = true;
      qlinq_event_release(&event);
      if (!valid)
        goto Exit;
    }
  }
  failed = !(received && finished);
Exit:
  qlinq_context_destroy(context);
  if (failed)
    fprintf(stderr, "delivery failed: mode=%d content=%d group=%d\n", delivery,
            content, group);
  return failed;
}

int main(void) {
  const qlinq_delivery_t modes[] = {
      QLINQ_DELIVERY_DATAGRAM, QLINQ_DELIVERY_FIXED_FEC,
      QLINQ_DELIVERY_RATELESS, QLINQ_DELIVERY_RELIABLE};
  const qlinq_content_type_t content[] = {QLINQ_CONTENT_DATA,
                                          QLINQ_CONTENT_VIDEO};
  for (size_t g = 0; g < 2; g++)
    for (size_t c = 0; c < sizeof(content) / sizeof(content[0]); c++)
      for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); m++)
        if (run_delivery(modes[m], content[c], g != 0))
          return 1;
  puts("===QLINQ DELIVERY MATRIX OK===");
  return 0;
}
