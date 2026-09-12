#include "qlinq.h"

#include "transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Exercise the public event boundary: transport-only tests cannot detect a
 * received object's descriptor no longer matching its application stream. */
static int run_delivery(qlinq_delivery_t delivery,
                        qlinq_content_type_t content) {
  qlinq_context_t *context = qlinq_context_create(NULL);
  if (!context)
    return 1;
  int failed = 1;
  qlinq_endpoint_config_t source = {
      .bind_addresses = {"127.0.0.1"},
      .bind_address_count = 1,
      .port = 19762,
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
  qlinq_stream_config_t conflicting = config;
  conflicting.delivery = delivery == QLINQ_DELIVERY_RELIABLE
                             ? QLINQ_DELIVERY_DATAGRAM
                             : QLINQ_DELIVERY_RELIABLE;
  if (qlinq_publish(listener, &conflicting) ||
      qlinq_subscribe(client, &conflicting))
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
        stats.active_connections == 1) {
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
  bool received = false;
  for (size_t attempt = 0; attempt < 500 && !received; attempt++) {
    if (qlinq_service(context, -1) < QLINQ_STATUS_OK)
      goto Exit;
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      bool valid = true;
      if (event.type == QLINQ_EVENT_RECORD) {
        valid = event.stream == subscriber && event.delivery == delivery &&
                event.content_type == content &&
                (finite || (event.record.sequence == 23 &&
                            event.record.group_id == 17)) &&
                event.record.size == sizeof(payload) &&
                memcmp(event.record.data, payload, sizeof(payload)) == 0;
        received |= valid;
      }
      qlinq_event_release(&event);
      if (!valid)
        goto Exit;
    }
  }
  failed = !received;
Exit:
  qlinq_context_destroy(context);
  if (failed)
    fprintf(stderr, "delivery failed: mode=%d content=%d\n", delivery, content);
  return failed;
}

static int run_reliable_boundaries(void) {
  qlinq_context_t *context = qlinq_context_create(NULL);
  if (!context)
    return 1;
  qlinq_endpoint_config_t config = {
      .bind_addresses = {"127.0.0.1"},
      .bind_address_count = 1,
      .port = 19763,
      .security = {.certificate_file = "t/assets/server.crt",
                   .private_key_file = "t/assets/server.key",
                   .allow_insecure_peer = true}};
  qlinq_endpoint_t *server = qlinq_listen(context, &config);
  config.remote_addresses[0] = "127.0.0.1";
  config.remote_address_count = 1;
  qlinq_endpoint_t *client = qlinq_connect(context, &config);
  qlinq_stream_config_t track = {.name = "maximum",
                                 .content_type = QLINQ_CONTENT_DATA,
                                 .delivery = QLINQ_DELIVERY_RELIABLE};
  qlinq_stream_t *publishers[2] = {qlinq_publish(server, &track),
                                   qlinq_publish(client, &track)};
  qlinq_stream_t *subscribers[2] = {qlinq_subscribe(client, &track),
                                    qlinq_subscribe(server, &track)};
  int failed = 1;
  uint8_t *payload = malloc(TRANSPORT_MAX_RELIABLE_OBJECT_SIZE + 1U);
  if (!server || !client || !publishers[0] || !publishers[1] ||
      !subscribers[0] || !subscribers[1] || !payload)
    goto Exit;
  for (size_t i = 0; i <= TRANSPORT_MAX_RELIABLE_OBJECT_SIZE; i++)
    payload[i] = (uint8_t)(i * 37U);
  unsigned joined = 0;
  for (size_t attempt = 0; attempt < 2000 && joined < 2; attempt++) {
    if (qlinq_service(context, 5) < QLINQ_STATUS_OK)
      goto Exit;
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      joined += event.type == QLINQ_EVENT_SUBSCRIBER_JOINED;
      qlinq_event_release(&event);
    }
  }
  if (joined != 2)
    goto Exit;
  for (size_t direction = 0; direction < 2; direction++) {
    qlinq_record_t record = {.data = payload,
                             .size = TRANSPORT_MAX_RELIABLE_OBJECT_SIZE + 1U};
    if (qlinq_stream_send(publishers[direction], &record) != QLINQ_SEND_INVALID)
      goto Exit;
    for (unsigned iteration = 0; iteration < 3; iteration++) {
      record.sequence = iteration;
      record.size = TRANSPORT_MAX_RELIABLE_OBJECT_SIZE - (iteration == 0);
      bool sent = false, received = false;
      for (size_t attempt = 0; attempt < 2000 && !received; attempt++) {
        if (!sent) {
          qlinq_send_result_t result =
              qlinq_stream_send(publishers[direction], &record);
          sent = result == QLINQ_SEND_SENT;
          if (!sent && result != QLINQ_SEND_WOULD_BLOCK)
            goto Exit;
        }
        if (qlinq_service(context, 5) < QLINQ_STATUS_OK)
          goto Exit;
        qlinq_event_t event;
        while (qlinq_next_event(context, &event)) {
          bool valid = true;
          if (event.type == QLINQ_EVENT_RECORD) {
            valid = event.stream == subscribers[direction] &&
                    event.record.sequence == record.sequence &&
                    event.record.size == record.size &&
                    memcmp(event.record.data, payload, record.size) == 0;
            received = valid;
          }
          qlinq_event_release(&event);
          if (!valid)
            goto Exit;
        }
      }
      if (!received)
        goto Exit;
    }
  }
  failed = 0;
Exit:
  free(payload);
  qlinq_context_destroy(context);
  if (failed)
    fputs("reliable maximum-record boundary failed\n", stderr);
  return failed;
}

int main(void) {
  if (run_reliable_boundaries())
    return 1;
  const qlinq_delivery_t modes[] = {
      QLINQ_DELIVERY_DATAGRAM, QLINQ_DELIVERY_FIXED_FEC,
      QLINQ_DELIVERY_RATELESS, QLINQ_DELIVERY_RELIABLE};
  const qlinq_content_type_t content[] = {QLINQ_CONTENT_DATA,
                                          QLINQ_CONTENT_VIDEO};
  for (size_t c = 0; c < sizeof(content) / sizeof(content[0]); c++)
    for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); m++)
      if (run_delivery(modes[m], content[c]))
        return 1;
  puts("===QLINQ DELIVERY MATRIX OK===");
  return 0;
}
