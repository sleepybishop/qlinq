#include "picotls/openssl.h"
#include "portable_sockets.h"
#include "quicly/defaults.h"
#include "transport_internal.h"
#include "transport_protocol.h"
#include "transport_publish.h"
#include "transport_subscriptions.h"
#include "transport_tracks.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                  \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
#define MAX_CLIENTS 12

typedef struct {
  transport_t *transport;
  bool connected;
  size_t received;
  size_t last_size;
  uint64_t last_checksum;
} endpoint_t;

typedef struct {
  endpoint_t source, clients[MAX_CLIENTS];
  size_t count;
  moq_track_id_t track;
  transport_flexicast_flow_t *flow;
} fixture_t;

static void source_event(void *data, const transport_event_t *event) {
  endpoint_t *endpoint = data;
  if (event->type == TRANSPORT_EVENT_AUTH)
    CHECK(transport_respond_auth(endpoint->transport, event->conn, true));
}

static void client_event(void *data, const transport_event_t *event) {
  endpoint_t *endpoint = data;
  if (event->type == TRANSPORT_EVENT_CONNECTED)
    CHECK(transport_send_auth(endpoint->transport, event->conn,
                              (uint8_t *)"test", 4));
  if (event->type == TRANSPORT_EVENT_AUTH_COMPLETE)
    endpoint->connected = event->auth.success;
  if (event->type == TRANSPORT_EVENT_OBJECT) {
    endpoint->received++;
    endpoint->last_size = event->object.size;
    endpoint->last_checksum = 0;
    for (size_t i = 0; i < event->object.size; i++)
      endpoint->last_checksum =
          endpoint->last_checksum * 33 + event->object.data[i];
  }
}

static void pump(fixture_t *fixture, size_t milliseconds) {
  for (size_t i = 0; i < milliseconds; i++) {
    transport_tick(fixture->source.transport);
    for (size_t j = 0; j < fixture->count; j++)
      if (fixture->clients[j].transport)
        transport_tick(fixture->clients[j].transport);
    usleep(1000);
  }
}

static void create_fixture(fixture_t *fixture, size_t count, bool adaptive,
                           const char *mode) {
  memset(fixture, 0, sizeof(*fixture));
  fixture->count = count;
  fixture->track =
      (moq_track_id_t){.type = MOQ_TRACK_VIDEO, .name = "regression"};
  if (strstr(mode, "fixed") || strstr(mode, "rateless")) {
    fixture->track.type = MOQ_TRACK_DATA;
    fixture->track.flags = MOQ_TRACK_FLAG_FEC_ENABLED;
    if (strstr(mode, "rateless"))
      fixture->track.flags |= MOQ_TRACK_FLAG_FEC_RATELESS;
  }
  if (strcmp(mode, "video-rateless") == 0)
    fixture->track.type = MOQ_TRACK_VIDEO;
  transport_config_t config = {.bind_hosts = {"127.0.0.1"},
                               .num_bind_hosts = 1,
                               .port = 19761,
                               .cert_file = "t/assets/server.crt",
                               .key_file = "t/assets/server.key",
                               .allow_insecure_peer = true,
                               .enable_flexicast = true,
                               .callback = source_event,
                               .user_data = &fixture->source};
  /* Do not override controller rates: first-packet progress must work with
   * the same defaults applications receive. */
  if (adaptive)
    config.flexicast_cc_mode = TRANSPORT_FLEXICAST_CC_ADAPTIVE;
  bool native = strstr(mode, "native") != NULL;
  if (native) {
    config.bind_hosts[0] = "127.0.0.2";
    config.bind_hosts[1] = "127.0.0.1";
    config.num_bind_hosts = 2;
    if (strstr(mode, "wildcard")) {
      config.bind_hosts[0] = "0.0.0.0";
      config.num_bind_hosts = 1;
    }
    config.flexicast_group = "232.42.42.61";
    config.flexicast_group_port = 19763;
    config.flexicast_interface = "127.0.0.1";
  }
  CHECK((fixture->source.transport = transport_create(&config)) != NULL);
  for (size_t j = 0; j < count; j++) {
    transport_config_t client = {.bind_hosts = {"127.0.0.1"},
                                 .num_bind_hosts = 1,
                                 .remote_hosts = {"127.0.0.1"},
                                 .num_remote_hosts = 1,
                                 .port = 19761,
                                 .allow_insecure_peer = true,
                                 .enable_flexicast = true,
                                 .callback = client_event,
                                 .user_data = &fixture->clients[j]};
    if (native)
      client.flexicast_interface = "127.0.0.1";
    if (strcmp(mode, "limits") == 0 && j == count - 1)
      client.limits.max_fec_object_size = 1024;
    CHECK((fixture->clients[j].transport = transport_create(&client)) != NULL);
    for (size_t attempt = 0; attempt < 1000 && !fixture->clients[j].connected;
         attempt++)
      pump(fixture, 2);
    CHECK(fixture->clients[j].connected);
    /* Give one member a different local alias for the same shared track. */
    if (strcmp(mode, "aliases") == 0 && j == count - 1) {
      moq_track_id_t other = {.type = MOQ_TRACK_VIDEO, .name = "alias-offset"};
      CHECK(transport_subscribe(fixture->clients[j].transport, other));
    }
    CHECK(transport_subscribe(fixture->clients[j].transport, fixture->track));
  }
  size_t cohort = strcmp(mode, "aliases") == 0 ? count - 1 : count;
  for (size_t attempt = 0; attempt < 1500; attempt++) {
    pump(fixture, 2);
    fixture->flow = transport_flexicast_find_source(fixture->source.transport,
                                                    &fixture->track);
    size_t ready = 0;
    bool pending = false;
    transport_t *source = fixture->source.transport;
    for (size_t f = 0; f < source->flexicast.capacity; f++) {
      transport_flexicast_flow_t *flow = &source->flexicast.flows[f];
      if (flow->active && flow->source &&
          transport_track_id_equal(&flow->track_id, &fixture->track)) {
        ready += flow->listening_count;
        pending |= flow->rekey_pending;
      }
    }
    if (fixture->flow && ready == count && !pending)
      break;
  }
  CHECK(fixture->flow && fixture->flow->listening_count == cohort &&
        !fixture->flow->rekey_pending);
}

static void destroy_fixture(fixture_t *fixture) {
  for (size_t i = 0; i < fixture->count; i++)
    transport_destroy(fixture->clients[i].transport);
  transport_destroy(fixture->source.transport);
}

static moq_object_t object_for(fixture_t *fixture, uint8_t *bytes,
                               size_t size) {
  return (moq_object_t){
      .track_id = fixture->track, .data = bytes, .size = size, .priority = 1};
}

static void check_delivery(fixture_t *fixture, size_t objects, size_t members) {
  bool complete = false;
  for (size_t attempt = 0; attempt < 30000 && !complete; attempt++) {
    pump(fixture, 2);
    complete = true;
    for (size_t i = 0; i < members; i++)
      complete &= fixture->clients[i].received == objects;
  }
  for (size_t i = 0; i < members; i++) {
    if (fixture->clients[i].received != objects)
      fprintf(stderr, "member %zu: received %zu expected %zu\n", i,
              fixture->clients[i].received, objects);
    CHECK(fixture->clients[i].received == objects);
    CHECK(fixture->clients[i].transport->stats.malformed_datagrams == 0);
  }
}

static void test_delivery(fixture_t *fixture, bool native) {
  uint8_t bytes[32] = {42};
  moq_object_t object = object_for(fixture, bytes, sizeof(bytes));
  transport_t *source = fixture->source.transport;
  uint64_t bytes_before = source->stats.flexicast_physical_bytes_sent;
  uint64_t packets_before = source->stats.flexicast_packets_sent;
  for (size_t i = 0; i < 4; i++) {
    object.object_id = i;
    CHECK(transport_publish_ex(source, &object) == TRANSPORT_PUBLISH_DELIVERED);
    check_delivery(fixture, i + 1, fixture->count);
  }
  CHECK(fixture->flow->data_queue.count == 0);
  size_t cohorts = 0;
  for (size_t f = 0; f < source->flexicast.capacity; f++)
    if (source->flexicast.flows[f].active &&
        source->flexicast.flows[f].source &&
        transport_track_id_equal(&source->flexicast.flows[f].track_id,
                                 &fixture->track))
      cohorts++;
  CHECK(source->stats.flexicast_packets_sent - packets_before == 4 * cohorts);
  CHECK(source->stats.flexicast_payloads_accepted == 4 * cohorts);
  size_t copies = native ? 1 : fixture->count;
  CHECK(source->stats.flexicast_physical_packets_sent == 4 * copies);
  size_t symbol_size = transport_get_datagram_symbol_size(source);
  if (symbol_size > sizeof(bytes))
    symbol_size = sizeof(bytes);
  size_t plaintext = QLINQ_WIRE_FEC_HEADER_SIZE + symbol_size;
  CHECK(source->stats.flexicast_plaintext_bytes_accepted ==
        4 * cohorts * plaintext);
  uint64_t expected =
      4 * copies *
      quicly_flexicast_datagram_size(fixture->flow->crypto, plaintext);
  CHECK(source->stats.flexicast_physical_bytes_sent - bytes_before == expected);
  if (native) {
    CHECK(source->stats.flexicast_native_packets_sent == 4);
    for (size_t i = 0; i < fixture->count; i++)
      CHECK(fixture->clients[i]
                .transport->stats.flexicast_multicast_datagrams_received == 4);
  }
}

static quicly_flexicast_frame_t state_frame(fixture_t *fixture, uint64_t epoch,
                                            uint64_t action) {
  quicly_flexicast_frame_t frame = {.type = QUICLY_FRAME_TYPE_FC_STATE};
  frame.data.state.flow_id.len = QUICLY_FLEXICAST_FLOW_ID_SIZE;
  quicly_encode64(frame.data.state.flow_id.bytes, fixture->flow->flow_id);
  frame.data.state.sequence = epoch;
  frame.data.state.action = action;
  return frame;
}

static void test_rekey(fixture_t *fixture, const char *mode) {
  bool partial = strcmp(mode, "partial-rekey") == 0;
  bool pressure = strcmp(mode, "control-queue") == 0;
  bool backlog = strcmp(mode, "egress-rekey") == 0;
  transport_t *source = fixture->source.transport;
  transport_flexicast_flow_t *flow = fixture->flow;
  transport_conn_t *departed = flow->members[fixture->count - 1].conn;
  uint8_t bytes[32] = {42};
  moq_object_t object = object_for(fixture, bytes, sizeof(bytes));
  uint32_t old_epoch = flow->key_epoch;
  uint8_t old_secret[sizeof(flow->secret)];
  memcpy(old_secret, flow->secret, sizeof(old_secret));
  if (pressure) {
    quicly_flexicast_key_frame_t key = {
        .flow_id = state_frame(fixture, old_epoch, 0).data.state.flow_id,
        .sequence = old_epoch,
        .first_packet_number =
            quicly_flexicast_get_next_packet_number(flow->crypto),
        .key = ptls_iovec_init(flow->secret, sizeof(flow->secret)),
        .algorithm = PTLS_CIPHER_SUITE_AES_128_GCM_SHA256};
    size_t accepted = 0;
    while (quicly_flexicast_send_key(flow->members[0].conn->quic, &key) ==
           QUICLY_FLEXICAST_OK)
      CHECK(++accepted <= 256);
    CHECK(accepted != 0);
  }
  if (backlog) {
    transport_egress_t *egress = &source->egress[0];
    CHECK(egress->count == 0);
    transport_egress_packet_t *packet = &egress->packets[egress->head];
    packet->destination = source->local_addrs[0];
    packet->destination_len = sizeof(struct sockaddr_in);
    packet->data = malloc(1);
    CHECK(packet->data);
    packet->data[0] = 0;
    packet->size = 1;
    egress->count = egress->bytes = 1;
    CHECK(transport_publish_ex(source, &object) == TRANSPORT_PUBLISH_DELIVERED);
    CHECK(flow->data_queue.count == 1);
    CHECK(flow->data_queue.entries[flow->data_queue.head].packet != NULL);
    CHECK(source->stats.flexicast_physical_packets_sent == 0);
  }
  if (partial) {
    /* Precisely one replica can pass. The logical packet stays owned by the
     * flow, allowing rotation of its remaining replicas. */
    flow->pacing_tokens = quicly_flexicast_datagram_size(
        flow->crypto,
        QLINQ_WIRE_FEC_HEADER_SIZE +
            (sizeof(bytes) < transport_get_datagram_symbol_size(source)
                 ? sizeof(bytes)
                 : transport_get_datagram_symbol_size(source)));
    flow->pacing_last_refill_ms = transport_get_time_ms();
    CHECK(transport_publish_ex(source, &object) == TRANSPORT_PUBLISH_DELIVERED);
    CHECK(flow->data_queue.count == 1);
    CHECK(flow->data_queue.entries[flow->data_queue.head].next_member >= 1);
  }
  transport_subscriptions_remove(&departed->send_subscriptions,
                                 fixture->track.type, fixture->track.name);
  transport_flexicast_remove_member(source, departed, &fixture->track);
  CHECK(flow->rekey_pending);
  uint64_t packet_number =
      quicly_flexicast_get_next_packet_number(flow->crypto);
  if (!partial && !backlog)
    CHECK(transport_publish_ex(source, &object) == TRANSPORT_PUBLISH_DELIVERED);
  CHECK(quicly_flexicast_get_next_packet_number(flow->crypto) == packet_number);
  CHECK(flow->data_queue.count == 1);
  CHECK(source->egress[0].count == (backlog ? 1U : 0U));
  CHECK(flow->key_epoch == old_epoch);
  /* A second membership event cannot postpone the already scheduled epoch. */
  int64_t deadline = flow->rekey_ready_at_ms;
  quicly_flexicast_frame_t frame =
      state_frame(fixture, old_epoch, QUICLY_FLEXICAST_STATE_READY);
  CHECK(transport_flexicast_receive_quic_frame(source, departed, &frame));
  CHECK(flow->rekey_ready_at_ms == deadline);
  if (pressure) {
    flow->rekey_ready_at_ms = transport_get_time_ms();
    transport_flexicast_tick(source);
    CHECK(flow->members[0].key_pending);
    CHECK(!flow->members[0].listening);
  }
  check_delivery(fixture, 1, fixture->count - 1);
  CHECK(flow->key_epoch > old_epoch);
  CHECK(memcmp(old_secret, flow->secret, sizeof(old_secret)) != 0);
  CHECK(flow->data_queue.count == 0);
  pump(fixture, 50);
  for (size_t i = 0; i < fixture->count - 1; i++)
    CHECK(fixture->clients[i].received == 1);
  CHECK(fixture->clients[fixture->count - 1].received == 0);
  quicly_flexicast_config_t crypto_config = {
      .flow_id = flow->flow_id,
      .first_packet_number = packet_number,
      .cipher_suite = &ptls_openssl_aes128gcmsha256,
      .crypto_engine = &quicly_default_crypto_engine,
      .traffic_secret = ptls_iovec_init(old_secret, sizeof(old_secret))};
  quicly_flexicast_flow_t *observer = NULL;
  CHECK(quicly_flexicast_flow_create(&observer, &crypto_config) ==
        QUICLY_FLEXICAST_OK);
  uint8_t packet[256];
  size_t packet_size;
  ptls_iovec_t decoded;
  CHECK(quicly_flexicast_send_datagram(flow->crypto,
                                       ptls_iovec_init(bytes, sizeof(bytes)),
                                       packet, sizeof(packet), &packet_size,
                                       &packet_number) == QUICLY_FLEXICAST_OK);
  CHECK(quicly_flexicast_receive_datagram(observer, packet, packet_size,
                                          &decoded, &packet_number) !=
        QUICLY_FLEXICAST_OK);
  quicly_flexicast_flow_free(observer);
}

static void test_controls(fixture_t *fixture) {
  transport_t *source = fixture->source.transport;
  transport_flexicast_flow_t *flow = fixture->flow;
  transport_conn_t *conn = flow->members[fixture->count - 1].conn;
  uint64_t epoch = flow->key_epoch;
  quicly_flexicast_frame_t frame =
      state_frame(fixture, epoch, QUICLY_FLEXICAST_STATE_LEAVE);
  CHECK(transport_flexicast_receive_quic_frame(source, conn, &frame));
  CHECK(flow->rekey_pending);
  int64_t deadline = flow->rekey_ready_at_ms;
  /* Deterministic stateful control permutations: obsolete and future READYs,
   * repeated LEAVEs, JOINs crossing the pending rotation, and throttling. */
  uint32_t random = 0x72a9b;
  for (size_t i = 0; i < 256; i++) {
    random = random * 1664525U + 1013904223U;
    unsigned action = (random >> 24) % 4;
    frame = state_frame(fixture, epoch + (action == 3),
                        action == 0   ? QUICLY_FLEXICAST_STATE_LEAVE
                        : action == 1 ? QUICLY_FLEXICAST_STATE_JOIN
                                      : QUICLY_FLEXICAST_STATE_READY);
    CHECK(transport_flexicast_receive_quic_frame(source, conn, &frame) ==
          (action != 3));
    CHECK(flow->rekey_ready_at_ms == deadline);
    CHECK(!transport_flexicast_member_is_listening(flow, conn));
  }
  transport_flexicast_remove_member(source, conn, &fixture->track);
  frame = state_frame(fixture, epoch, QUICLY_FLEXICAST_STATE_READY);
  CHECK(transport_flexicast_receive_quic_frame(source, conn, &frame));
  frame.data.state.sequence = epoch + 1;
  CHECK(!transport_flexicast_receive_quic_frame(source, conn, &frame));
}

static void test_limits(fixture_t *fixture) {
  uint8_t bytes[2048] = {42};
  moq_object_t object = object_for(fixture, bytes, sizeof(bytes));
  CHECK(transport_publish_ex(fixture->source.transport, &object) ==
        TRANSPORT_PUBLISH_INVALID);
  pump(fixture, 50);
  for (size_t i = 0; i < fixture->count; i++) {
    CHECK(fixture->clients[i].received == 0);
    CHECK(fixture->clients[i].transport->stats.malformed_datagrams == 0);
  }
}

static void test_recovery(fixture_t *fixture) {
  uint8_t bytes[32] = {42};
  moq_object_t object = object_for(fixture, bytes, sizeof(bytes));
  transport_t *source = fixture->source.transport;
  /* Lose a complete leading object and a complete interior object which
   * will be more than 32 objects behind the terminal watermark. */
  for (size_t group = 0; group < 40; group++) {
    fixture->clients[1].transport->simulated_loss_rate =
        (group == 0 || group == 3) ? 100 : 0;
    for (size_t k = 0; k < 4; k++) {
      transport_publish_result_t result = transport_publish_ex(source, &object);
      CHECK(result == TRANSPORT_PUBLISH_DELIVERED ||
            result == TRANSPORT_PUBLISH_BUFFERED);
    }
    pump(fixture, 60);
  }
  fixture->clients[1].transport->simulated_loss_rate = 0;
  CHECK(source->stats.recovery_checkpoints_sent > 0);
  CHECK(transport_finish_track(source, fixture->track));
  check_delivery(fixture, 40, fixture->count);
  for (size_t attempt = 0;
       attempt < 1000 && source->stats.recovery_cache_releases < 40; attempt++)
    pump(fixture, 2);
  CHECK(source->stats.recovery_cache_releases == 40);
  for (size_t i = 0; i < fixture->count; i++) {
    transport_conn_t *conn = fixture->clients[i].transport->client_conn;
    uint8_t alias;
    CHECK(transport_subscriptions_find_alias(&conn->receive_subscriptions,
                                             &fixture->track, &alias) == 0);
    CHECK(transport_object_gap(conn, alias)->finish_emitted);
  }
}

static void test_cache_pressure(fixture_t *fixture) {
  transport_t *source = fixture->source.transport;
  uint8_t bytes[32] = {42};
  moq_object_t object = object_for(fixture, bytes, sizeof(bytes));
  /* Model a completely unconfirmed prefix occupying the bounded repair
   * cache. New publication must not evict even its oldest object. */
  for (size_t i = 0; i < TRANSPORT_SENT_CACHE_SIZE; i++) {
    object.object_id = i;
    CHECK(transport_sent_cache_store(&source->sent_cache, &object, 1, 1, 32,
                                     false));
  }
  CHECK(!transport_sent_cache_has_space(&source->sent_cache));
  source->fec_in_flush = true;
  object.object_id = TRANSPORT_SENT_CACHE_SIZE;
  CHECK(transport_publish_ex(source, &object) ==
        TRANSPORT_PUBLISH_BACKPRESSURE);
  source->fec_in_flush = false;
  CHECK(source->stats.recovery_cache_backpressure == 1);
  CHECK(source->stats.flexicast_packets_sent == 0);
  for (size_t i = 0; i < TRANSPORT_SENT_CACHE_SIZE; i++)
    CHECK(transport_sent_cache_find(&source->sent_cache, &fixture->track, 0,
                                    i) != NULL);
}

static void test_video_rateless(fixture_t *fixture) {
  transport_t *source = fixture->source.transport;
  uint8_t bytes[6000];
  uint64_t checksum = 0;
  for (size_t i = 0; i < sizeof(bytes); i++) {
    bytes[i] = (uint8_t)(i * 7);
    checksum = checksum * 33 + bytes[i];
  }
  moq_object_t object = object_for(fixture, bytes, sizeof(bytes));
  /* Hold the encoded payloads before protection so the decoder can be fed a
   * precise erasure pattern, independent of RNG and operating-system loss. */
  fixture->flow->rekey_pending = true;
  CHECK(transport_publish_ex(source, &object) == TRANSPORT_PUBLISH_DELIVERED);
  transport_flexicast_queue_t *queue = &fixture->flow->data_queue;
  CHECK(queue->count > 1);
  for (size_t i = 0; i < queue->count; i++) {
    transport_flexicast_queued_payload_t *payload =
        &queue->entries[(queue->head + i) % queue->capacity];
    qlinq_wire_fec_header_t header;
    CHECK(qlinq_wire_decode_fec_header(payload->data, payload->size, &header) ==
          QLINQ_WIRE_OK);
    if (header.symbol_index == 0)
      continue;
    transport_protocol_receive_datagram(
        fixture->clients[0].transport->client_conn,
        ptls_iovec_init(payload->data, payload->size), false);
  }
  CHECK(fixture->clients[0].received == 1);
  CHECK(fixture->clients[0].last_size == sizeof(bytes));
  CHECK(fixture->clients[0].last_checksum == checksum);
}

int main(int argc, char **argv) {
  const char *mode = argc > 1 ? argv[1] : "pacing";
  size_t count = argc > 2 ? strtoul(argv[2], NULL, 10) : 2;
  CHECK(count > 0 && count <= MAX_CLIENTS);
  fixture_t fixture;
  create_fixture(&fixture, count, argc > 3, mode);
  if (strstr(mode, "rekey") || strcmp(mode, "control-queue") == 0)
    test_rekey(&fixture, mode);
  else if (strcmp(mode, "controls") == 0)
    test_controls(&fixture);
  else if (strcmp(mode, "limits") == 0)
    test_limits(&fixture);
  else if (strstr(mode, "cache"))
    test_cache_pressure(&fixture);
  else if (strcmp(mode, "video-rateless") == 0)
    test_video_rateless(&fixture);
  else if (strstr(mode, "fixed") || strstr(mode, "rateless"))
    test_recovery(&fixture);
  else
    test_delivery(&fixture, strstr(mode, "native") != NULL);
  destroy_fixture(&fixture);
  puts("===FLEXICAST REGRESSIONS OK===");
  return 0;
}
