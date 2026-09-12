#include "fec.h"
#include "transport_internal.h"
#include "transport_protocol.h"
#include "transport_subscriptions.h"
#include "transport_wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void count_record(void *data, const transport_event_t *event) {
  if (event->type == TRANSPORT_EVENT_OBJECT)
    ++*(unsigned *)data;
}

static void receive_symbol(transport_conn_t *conn, uint8_t alias, uint64_t id,
                           uint16_t index, uint16_t symbols) {
  uint8_t packet[QLINQ_WIRE_FEC_HEADER_SIZE + 3] = {0};
  qlinq_wire_fec_header_t header = {.alias = alias,
                                    .object_id = id,
                                    .symbol_index = index,
                                    .total_symbols = symbols,
                                    .data_symbols = symbols,
                                    .symbol_size = 3,
                                    .original_size = 3U * symbols};
  (void)qlinq_wire_encode_fec_header(packet, sizeof(packet), &header);
  memcpy(packet + QLINQ_WIRE_FEC_HEADER_SIZE, "abc", 3);
  conn->transport->receive_datagram.cb(&conn->transport->receive_datagram,
                                       conn->quic,
                                       ptls_iovec_init(packet, sizeof(packet)));
}

/* A slowly arriving image must survive arbitrarily many completed small
 * records while other assembler slots are empty. Exercise the wire receiver,
 * not a model of the cache replacement algorithm. */
static int check_interleaved_records(void) {
  unsigned records = 0;
  transport_config_t config = {
      .bind_hosts = {"127.0.0.1"},
      .num_bind_hosts = 1,
      .remote_hosts = {"127.0.0.1"},
      .num_remote_hosts = 1,
      .port = 19867,
      .allow_insecure_peer = true,
      .callback = count_record,
      .user_data = &records,
      .limits = {.max_assemblers_per_connection = 8,
                 .max_assembler_memory_bytes = 1024 * 1024}};
  transport_t *t = transport_create(&config);
  if (!t)
    return 1;
  transport_conn_t *conn = t->client_conn;
  conn->authenticated = true;
  conn->negotiated_limits.max_fec_object_size = 1024;
  int failed =
      !transport_subscriptions_init(&conn->receive_subscriptions, 2) ||
      !transport_subscriptions_add(&conn->receive_subscriptions, MOQ_TRACK_DATA,
                                   MOQ_TRACK_FLAG_FEC_RATELESS, "image", 8) ||
      !transport_subscriptions_add(&conn->receive_subscriptions, MOQ_TRACK_DATA,
                                   MOQ_TRACK_FLAG_FEC_RATELESS, "chat", 9);
  if (!failed) {
    receive_symbol(conn, 8, 0, 0, 2);
    for (unsigned i = 0; i < 24; i++)
      receive_symbol(conn, 9, i, 0, 1);
    receive_symbol(conn, 8, 0, 1, 2);
    failed = records != 25 || t->stats.fec_objects_lost != 0;
    /* Exhausting every live slot still enforces the bounded receive policy. */
    for (unsigned i = 1; i <= 9; i++)
      receive_symbol(conn, 8, i, 0, 2);
    failed |= t->stats.fec_objects_lost != 1;
  }
  transport_destroy(t);
  return failed;
}

typedef struct {
  uint8_t expected[4 * 64];
  unsigned records;
  bool corrupted;
} recovered_record_t;

static void check_recovered_record(void *data, const transport_event_t *event) {
  recovered_record_t *record = data;
  if (event->type != TRANSPORT_EVENT_OBJECT)
    return;
  record->records++;
  if (event->object.size != sizeof(record->expected) ||
      memcmp(event->object.data, record->expected, sizeof(record->expected)))
    record->corrupted = true;
}

/* Exercise the wire receiver with a missing source symbol. Receiving every
 * source symbol bypasses fec_decode and cannot detect a codec mismatch. */
static int check_fec_loss_recovery(void) {
  recovered_record_t record = {0};
  transport_config_t config = {.bind_hosts = {"127.0.0.1"},
                               .num_bind_hosts = 1,
                               .remote_hosts = {"127.0.0.1"},
                               .num_remote_hosts = 1,
                               .port = 19867,
                               .allow_insecure_peer = true,
                               .callback = check_recovered_record,
                               .user_data = &record};
  transport_t *t = transport_create(&config);
  if (!t)
    return 1;
  transport_conn_t *conn = t->client_conn;
  conn->authenticated = true;
  conn->negotiated_limits.max_fec_object_size = sizeof(record.expected);
  const moq_track_type_t types[] = {MOQ_TRACK_VIDEO, MOQ_TRACK_AUDIO,
                                    MOQ_TRACK_INPUT, MOQ_TRACK_TEXT,
                                    MOQ_TRACK_DATA,  MOQ_TRACK_TELEMETRY};
  int failed = 0;
  for (unsigned mode = 0; mode < 2; mode++) {
    uint8_t flags =
        mode ? MOQ_TRACK_FLAG_FEC_RATELESS : MOQ_TRACK_FLAG_FEC_ENABLED;
    uint8_t parity[4][64];
    const uint8_t *data_blocks[4];
    uint8_t *parity_blocks[4];
    for (size_t i = 0; i < sizeof(record.expected); i++)
      record.expected[i] = (uint8_t)(i * 37U + i / 64U);
    for (size_t i = 0; i < 4; i++) {
      data_blocks[i] = record.expected + i * 64;
      parity_blocks[i] = parity[i];
    }
    fec_t *fec = fec_create_ex(mode ? FEC_RAPTORQ : FEC_REED_SOLOMON, 4, 4, 64);
    if (!fec || !fec_encode(fec, data_blocks, parity_blocks)) {
      fec_destroy(fec);
      failed = 1;
      break;
    }
    fec_destroy(fec);

    for (size_t type = 0; type < sizeof(types) / sizeof(types[0]); type++) {
      record.records = 0;
      record.corrupted = false;
      if (!transport_subscriptions_add(&conn->receive_subscriptions,
                                       types[type], flags, "loss", 8)) {
        failed = 1;
        break;
      }
      /* Drop symbol zero, then feed the other source symbols and enough
       * repair equations for RaptorQ even if its first solve is singular. */
      for (uint16_t index = 1; index < 8 && record.records == 0; index++) {
        uint8_t packet[QLINQ_WIRE_FEC_HEADER_SIZE + 64];
        qlinq_wire_fec_header_t header = {.alias = 8,
                                          .object_id = mode * 16U + type,
                                          .symbol_index = index,
                                          .total_symbols = 8,
                                          .data_symbols = 4,
                                          .symbol_size = 64,
                                          .original_size =
                                              sizeof(record.expected)};
        if (qlinq_wire_encode_fec_header(packet, sizeof(packet), &header) !=
            QLINQ_WIRE_OK) {
          failed = 1;
          break;
        }
        memcpy(packet + QLINQ_WIRE_FEC_HEADER_SIZE,
               index < 4 ? data_blocks[index] : parity_blocks[index - 4], 64);
        t->receive_datagram.cb(&t->receive_datagram, conn->quic,
                               ptls_iovec_init(packet, sizeof(packet)));
      }
      if (record.records != 1 || record.corrupted) {
        fprintf(stderr,
                "FEC receive failed: type=%d rateless=%u records=%u "
                "corrupted=%d\n",
                types[type], mode, record.records, record.corrupted);
        failed = 1;
      }
      transport_subscriptions_remove(&conn->receive_subscriptions, types[type],
                                     "loss");
    }
  }
  transport_destroy(t);
  return failed;
}

typedef struct {
  transport_t *transport;
  unsigned records, losses;
  bool resubscribe, unsubscribe;
} callback_state_t;

static void mutate_subscription(void *data, const transport_event_t *event) {
  callback_state_t *state = data;
  if (event->type == TRANSPORT_EVENT_OBJECT)
    state->records++;
  if (event->type != TRANSPORT_EVENT_OBJECT_LOST)
    return;
  state->losses++;
  if (state->unsubscribe) {
    if (!transport_unsubscribe(state->transport, event->track_id))
      abort();
    if (state->resubscribe &&
        !transport_subscribe(state->transport, event->track_id))
      abort();
  }
}

static int check_callback_and_completion_lifetimes(void) {
  for (unsigned mode = 0; mode < 6; mode++) {
    callback_state_t state = {.unsubscribe = mode < 2 || mode >= 4,
                              .resubscribe = mode == 1 || mode == 5};
    transport_config_t config = {
        .bind_hosts = {"127.0.0.1"},
        .num_bind_hosts = 1,
        .remote_hosts = {"127.0.0.1"},
        .num_remote_hosts = 1,
        .port = 19867,
        .allow_insecure_peer = true,
        .callback = mutate_subscription,
        .user_data = &state,
        .limits = {.max_assemblers_per_connection = 1}};
    state.transport = transport_create(&config);
    if (!state.transport)
      return 1;
    transport_t *t = state.transport;
    transport_conn_t *conn = t->client_conn;
    conn->authenticated = conn->protocol_ready = true;
    conn->negotiated_limits = t->limits;
    conn->negotiated_limits.max_fec_object_size = 1024;
    moq_track_id_t track = {
        .type = mode < 2 || mode >= 4 ? MOQ_TRACK_DATA : MOQ_TRACK_VIDEO,
        .flags = mode < 2 || mode >= 4 ? MOQ_TRACK_FLAG_FEC_RATELESS
                                       : MOQ_TRACK_FLAG_FEC_ENABLED,
        .name = "lifetime"};
    if (!transport_subscribe(t, track))
      abort();
    if (mode >= 4) {
      receive_symbol(conn, 8, 0, 0, 2);
      conn->assemblers[0].last_activity_time_ms =
          transport_get_time_ms() - 10000;
      transport_tick(t);
      if (state.losses != 1 || state.records != 0 ||
          t->assembler_memory_bytes != 0)
        abort();
      if (mode == 5) {
        receive_symbol(conn, 8, 1, 0, 1);
        if (state.records != 1)
          abort();
      }
    } else if (mode < 2) {
      receive_symbol(conn, 8, 0, 0, 2);
      receive_symbol(conn, 8, 1, 0,
                     1); /* evicts while holding incoming state */
      if (state.records != 0 || state.losses != 1)
        abort();
      if (mode == 1) {
        receive_symbol(conn, 8, 1, 0, 1);
        if (state.records != 1)
          abort();
      }
    } else {
      /* The receiver must ignore late parity even when it could independently
       * reconstruct the object. Feed actual encoder output. */
      uint8_t parity[3];
      const uint8_t *data_blocks[2] = {(const uint8_t *)"abc",
                                       (const uint8_t *)"abc"};
      uint8_t *parity_blocks[1] = {parity};
      unsigned sources = mode == 2 ? 1 : 2;
      fec_t *fec = fec_create_ex(FEC_REED_SOLOMON, sources, 1, 3);
      if (!fec || !fec_encode(fec, data_blocks, parity_blocks))
        abort();
      fec_destroy(fec);
      for (uint16_t index = 0; index <= sources; index++) {
        uint8_t packet[QLINQ_WIRE_FEC_HEADER_SIZE + 3];
        qlinq_wire_fec_header_t header = {.alias = 8,
                                          .group_id = 42,
                                          .object_id = 0,
                                          .symbol_index = index,
                                          .total_symbols = sources + 1,
                                          .data_symbols = sources,
                                          .symbol_size = 3,
                                          .original_size = 3 * sources};
        if (qlinq_wire_encode_fec_header(packet, sizeof(packet), &header) !=
            QLINQ_WIRE_OK)
          abort();
        memcpy(packet + QLINQ_WIRE_FEC_HEADER_SIZE,
               index < sources ? data_blocks[index] : parity, 3);
        t->receive_datagram.cb(&t->receive_datagram, conn->quic,
                               ptls_iovec_init(packet, sizeof(packet)));
      }
      if (state.records != 1 || conn->assemblers[0].total_symbols != 0)
        abort();
      /* Equal object IDs in different groups and new subscriptions are new
       * objects. Completion history must not leak across either boundary. */
      receive_symbol(conn, 8, 0, 0, 1);
      if (state.records != 2 || !transport_unsubscribe(t, track) ||
          !transport_subscribe(t, track))
        abort();
      receive_symbol(conn, 8, 0, 0, 1);
      if (state.records != 3)
        abort();
      transport_tick(t);
      if (state.losses != 0)
        abort();
    }
    transport_destroy(t);
  }
  return 0;
}

int main(void) {
  if (check_callback_and_completion_lifetimes() || check_fec_loss_recovery())
    return 1;
  if (check_interleaved_records()) {
    fputs("interleaved receive regression failed\n", stderr);
    return 1;
  }
  puts("===INTERLEAVED RECEIVE OK===");
  return 0;
}
