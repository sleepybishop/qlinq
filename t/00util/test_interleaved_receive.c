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

int main(void) {
  if (check_interleaved_records()) {
    fputs("interleaved receive regression failed\n", stderr);
    return 1;
  }
  puts("===INTERLEAVED RECEIVE OK===");
  return 0;
}
