#include "cli_parse.h"
#include "transport_config.h"
#include "transport_internal.h"
#include "transport_protocol.h"
#include "transport_stream.h"
#include "transport_wire.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct {
  transport_t *transport;
  bool server, authenticated;
  unsigned objects, lost, disconnected;
  uint64_t error;
  char reason[64];
} endpoint_t;

static void event(void *data, const transport_event_t *ev) {
  endpoint_t *ep = data;
  switch (ev->type) {
  case TRANSPORT_EVENT_CONNECTED:
    if (!ep->server)
      assert(transport_send_auth(ep->transport, ev->conn, (const uint8_t *)"x",
                                 1));
    break;
  case TRANSPORT_EVENT_AUTH:
    assert(transport_respond_auth(ep->transport, ev->conn, true));
    break;
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    assert(ev->auth.success);
    ep->authenticated = true;
    break;
  case TRANSPORT_EVENT_OBJECT:
    ep->objects++;
    break;
  case TRANSPORT_EVENT_OBJECT_LOST:
    ep->lost++;
    break;
  case TRANSPORT_EVENT_DISCONNECTED:
    ep->disconnected++;
    ep->error = ev->disconnect.error_code;
    snprintf(ep->reason, sizeof(ep->reason), "%s", ev->disconnect.reason);
    break;
  default:
    break;
  }
}

static void parsers_and_limits(void) {
  uint64_t number = 77;
  assert(cli_parse_u64("18446744073709551615", UINT64_MAX, &number));
  assert(number == UINT64_MAX);
  const char *bad[] = {"",   "-1", " -1", "+1",
                       " 1", "1 ", "1x",  "18446744073709551616"};
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    assert(!cli_parse_u64(bad[i], UINT64_MAX, &number));
  assert(!cli_parse_u64("256", 255, &number));
  assert(cli_parse_u64("0", 0, &number) && number == 0);
  char host[64];
  uint16_t port = 443;
  bool explicit_port;
  assert(cli_parse_endpoint("[fe80::1%lo]:1234", host, sizeof(host), &port,
                            &explicit_port));
  assert(strcmp(host, "fe80::1%lo") == 0 && port == 1234 && explicit_port);
  assert(cli_parse_endpoint("::1", host, sizeof(host), &port, &explicit_port));
  assert(strcmp(host, "::1") == 0 && port == 1234 && !explicit_port);
  assert(cli_parse_endpoint("host:65535", host, sizeof(host), &port, NULL));
  assert(port == 65535);
  const char *bad_endpoints[] = {"host:",     "host:0", "host:65536", "[::1",
                                 "[::1]junk", ":80",    "[]"};
  for (size_t i = 0; i < sizeof(bad_endpoints) / sizeof(bad_endpoints[0]); i++)
    assert(
        !cli_parse_endpoint(bad_endpoints[i], host, sizeof(host), &port, NULL));
  assert(!cli_parse_endpoint("long", host, 4, &port, NULL));

  transport_repair_limiter_t limiter = {0};
  assert(transport_repair_limiter_wait_ms(&limiter, 2, 1000) == 0);
  assert(transport_repair_limiter_take(&limiter, 2, 1000));
  assert(transport_repair_limiter_wait_ms(&limiter, 2, 1000) == 0);
  assert(transport_repair_limiter_take(&limiter, 2, 1000));
  assert(transport_repair_limiter_wait_ms(&limiter, 2, 1000) == 500);
  assert(transport_repair_limiter_wait_ms(&limiter, 2, 1499) == 1);
  assert(!transport_repair_limiter_take(&limiter, 2, 1499));
  assert(transport_repair_limiter_take(&limiter, 2, 1500));
  assert(transport_repair_limiter_wait_ms(&limiter, 0, 1500) == UINT64_MAX);
  transport_limits_t requested = {0}, resolved;
  char error[128];
  assert(transport_limits_resolve(&requested, &resolved, error, sizeof(error)));
  assert(resolved.max_aggregate_nack_requests_per_second == 16);
  requested.max_aggregate_nack_requests_per_second = 65536;
  assert(
      !transport_limits_resolve(&requested, &resolved, error, sizeof(error)));
}

static void tick_all(endpoint_t ep[3]) {
  for (size_t i = 0; i < 3; i++)
    transport_tick(ep[i].transport);
  usleep(1000);
}

static void transport_regressions(void) {
  endpoint_t ep[3] = {{.server = true}, {0}, {0}};
  transport_config_t config = {
      .bind_hosts = {"127.0.0.1"},
      .num_bind_hosts = 1,
      .port = 19933,
      .allow_insecure_peer = true,
      .callback = event,
      .cert_file = "t/assets/server.crt",
      .key_file = "t/assets/server.key",
      .fec_assembler_timeout_ms = 10000,
      .initial_rtt_ms = 125,
      .handshake_timeout_rtt_multiplier = 40,
      .limits = {.max_aggregate_nack_requests_per_second = 1}};
  for (size_t i = 0; i < 3; i++) {
    config.user_data = &ep[i];
    ep[i].transport = transport_create(&config);
    assert(ep[i].transport);
    assert(ep[i].transport->fec_assembler_timeout_ms == 10000);
    assert(ep[i].transport->quic_ctx.loss.default_initial_rtt == 125);
    assert(ep[i].transport->quic_ctx.handshake_timeout_rtt_multiplier == 40);
    config.remote_hosts[0] = "127.0.0.1";
    config.num_remote_hosts = 1;
  }
  for (size_t n = 0; n < 2000 && (!ep[1].authenticated || !ep[2].authenticated);
       n++)
    tick_all(ep);
  assert(ep[1].authenticated && ep[2].authenticated);
  transport_t *t = ep[0].transport;
  assert(t->conn_count == 2);
  transport_conn_t *a = t->conns[0], *b = t->conns[1];

  /* Distinct clients continue routing correctly with warm/colliding hints. */
  const quicly_cid_plaintext_t cid = *quicly_get_master_id(a->quic);
  transport_connection_cache_remember(t, a);
  assert(transport_connection_cache_find(t, &cid) == a);
  t->connection_cache[cid.master_id % QLINQ_CONNECTION_CACHE_SLOTS] = b;
  assert(transport_connection_cache_find(t, &cid) == NULL);
  for (size_t i = 1; i < 3; i++)
    assert(transport_send_unicast(ep[i].transport, ep[i].transport->client_conn,
                                  "x", 1));
  for (size_t n = 0; n < 1000 && ep[0].objects < 2; n++)
    tick_all(ep);
  assert(ep[0].objects == 2);
  transport_connection_cache_remember(t, a);
  transport_connection_cache_forget(t, a);
  assert(transport_connection_cache_find(t, &cid) == NULL);

  quicly_path_stats_t stats;
  size_t index = transport_path_get_stats_by_link(a->quic, t->local_addrs,
                                                  t->num_fds, 0, &stats);
  assert(index != SIZE_MAX &&
         transport_path_matches_local(&stats, &t->local_addrs[0]));
  assert(transport_path_get_stats_by_link(a->quic, t->local_addrs, t->num_fds,
                                          t->num_fds, &stats) == SIZE_MAX);
  struct sockaddr_storage v6 = {0};
  struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&v6;
  addr6->sin6_family = AF_INET6;
  addr6->sin6_scope_id = 2;
  stats.local.sin6 = *addr6;
  assert(transport_path_matches_local(&stats, &v6));
  addr6->sin6_scope_id = 3;
  assert(!transport_path_matches_local(&stats, &v6));

  for (size_t i = 0; i < 2; i++)
    assert(transport_subscriptions_add(
        &t->conns[i]->receive_subscriptions, MOQ_TRACK_DATA,
        MOQ_TRACK_FLAG_FEC_RATELESS, "recovery", 8));
  assert(transport_protocol_send_nack(a, 8, 0, 100, NULL, 0, true));
  uint64_t b_tokens = b->nack_request_limiter.tokens_milli;
  assert(!transport_protocol_send_nack(b, 8, 0, 100, NULL, 0, true));
  /* Inspection may initialize the peer bucket, but aggregate rejection spends
   * nothing. */
  assert(b->nack_request_limiter.tokens_milli == b_tokens ||
         b->nack_request_limiter.tokens_milli ==
             t->limits.max_repair_requests_per_second * 1000);
  assert(transport_protocol_send_nack(a, 8, 0, 100, NULL, 0, true));
  assert(t->stats.repair_requests_sent == 1 &&
         t->stats.repair_requests_coalesced == 1);

  /* Only one fresh request can be admitted per refill; the second peer gets
   * the next turn even while the first peer still has missing objects. */
  for (size_t i = 0; i < 2; i++) {
    transport_object_gap_state_t *gap = transport_object_gap(t->conns[i], 8);
    assert(gap);
    gap->pending_mask = 1;
    gap->pending_base = 200;
    gap->detected_at_ms = transport_get_time_ms() - 1000;
  }
  for (size_t turn = 0; turn < 2; turn++) {
    t->aggregate_nack_limiter.last_refill_ms = transport_get_time_ms() - 1000;
    transport_tick(t);
    assert(t->stats.repair_requests_sent == turn + 2);
    assert(t->recovery_conn_cursor == (turn + 1) % 2);
    assert(t->aggregate_nack_retry_at_ms > transport_get_time_ms());
    assert(transport_get_first_timeout(t) <= t->aggregate_nack_retry_at_ms);
    transport_object_gap(a, 8)->detected_at_ms = transport_get_time_ms() - 1000;
  }

  /* Receive an incomplete object and expire it despite an empty NACK bucket. */
  uint8_t packet[QLINQ_WIRE_FEC_HEADER_SIZE + 3] = {0};
  qlinq_wire_fec_header_t header = {.alias = 8,
                                    .object_id = 300,
                                    .total_symbols = 2,
                                    .data_symbols = 2,
                                    .symbol_size = 3,
                                    .original_size = 6};
  assert(qlinq_wire_encode_fec_header(packet, sizeof(packet), &header) ==
         QLINQ_WIRE_OK);
  t->receive_datagram.cb(&t->receive_datagram, a->quic,
                         ptls_iovec_init(packet, sizeof(packet)));
  frame_assembler_t *assembler = NULL;
  for (size_t i = 0; i < t->limits.max_assemblers_per_connection; i++)
    if (a->assemblers[i].total_symbols)
      assembler = &a->assemblers[i];
  assert(assembler && t->assembler_memory_bytes > 0);
  assembler->last_activity_time_ms = transport_get_time_ms() - 2001;
  transport_tick(t);
  assert(assembler->total_symbols && ep[0].lost == 0);
  assembler->last_activity_time_ms = transport_get_time_ms() - 10001;
  assert(transport_get_first_timeout(t) <= transport_get_time_ms());
  transport_tick(t);
  assert(!assembler->total_symbols && t->assembler_memory_bytes == 0 &&
         ep[0].lost == 1);

  transport_close_conn_with_error(t, ep[1].transport->client_conn,
                                  TRANSPORT_APP_ERROR_RESOURCE_LIMIT,
                                  "foreign");
  transport_close_conn_with_error(t, b, 123, "invalid");
  assert(quicly_get_state(b->quic) < QUICLY_STATE_CLOSING);
  transport_close_conn_with_error(t, b, TRANSPORT_APP_ERROR_RESOURCE_LIMIT,
                                  "application capacity");
  transport_close_conn_with_error(t, b, TRANSPORT_APP_ERROR_PROTOCOL,
                                  "replace");
  assert(t->stats.resource_limit_errors == 1);
  assert(quicly_get_close_reason(b->quic, NULL, NULL, NULL) ==
         TRANSPORT_APP_ERROR_RESOURCE_LIMIT);
  /* Pending recovery requests need no further peer service in this fixture. */
  for (size_t i = 1; i < 3; i++)
    transport_destroy(ep[i].transport);
  transport_destroy(t);
}

int main(void) {
  parsers_and_limits();
  transport_regressions();
  puts("===GENERIC PORTS OK===");
  return 0;
}
