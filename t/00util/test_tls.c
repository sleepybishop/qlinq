/* Mutual-TLS acceptance and rejection integration test. */

#include "transport.h"

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

typedef struct {
  transport_t *transport;
  bool server;
  uint32_t connected;
  uint32_t authenticated;
  uint32_t disconnected;
  uint64_t disconnect_error;
} tls_state_t;

static void on_event(void *user_data, const transport_event_t *event) {
  tls_state_t *state = user_data;
  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    state->connected++;
    if (!state->server)
      (void)transport_send_auth(state->transport, event->conn,
                                (const uint8_t *)"tls-test", 8);
    break;
  case TRANSPORT_EVENT_AUTH:
    if (state->server) {
      state->authenticated++;
      (void)transport_respond_auth(state->transport, event->conn, true);
    }
    break;
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    if (event->auth.success)
      state->authenticated++;
    break;
  case TRANSPORT_EVENT_DISCONNECTED:
    state->disconnected++;
    state->disconnect_error = event->disconnect.error_code;
    break;
  default:
    break;
  }
}

static transport_t *create_endpoint(tls_state_t *state, uint16_t port,
                                    const char *host, const char *identity_file,
                                    const char *key_file,
                                    const char *trust_file) {
  transport_config_t config = {0};
  config.bind_hosts[0] = host;
  config.num_bind_hosts = 1;
  if (!state->server) {
    config.remote_hosts[0] = host;
    config.num_remote_hosts = 1;
  }
  config.port = port;
  config.cert_file = identity_file;
  config.key_file = key_file;
  config.ca_file = trust_file;
  config.verify_peer = true;
  config.quic_idle_timeout_ms = 500;
  config.callback = on_event;
  config.user_data = state;
  state->transport = transport_create(&config);
  return state->transport;
}

static bool drive(tls_state_t *server_state, tls_state_t *client_state,
                  int iterations) {
  while (iterations-- > 0) {
    transport_tick(server_state->transport);
    transport_tick(client_state->transport);
    if (server_state->authenticated && client_state->authenticated)
      return true;
    usleep(5000);
  }
  return false;
}

static void drain_and_destroy(tls_state_t *server_state,
                              tls_state_t *client_state) {
  transport_shutdown(client_state->transport, "TLS test complete");
  for (int i = 0; i < 400; i++) {
    transport_tick(client_state->transport);
    transport_tick(server_state->transport);
    if (transport_is_drained(client_state->transport) &&
        transport_is_drained(server_state->transport))
      break;
    usleep(5000);
  }
  transport_destroy(client_state->transport);
  transport_destroy(server_state->transport);
}

int main(void) {
  tls_state_t trusted_server = {.server = true};
  tls_state_t trusted_client = {0};
  if (!create_endpoint(&trusted_server, 10002, "127.0.0.1",
                       "t/assets/verified.crt", "t/assets/verified.key",
                       "t/assets/verified.crt") ||
      transport_reload_credentials(trusted_server.transport,
                                   "t/assets/verified.crt",
                                   "t/assets/untrusted.key") ||
      !create_endpoint(&trusted_client, 10002, "127.0.0.1",
                       "t/assets/verified.crt", "t/assets/verified.key",
                       "t/assets/verified.crt") ||
      !drive(&trusted_server, &trusted_client, 500)) {
    fprintf(stderr, "trusted mutual-TLS session did not authenticate\n");
    if (trusted_client.transport)
      transport_destroy(trusted_client.transport);
    if (trusted_server.transport)
      transport_destroy(trusted_server.transport);
    return 1;
  }
  drain_and_destroy(&trusted_server, &trusted_client);

  tls_state_t ipv6_server = {.server = true};
  tls_state_t ipv6_client = {0};
  if (!create_endpoint(&ipv6_server, 10004, "::1", "t/assets/verified-v6.crt",
                       "t/assets/verified-v6.key",
                       "t/assets/verified-v6.crt") ||
      !create_endpoint(&ipv6_client, 10004, "::1", "t/assets/verified-v6.crt",
                       "t/assets/verified-v6.key",
                       "t/assets/verified-v6.crt") ||
      !drive(&ipv6_server, &ipv6_client, 500)) {
    fprintf(stderr, "IPv6 mutual-TLS session did not authenticate\n");
    if (ipv6_client.transport)
      transport_destroy(ipv6_client.transport);
    if (ipv6_server.transport)
      transport_destroy(ipv6_server.transport);
    return 1;
  }
  drain_and_destroy(&ipv6_server, &ipv6_client);

  tls_state_t rejected_server = {.server = true};
  tls_state_t rejected_client = {0};
  if (!create_endpoint(&rejected_server, 10003, "127.0.0.1",
                       "t/assets/verified.crt", "t/assets/verified.key",
                       "t/assets/verified.crt") ||
      !create_endpoint(&rejected_client, 10003, "127.0.0.1",
                       "t/assets/verified.crt", "t/assets/verified.key",
                       "t/assets/untrusted.crt")) {
    fprintf(stderr, "unable to create rejected TLS test endpoints\n");
    if (rejected_client.transport)
      transport_destroy(rejected_client.transport);
    if (rejected_server.transport)
      transport_destroy(rejected_server.transport);
    return 1;
  }
  (void)drive(&rejected_server, &rejected_client, 500);
  transport_stats_t rejected_stats = {0};
  (void)transport_get_stats(rejected_client.transport, &rejected_stats);
  if (rejected_client.connected != 0 || rejected_client.authenticated != 0 ||
      rejected_stats.protocol_handshakes_completed != 0) {
    fprintf(stderr, "untrusted server certificate was accepted\n");
    transport_destroy(rejected_client.transport);
    transport_destroy(rejected_server.transport);
    return 1;
  }
  transport_destroy(rejected_client.transport);
  transport_destroy(rejected_server.transport);

  printf("===TLS OK===\n");
  return 0;
}
