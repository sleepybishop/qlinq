#ifndef TEST_TRANSPORT_FIXTURE_H
#define TEST_TRANSPORT_FIXTURE_H

#include "transport_internal.h"
#include <assert.h>
#include <string.h>
#include <unistd.h>

typedef struct {
  transport_t *transport;
  transport_conn_t *conn;
  bool server, authenticated, failed;
  size_t subscriptions, objects;
  moq_track_id_t last_track;
  uint8_t payload[4096];
  size_t payload_size;
} fixture_endpoint_t;

typedef struct {
  fixture_endpoint_t server, client;
} transport_fixture_t;

static void fixture_event(void *data, const transport_event_t *event) {
  fixture_endpoint_t *endpoint = data;
  endpoint->conn = event->conn;
  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    if (!endpoint->server)
      endpoint->failed |= !transport_send_auth(endpoint->transport, event->conn,
                                              (const uint8_t *)"test", 4);
    break;
  case TRANSPORT_EVENT_AUTH:
    endpoint->failed |= !transport_respond_auth(endpoint->transport, event->conn, true);
    endpoint->authenticated = !endpoint->failed;
    break;
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    endpoint->authenticated = event->auth.success;
    endpoint->failed |= !event->auth.success;
    break;
  case TRANSPORT_EVENT_SUBSCRIBE:
    endpoint->subscriptions++;
    break;
  case TRANSPORT_EVENT_OBJECT:
    endpoint->objects++;
    endpoint->last_track = event->track_id;
    endpoint->payload_size = event->object.size;
    if (event->object.size <= sizeof(endpoint->payload))
      memcpy(endpoint->payload, event->object.data, event->object.size);
    else
      endpoint->failed = true;
    break;
  case TRANSPORT_EVENT_DISCONNECTED:
    endpoint->failed = true;
    break;
  default:
    break;
  }
}

static void fixture_tick(transport_fixture_t *fixture) {
  transport_tick(fixture->server.transport);
  transport_tick(fixture->client.transport);
  assert(!fixture->server.failed && !fixture->client.failed);
  usleep(1000);
}

static void fixture_create(transport_fixture_t *fixture, uint16_t port,
                           const transport_limits_t *server_limits,
                           const transport_limits_t *client_limits) {
  memset(fixture, 0, sizeof(*fixture));
  fixture->server.server = true;
  transport_config_t config = {.bind_hosts = {"127.0.0.1"}, .num_bind_hosts = 1,
                               .port = port, .allow_insecure_peer = true,
                               .callback = fixture_event,
                               .cert_file = "t/assets/server.crt",
                               .key_file = "t/assets/server.key",
                               .user_data = &fixture->server};
  if (server_limits)
    config.limits = *server_limits;
  fixture->server.transport = transport_create(&config);
  assert(fixture->server.transport);
  config.remote_hosts[0] = "127.0.0.1";
  config.num_remote_hosts = 1;
  config.user_data = &fixture->client;
  config.limits = client_limits ? *client_limits : (transport_limits_t){0};
  fixture->client.transport = transport_create(&config);
  assert(fixture->client.transport);
  for (size_t i = 0; i < 2000 && !fixture->client.authenticated; i++)
    fixture_tick(fixture);
  assert(fixture->client.authenticated && fixture->server.authenticated);
}

static void fixture_subscribe(transport_fixture_t *fixture,
                              fixture_endpoint_t *receiver, moq_track_id_t track) {
  fixture_endpoint_t *source = receiver->server ? &fixture->client : &fixture->server;
  size_t expected = source->subscriptions + 1;
  assert(transport_subscribe_conn(receiver->transport, receiver->conn, track));
  for (size_t i = 0; i < 2000 && source->subscriptions < expected; i++)
    fixture_tick(fixture);
  assert(source->subscriptions == expected);
}

static void fixture_receive(transport_fixture_t *fixture,
                            fixture_endpoint_t *receiver, size_t expected) {
  for (size_t i = 0; i < 2000 && receiver->objects < expected; i++)
    fixture_tick(fixture);
  assert(receiver->objects == expected);
}

static void fixture_destroy(transport_fixture_t *fixture) {
  transport_destroy(fixture->client.transport);
  transport_destroy(fixture->server.transport);
}

#endif
