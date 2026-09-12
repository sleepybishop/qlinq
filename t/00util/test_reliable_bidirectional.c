#include "transport.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define EXCHANGES 220U
#define SERVICE_ATTEMPTS 2000U

typedef struct {
  transport_t *transport;
  bool is_server;
  bool connected;
  bool authenticated;
  bool peer_subscribed;
  bool failed;
  size_t received;
} endpoint_state_t;

static const moq_track_id_t reliable_track = {
    .type = MOQ_TRACK_DATA,
    .flags = MOQ_TRACK_FLAG_RELIABLE,
    .name = "bidirectional-reliable",
};

static bool track_matches(const moq_track_id_t *track) {
  return track->type == reliable_track.type &&
         strcmp(track->name, reliable_track.name) == 0;
}

static void on_event(void *user_data, const transport_event_t *event) {
  endpoint_state_t *state = user_data;

  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    state->connected = true;
    if (!state->is_server &&
        !transport_send_auth(state->transport, event->conn,
                             (const uint8_t *)"bidirectional-reliable-test",
                             strlen("bidirectional-reliable-test")))
      state->failed = true;
    break;
  case TRANSPORT_EVENT_AUTH:
    if (state->is_server &&
        !transport_respond_auth(state->transport, event->conn, true))
      state->failed = true;
    break;
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    state->authenticated = event->auth.success;
    state->failed |= !event->auth.success;
    break;
  case TRANSPORT_EVENT_SUBSCRIBE:
    if (track_matches(&event->track_id))
      state->peer_subscribed = true;
    break;
  case TRANSPORT_EVENT_OBJECT:
    if (track_matches(&event->track_id)) {
      uint64_t payload = UINT64_MAX;
      uint64_t expected =
          state->is_server ? state->received * 2U + 1U : state->received * 2U;
      if (event->object.size == sizeof(payload))
        memcpy(&payload, event->object.data, sizeof(payload));
      if (event->object.object_id != expected || payload != expected)
        state->failed = true;
      state->received++;
    }
    break;
  case TRANSPORT_EVENT_DISCONNECTED:
    state->failed = true;
    break;
  default:
    break;
  }
}

static bool service_until(transport_t *server, transport_t *client,
                          const bool *condition, endpoint_state_t *server_state,
                          endpoint_state_t *client_state) {
  for (size_t attempt = 0; attempt < SERVICE_ATTEMPTS; attempt++) {
    transport_tick(server);
    transport_tick(client);
    if (*condition)
      return !server_state->failed && !client_state->failed;
    if (server_state->failed || client_state->failed)
      return false;
    usleep(1000);
  }
  return false;
}

static bool service_until_received(transport_t *server, transport_t *client,
                                   endpoint_state_t *receiver, size_t target,
                                   endpoint_state_t *server_state,
                                   endpoint_state_t *client_state) {
  for (size_t attempt = 0; attempt < SERVICE_ATTEMPTS; attempt++) {
    transport_tick(server);
    transport_tick(client);
    if (receiver->received == target)
      return !server_state->failed && !client_state->failed;
    if (server_state->failed || client_state->failed)
      return false;
    usleep(1000);
  }
  return false;
}

int main(void) {
  endpoint_state_t server_state = {.is_server = true};
  endpoint_state_t client_state = {0};
  transport_config_t server_config = {
      .bind_hosts = {"127.0.0.1"},
      .num_bind_hosts = 1,
      .port = 19927,
      .cert_file = "t/assets/server.crt",
      .key_file = "t/assets/server.key",
      .callback = on_event,
      .allow_insecure_peer = true,
      .user_data = &server_state,
  };
  transport_config_t client_config = {
      .bind_hosts = {"127.0.0.1"},
      .num_bind_hosts = 1,
      .remote_hosts = {"127.0.0.1"},
      .num_remote_hosts = 1,
      .port = 19927,
      .callback = on_event,
      .allow_insecure_peer = true,
      .user_data = &client_state,
  };
  int result = 1;

  server_state.transport = transport_create(&server_config);
  client_state.transport = transport_create(&client_config);
  if (!server_state.transport || !client_state.transport) {
    fprintf(stderr, "failed to create bidirectional transports\n");
    goto cleanup;
  }

  if (!service_until(server_state.transport, client_state.transport,
                     &client_state.authenticated, &server_state,
                     &client_state)) {
    fprintf(stderr, "bidirectional authentication did not complete\n");
    goto cleanup;
  }

  if (!transport_subscribe(client_state.transport, reliable_track) ||
      !service_until(server_state.transport, client_state.transport,
                     &server_state.peer_subscribed, &server_state,
                     &client_state)) {
    fprintf(stderr, "server did not receive reliable subscription\n");
    goto cleanup;
  }
  if (!transport_subscribe(server_state.transport, reliable_track) ||
      !service_until(server_state.transport, client_state.transport,
                     &client_state.peer_subscribed, &server_state,
                     &client_state)) {
    fprintf(stderr, "client did not receive reliable subscription\n");
    goto cleanup;
  }

  for (uint64_t sequence = 0; sequence < EXCHANGES; sequence++) {
    endpoint_state_t *publisher =
        sequence % 2U == 0 ? &server_state : &client_state;
    endpoint_state_t *receiver =
        sequence % 2U == 0 ? &client_state : &server_state;
    size_t expected_received = receiver->received + 1U;
    moq_object_t object = {
        .track_id = reliable_track,
        .group_id = 1,
        .object_id = sequence,
        .data = (const uint8_t *)&sequence,
        .size = sizeof(sequence),
    };

    if (!transport_publish(publisher->transport, &object)) {
      fprintf(stderr, "reliable publish failed at exchange %" PRIu64 "\n",
              sequence);
      goto cleanup;
    }
    if (!service_until_received(server_state.transport, client_state.transport,
                                receiver, expected_received, &server_state,
                                &client_state)) {
      fprintf(stderr, "reliable exchange %" PRIu64 " was not delivered\n",
              sequence);
      goto cleanup;
    }
  }

  if (server_state.received != EXCHANGES / 2U ||
      client_state.received != EXCHANGES / 2U) {
    fprintf(stderr, "bidirectional delivery totals were incomplete\n");
    goto cleanup;
  }

  puts("===RELIABLE BIDIRECTIONAL OK===");
  result = 0;

cleanup:
  transport_destroy(client_state.transport);
  transport_destroy(server_state.transport);
  return result;
}
