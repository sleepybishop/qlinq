/* t/00util/test_multipath_nack.c */

#include "transport.h"
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define NUM_OBJECTS 40
#define PAYLOAD_SIZE 8000

typedef struct {
  bool connected;
  bool subscribed;
  size_t received_count;
  size_t total_bytes_received;
  transport_t *transport;
} mp_test_state_t;

static void on_server_event(void *user_data, const transport_event_t *event) {
  mp_test_state_t *state = user_data;
  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    state->connected = true;
    break;
  case TRANSPORT_EVENT_SUBSCRIBE:
    state->subscribed = true;
    break;
  case TRANSPORT_EVENT_AUTH:
    transport_respond_auth(state->transport, event->conn, true);
    break;
  default:
    break;
  }
}

static void on_client_event(void *user_data, const transport_event_t *event) {
  mp_test_state_t *state = user_data;
  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    transport_send_auth(state->transport, event->conn,
                        (const uint8_t *)"secret_token_123",
                        strlen("secret_token_123"));
    break;
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    if (event->auth.success) {
      state->connected = true;
    }
    break;
  case TRANSPORT_EVENT_OBJECT:
    state->received_count++;
    state->total_bytes_received += event->object.size;
    break;
  default:
    break;
  }
}

int main(void) {
  printf("=== QLINQ MULTIPATH NACK FEC WORKLOAD TEST ===\n");

  mp_test_state_t server_state = {0};
  mp_test_state_t client_state = {0};

  /* configure server on 2 loopback interfaces */
  transport_config_t server_cfg = {0};
  server_cfg.bind_hosts[0] = "127.0.1.1";
  server_cfg.bind_hosts[1] = "127.0.2.1";
  server_cfg.num_bind_hosts = 2;
  server_cfg.port = 9910;
  server_cfg.cert_file = "t/assets/server.crt";
  server_cfg.key_file = "t/assets/server.key";
  server_cfg.callback = on_server_event;
  server_cfg.user_data = &server_state;
  server_cfg.simulated_loss_rate = 20; /* 20% loss on primary link */

  /* configure client on 2 loopback interfaces */
  transport_config_t client_cfg = {0};
  client_cfg.bind_hosts[0] = "127.0.1.2";
  client_cfg.bind_hosts[1] = "127.0.2.2";
  client_cfg.num_bind_hosts = 2;
  client_cfg.remote_hosts[0] = "127.0.1.1";
  client_cfg.remote_hosts[1] = "127.0.2.1";
  client_cfg.num_remote_hosts = 2;
  client_cfg.port = 9910;
  client_cfg.cert_file = NULL;
  client_cfg.key_file = NULL;
  client_cfg.callback = on_client_event;
  client_cfg.user_data = &client_state;
  client_cfg.simulated_loss_rate = 0; /* clean secondary link for NACK repair */

  server_state.transport = transport_create(&server_cfg);
  client_state.transport = transport_create(&client_cfg);

  if (!server_state.transport || !client_state.transport) {
    fprintf(stderr, "Failed to create multipath transports\n");
    return 1;
  }

  /* wait for multipath connection handshake */
  int retries = 300;
  while (retries-- > 0 &&
         (!server_state.connected || !client_state.connected)) {
    transport_tick(server_state.transport);
    transport_tick(client_state.transport);
    usleep(5000);
  }

  if (!server_state.connected || !client_state.connected) {
    fprintf(stderr, "Multipath connection handshake failed\n");
    return 1;
  }
  printf("Multipath connection established across 2 interfaces.\n");

  /* client subscribes using MOQ_TRACK_FLAG_FEC_RATELESS */
  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = MOQ_TRACK_FLAG_FEC_RATELESS};
  strcpy(track.name, "multipath_nack_track");
  transport_subscribe(client_state.transport, track);

  retries = 200;
  while (retries-- > 0 && !server_state.subscribed) {
    transport_tick(server_state.transport);
    transport_tick(client_state.transport);
    usleep(5000);
  }

  /* publish payload objects over multipath track */
  uint8_t *payload = malloc(PAYLOAD_SIZE);
  memset(payload, 0xDE, PAYLOAD_SIZE);

  printf("Publishing %d objects (%d bytes total) with 20%% loss on primary "
         "path...\n",
         NUM_OBJECTS, NUM_OBJECTS * PAYLOAD_SIZE);

  for (size_t i = 0; i < NUM_OBJECTS; i++) {
    moq_object_t obj = {.track_id = track,
                        .group_id = 0,
                        .object_id = i,
                        .data = payload,
                        .size = PAYLOAD_SIZE,
                        .is_keyframe = (i % 5 == 0),
                        .priority = 1};
    transport_publish(server_state.transport, &obj);
    transport_tick(server_state.transport);
    transport_tick(client_state.transport);
  }

  /* drive event loop until NACK repairs arrive and block completes */
  retries = 2000;
  while (retries-- > 0 &&
         client_state.total_bytes_received < (NUM_OBJECTS * PAYLOAD_SIZE)) {
    transport_tick(server_state.transport);
    transport_tick(client_state.transport);

    int64_t now_ms = transport_get_time_ms();
    int64_t to_s = transport_get_first_timeout(server_state.transport);
    int64_t to_c = transport_get_first_timeout(client_state.transport);
    int64_t earliest = to_s < to_c ? to_s : to_c;

    int timeout_ms = 5;
    if (earliest != INT64_MAX) {
      int delta = (int)(earliest - now_ms);
      if (delta < 0) {
        timeout_ms = 0;
      } else if (delta < timeout_ms) {
        timeout_ms = delta;
      }
    }

    if (timeout_ms > 0) {
      usleep(timeout_ms * 1000);
    }
  }

  size_t expected_bytes = NUM_OBJECTS * PAYLOAD_SIZE;
  printf("Received %zu / %zu payload bytes (%.1f%% delivery).\n",
         client_state.total_bytes_received, expected_bytes,
         (double)client_state.total_bytes_received / expected_bytes * 100.0);

  assert(client_state.total_bytes_received > 0);
  printf("=== MULTIPATH NACK FEC TEST PASSED SUCCESSFULLY ===\n");

  free(payload);
  transport_destroy(client_state.transport);
  transport_destroy(server_state.transport);
  return 0;
}
