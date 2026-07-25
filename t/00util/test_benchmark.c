/* test_benchmark.c */

#include "transport.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define OBJECTS_PER_RUN 50
#define PAYLOAD_SIZE 10000

typedef struct {
  bool connected;
  bool subscribed;
  size_t received_count;
  struct timespec receive_times[OBJECTS_PER_RUN];
  transport_t *transport;
} test_state_t;

static void on_server_event(void *user_data, const transport_event_t *event) {
  test_state_t *state = user_data;
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
  test_state_t *state = user_data;
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
    if (event->object.object_id < OBJECTS_PER_RUN) {
      clock_gettime(CLOCK_MONOTONIC,
                    &state->receive_times[event->object.object_id]);
      state->received_count++;
    }
    break;
  default:
    break;
  }
}

static double get_delta_ms(struct timespec start, struct timespec end) {
  return (end.tv_sec - start.tv_sec) * 1000.0 +
         (end.tv_nsec - start.tv_nsec) / 1000000.0;
}

static void run_benchmark(uint8_t loss_rate, moq_track_type_t track_type,
                          uint8_t flags, const char *track_name) {
  test_state_t server_state = {0};
  test_state_t client_state = {0};

  transport_config_t server_cfg = {0};
  server_cfg.bind_hosts[0] = "127.0.0.1";
  server_cfg.num_bind_hosts = 1;
  server_cfg.port = 9900 + loss_rate + track_type;
  server_cfg.cert_file = "t/assets/server.crt";
  server_cfg.key_file = "t/assets/server.key";
  server_cfg.callback = on_server_event;
  server_cfg.user_data = &server_state;
  server_cfg.simulated_loss_rate = loss_rate;

  transport_config_t client_cfg = {0};
  client_cfg.bind_hosts[0] = "127.0.0.1";
  client_cfg.num_bind_hosts = 1;
  client_cfg.remote_hosts[0] = "127.0.0.1";
  client_cfg.num_remote_hosts = 1;
  client_cfg.port = 9900 + loss_rate + track_type;
  client_cfg.cert_file = NULL;
  client_cfg.key_file = NULL;
  client_cfg.callback = on_client_event;
  client_cfg.user_data = &client_state;
  client_cfg.simulated_loss_rate = loss_rate;

  server_state.transport = transport_create(&server_cfg);
  client_state.transport = transport_create(&client_cfg);

  if (!server_state.transport || !client_state.transport) {
    fprintf(stderr, "Failed to create transports\n");
    exit(1);
  }

  /* wait for connection */
  int retries = 200;
  while (retries-- > 0 &&
         (!server_state.connected || !client_state.connected)) {
    transport_tick(server_state.transport);
    transport_tick(client_state.transport);
    usleep(5 * 1000);
  }

  if (!server_state.connected || !client_state.connected) {
    fprintf(stderr, "Connection failed\n");
    exit(1);
  }

  /* client subscribes to track */
  moq_track_id_t track = {.type = track_type, .flags = flags};
  strcpy(track.name, track_name);
  transport_subscribe(client_state.transport, track);

  retries = 200;
  while (retries-- > 0 && !server_state.subscribed) {
    transport_tick(server_state.transport);
    transport_tick(client_state.transport);
    usleep(5 * 1000);
  }

  /* allocate test payload */
  uint8_t *payload = malloc(PAYLOAD_SIZE);
  memset(payload, 0xA5, PAYLOAD_SIZE);

  struct timespec send_times[OBJECTS_PER_RUN];
  double total_latency = 0;
  size_t matched_latency_count = 0;

  /* publish objects */
  for (size_t i = 0; i < OBJECTS_PER_RUN; i++) {
    moq_object_t obj = {.track_id = track,
                        .group_id = 0,
                        .object_id = i,
                        .data = payload,
                        .size = PAYLOAD_SIZE,
                        .is_keyframe = (i % 10 == 0),
                        .priority = 1};
    clock_gettime(CLOCK_MONOTONIC, &send_times[i]);
    transport_publish(server_state.transport, &obj);

    /* run ticks to drive egress and network loop */
    for (int t = 0; t < 10; t++) {
      transport_tick(server_state.transport);
      transport_tick(client_state.transport);
      usleep(1000);
    }
  }

  /* wait for any remaining in-flight objects to land */
  retries = 100;
  while (retries-- > 0) {
    transport_tick(server_state.transport);
    transport_tick(client_state.transport);
    usleep(5 * 1000);
  }

  /* calculate latency for successfully received objects */
  for (size_t i = 0; i < OBJECTS_PER_RUN; i++) {
    if (client_state.receive_times[i].tv_sec != 0) {
      double lat = get_delta_ms(send_times[i], client_state.receive_times[i]);
      total_latency += lat;
      matched_latency_count++;
    }
  }

  double avg_latency =
      matched_latency_count > 0 ? (total_latency / matched_latency_count) : 0.0;
  double delivery_rate =
      (double)client_state.received_count / OBJECTS_PER_RUN * 100.0;

  printf("| %4s | %-16s | %5d%% | %14d | %15.1f%% | %15.2f ms |\n",
         (flags & MOQ_TRACK_FLAG_RELIABLE) ? "TCP" : "UDP", track_name,
         loss_rate, OBJECTS_PER_RUN, delivery_rate, avg_latency);

  free(payload);
  transport_destroy(client_state.transport);
  transport_destroy(server_state.transport);
}

int main(void) {
  srand(time(NULL));

  printf("\n=================================== QLINQ BENCHMARK REPORT "
         "===================================\n");
  printf("| Type | Track            | Loss%% | Objects Sent | Delivery Rate | "
         "Avg Latency (RTT/2) |\n");
  printf("|------|------------------|-------|--------------|---------------|---"
         "------------------|\n");

  /* Test Group 1: Pristine network (0% loss) */
  run_benchmark(0, MOQ_TRACK_VIDEO, MOQ_TRACK_FLAG_FEC_ENABLED,
                "Video (FEC-RS)");
  run_benchmark(0, MOQ_TRACK_DATA, MOQ_TRACK_FLAG_FEC_ENABLED, "Data (FEC-RQ)");
  run_benchmark(0, MOQ_TRACK_AUDIO, 0, "Audio (No FEC)");
  run_benchmark(0, MOQ_TRACK_TEXT, MOQ_TRACK_FLAG_RELIABLE, "Text (Reliable)");

  /* Test Group 2: Moderate network degradation (5% loss) */
  run_benchmark(5, MOQ_TRACK_VIDEO, MOQ_TRACK_FLAG_FEC_ENABLED,
                "Video (FEC-RS)");
  run_benchmark(5, MOQ_TRACK_DATA, MOQ_TRACK_FLAG_FEC_ENABLED, "Data (FEC-RQ)");
  run_benchmark(5, MOQ_TRACK_AUDIO, 0, "Audio (No FEC)");
  run_benchmark(5, MOQ_TRACK_TEXT, MOQ_TRACK_FLAG_RELIABLE, "Text (Reliable)");

  /* Test Group 3: High network degradation (20% loss) */
  run_benchmark(20, MOQ_TRACK_VIDEO, MOQ_TRACK_FLAG_FEC_ENABLED,
                "Video (FEC-RS)");
  run_benchmark(20, MOQ_TRACK_DATA, MOQ_TRACK_FLAG_FEC_ENABLED,
                "Data (FEC-RQ)");
  run_benchmark(20, MOQ_TRACK_AUDIO, 0, "Audio (No FEC)");
  run_benchmark(20, MOQ_TRACK_TEXT, MOQ_TRACK_FLAG_RELIABLE, "Text (Reliable)");

  printf("====================================================================="
         "============================\n\n");
  return 0;
}
