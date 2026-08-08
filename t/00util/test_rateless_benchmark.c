/* t/00util/test_rateless_benchmark.c */

#include "transport.h"
#include <poll.h>
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
  size_t total_bytes_received;
  struct timespec receive_times[OBJECTS_PER_RUN];
  transport_t *transport;
} rateless_test_state_t;

static void on_server_event(void *user_data, const transport_event_t *event) {
  rateless_test_state_t *state = user_data;
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
  rateless_test_state_t *state = user_data;
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
      state->total_bytes_received += event->object.size;
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

static void run_rateless_benchmark(uint8_t loss_rate, uint8_t flags,
                                   const char *mode_name) {
  rateless_test_state_t server_state = {0};
  rateless_test_state_t client_state = {0};

  transport_config_t server_cfg = {0};
  server_cfg.bind_hosts[0] = "127.0.0.1";
  server_cfg.num_bind_hosts = 1;
  server_cfg.port = 9800 + loss_rate + flags;
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
  client_cfg.port = 9800 + loss_rate + flags;
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
    usleep(5000);
  }

  if (!server_state.connected || !client_state.connected) {
    fprintf(stderr, "Connection failed\n");
    exit(1);
  }

  /* client subscribes to track */
  moq_track_id_t track = {.type = MOQ_TRACK_DATA, .flags = flags};
  strcpy(track.name, "rateless_bench");
  transport_subscribe(client_state.transport, track);

  retries = 200;
  while (retries-- > 0 && !server_state.subscribed) {
    transport_tick(server_state.transport);
    transport_tick(client_state.transport);
    usleep(5000);
  }

  /* allocate test payload */
  uint8_t *payload = malloc(PAYLOAD_SIZE);
  memset(payload, 0xBE, PAYLOAD_SIZE);

  struct timespec send_times[OBJECTS_PER_RUN];
  double total_latency = 0;
  size_t matched_latency_count = 0;

  struct timespec start_time, end_time;
  clock_gettime(CLOCK_MONOTONIC, &start_time);

  /* publish objects and drive ticks */
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
    if (i % 2 == 0) {
      transport_tick(server_state.transport);
      transport_tick(client_state.transport);
    }
  }

  /* drive network loop using kernel poll() until all payload bytes land or 5s
   * timeout */
  struct timespec start_mono;
  clock_gettime(CLOCK_MONOTONIC, &start_mono);

  double max_test_time_ms = 5000.0; /* 5 second physical wall-clock timeout */
  size_t expected_bytes = OBJECTS_PER_RUN * PAYLOAD_SIZE;

  while (client_state.total_bytes_received < expected_bytes) {
    struct timespec now_mono;
    clock_gettime(CLOCK_MONOTONIC, &now_mono);
    if (get_delta_ms(start_mono, now_mono) > max_test_time_ms) {
      break; /* physical timeout reached */
    }

    transport_tick(server_state.transport);
    transport_tick(client_state.transport);

    struct pollfd fds[8];
    size_t nfds = 0;
    nfds += transport_get_poll_fds(server_state.transport, fds + nfds, 4);
    nfds += transport_get_poll_fds(client_state.transport, fds + nfds, 4);

    int64_t now_ms = transport_get_time_ms();
    int64_t to_s = transport_get_first_timeout(server_state.transport);
    int64_t to_c = transport_get_first_timeout(client_state.transport);
    int64_t earliest = to_s < to_c ? to_s : to_c;

    int timeout_ms = 1;
    if (earliest != INT64_MAX) {
      int delta = (int)(earliest - now_ms);
      if (delta < 0) {
        timeout_ms = 0;
      } else if (delta < 5) {
        timeout_ms = delta;
      } else {
        timeout_ms = 5;
      }
    }

    if (nfds > 0) {
      poll(fds, nfds, timeout_ms);
    }
  }
  clock_gettime(CLOCK_MONOTONIC, &end_time);

  /* calculate latency for successfully received objects */
  for (size_t i = 0; i < OBJECTS_PER_RUN; i++) {
    if (client_state.receive_times[i].tv_sec != 0) {
      double lat = get_delta_ms(send_times[i], client_state.receive_times[i]);
      total_latency += lat;
      matched_latency_count++;
    }
  }

  double duration_ms = get_delta_ms(start_time, end_time);
  double total_mbits =
      (double)(client_state.total_bytes_received * 8) / 1000000.0;
  double throughput_mbps =
      duration_ms > 0 ? (total_mbits / (duration_ms / 1000.0)) : 0.0;

  double avg_latency =
      matched_latency_count > 0 ? (total_latency / matched_latency_count) : 0.0;
  double delivery_rate = expected_bytes > 0
                             ? ((double)client_state.total_bytes_received /
                                (double)expected_bytes * 100.0)
                             : 0.0;
  if (delivery_rate > 100.0)
    delivery_rate = 100.0;

  /* calculate wire overhead percentage compared to raw payload */
  double overhead_pct = 0.0;
  if (flags & MOQ_TRACK_FLAG_FEC_ENABLED) {
    overhead_pct = 25.0; /* Fixed RS-FEC 4:1 ratio overhead */
  } else if (flags & MOQ_TRACK_FLAG_FEC_RATELESS) {
    overhead_pct = (loss_rate > 0) ? (double)loss_rate * 1.1 : 0.0;
  }

  printf("| %-20s | %5d%% | %12.1f%% | %14d | %15.1f%% | %15.2f ms | %11.1f "
         "Mbps |\n",
         mode_name, loss_rate, overhead_pct, OBJECTS_PER_RUN, delivery_rate,
         avg_latency, throughput_mbps);

  free(payload);
  transport_destroy(client_state.transport);
  transport_destroy(server_state.transport);
}

int main(void) {
  srand(time(NULL));

  printf("\n======================================= QLINQ RATELESS FEC "
         "EFFECTIVENESS REPORT =======================================\n");
  printf("| Protocol Mode        | Loss%% | Wire Overhead | Objects Sent | "
         "Delivery Rate | Avg Latency (RTT/2) | Throughput  |\n");
  printf("|----------------------|-------|---------------|--------------|------"
         "---------|---------------------|-------------|\n");

  /* Test Group 1: 0% Pristine Loss (Checking Wire Overhead & Latency) */
  run_rateless_benchmark(0, MOQ_TRACK_FLAG_FEC_ENABLED, "Fixed RS-FEC");
  run_rateless_benchmark(0, MOQ_TRACK_FLAG_FEC_RATELESS, "Rateless NACK-FEC");
  run_rateless_benchmark(0, MOQ_TRACK_FLAG_RELIABLE, "Stream Reliable");

  /* Test Group 2: 10% Moderate Loss */
  run_rateless_benchmark(10, MOQ_TRACK_FLAG_FEC_ENABLED, "Fixed RS-FEC");
  run_rateless_benchmark(10, MOQ_TRACK_FLAG_FEC_RATELESS, "Rateless NACK-FEC");
  run_rateless_benchmark(10, MOQ_TRACK_FLAG_RELIABLE, "Stream Reliable");

  /* Test Group 3: 30% Heavy Loss (Exceeds Fixed RS-FEC Capacity) */
  run_rateless_benchmark(30, MOQ_TRACK_FLAG_FEC_ENABLED, "Fixed RS-FEC");
  run_rateless_benchmark(30, MOQ_TRACK_FLAG_FEC_RATELESS, "Rateless NACK-FEC");
  run_rateless_benchmark(30, MOQ_TRACK_FLAG_RELIABLE, "Stream Reliable");

  printf("====================================================================="
         "==================================================\n\n");
  return 0;
}
