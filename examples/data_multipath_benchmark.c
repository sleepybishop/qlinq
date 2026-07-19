/* examples/data_multipath_benchmark.c */

#include "transport.h"
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_PACKETS 600
#define PACKET_SIZE 8000 /* 8KB general data payload */

typedef struct {
  double send_time;
  double recv_time;
  bool arrived;
} frame_metrics_t;

typedef struct {
  bool connected;
  bool subscribed;
  bool use_reliable;
  frame_metrics_t packets[MAX_PACKETS];
  int frames_received;
  transport_t *transport;
} benchmark_state_t;

static double get_time_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

static void on_server_event(void *user_data, const transport_event_t *event) {
  benchmark_state_t *state = user_data;
  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    state->connected = true;
    break;
  case TRANSPORT_EVENT_SUBSCRIBE:
    if (strcmp(event->track_id.name, "data_benchmark") == 0) {
      state->subscribed = true;
    }
    break;
  case TRANSPORT_EVENT_AUTH:
    transport_respond_auth(state->transport, event->conn, true);
    break;
  default:
    break;
  }
}

static void on_client_event(void *user_data, const transport_event_t *event) {
  benchmark_state_t *state = user_data;
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
    if (strcmp(event->track_id.name, "data_benchmark") == 0) {
      uint64_t fid = event->object.object_id;
      if (fid < MAX_PACKETS) {
        state->packets[fid].recv_time = get_time_ms();
        state->packets[fid].arrived = true;
        state->frames_received++;
      }
    }
    break;
  default:
    break;
  }
}

int main(int argc, char **argv) {
  bool use_reliable = false;
  const char *server_bind_hosts[4] = {"0.0.0.0"};
  int num_server_bind = 1;
  const char *client_bind_hosts[4] = {"0.0.0.0"};
  int num_client_bind = 1;
  const char *client_remote_hosts[4] = {"127.0.0.1"};
  int num_client_remote = 1;
  const char *qlog_socket = NULL;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--reliable") == 0) {
      use_reliable = true;
    } else if (strcmp(argv[i], "--server-bind") == 0 && i + 1 < argc) {
      server_bind_hosts[0] = argv[++i];
      num_server_bind = 1;
      while (i + 1 < argc && argv[i + 1][0] != '-') {
        server_bind_hosts[num_server_bind++] = argv[++i];
      }
    } else if (strcmp(argv[i], "--client-bind") == 0 && i + 1 < argc) {
      client_bind_hosts[0] = argv[++i];
      num_client_bind = 1;
      while (i + 1 < argc && argv[i + 1][0] != '-') {
        client_bind_hosts[num_client_bind++] = argv[++i];
      }
    } else if (strcmp(argv[i], "--client-remote") == 0 && i + 1 < argc) {
      client_remote_hosts[0] = argv[++i];
      num_client_remote = 1;
      while (i + 1 < argc && argv[i + 1][0] != '-') {
        client_remote_hosts[num_client_remote++] = argv[++i];
      }
    } else if (strcmp(argv[i], "--qlog-unix-socket") == 0 && i + 1 < argc) {
      qlog_socket = argv[++i];
    }
  }

  if (qlog_socket) {
    if (transport_enable_qlog(qlog_socket) < 0) {
      fprintf(stderr, "failed to connect to qlog unix socket: %s\n",
              qlog_socket);
    } else {
      printf("qlog streaming enabled via unix socket\n");
    }
  }

  printf("starting data multipath benchmark (%s mode)...\n",
         use_reliable ? "reliable stream" : "fec datagram");

  benchmark_state_t server_state = {0};
  benchmark_state_t client_state = {0};
  client_state.use_reliable = use_reliable;

  /* create server transport config */
  transport_config_t server_cfg = {.port = 9999,
                                   .cert_file = "t/assets/server.crt",
                                   .key_file = "t/assets/server.key",
                                   .callback = on_server_event,
                                   .user_data = &server_state};
  server_cfg.num_bind_hosts = num_server_bind;
  for (int i = 0; i < num_server_bind; i++)
    server_cfg.bind_hosts[i] = server_bind_hosts[i];

  /* create client transport config */
  transport_config_t client_cfg = {.port = 9999,
                                   .cert_file = NULL,
                                   .key_file = NULL,
                                   .callback = on_client_event,
                                   .user_data = &client_state};
  client_cfg.num_bind_hosts = num_client_bind;
  for (int i = 0; i < num_client_bind; i++)
    client_cfg.bind_hosts[i] = client_bind_hosts[i];
  client_cfg.num_remote_hosts = num_client_remote;
  for (int i = 0; i < num_client_remote; i++)
    client_cfg.remote_hosts[i] = client_remote_hosts[i];

  transport_t *server = transport_create(&server_cfg);
  if (!server) {
    fprintf(stderr, "failed to create server transport\n");
    return 1;
  }
  server_state.transport = server;

  transport_t *client = transport_create(&client_cfg);
  if (!client) {
    fprintf(stderr, "failed to create client transport\n");
    transport_destroy(server);
    return 1;
  }
  client_state.transport = client;

  /* wait for connection */
  int retries = 200;
  while (retries-- > 0 &&
         (!server_state.connected || !client_state.connected)) {
    transport_tick(server);
    transport_tick(client);
    usleep(5000);
  }

  if (!server_state.connected || !client_state.connected) {
    fprintf(stderr, "failed to establish connection\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }

  /* client subscribes to benchmark track */
  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = use_reliable ? MOQ_TRACK_FLAG_RELIABLE
                                                : MOQ_TRACK_FLAG_FEC_ENABLED};
  strcpy(track.name, "data_benchmark");

  if (!transport_subscribe(client, track)) {
    fprintf(stderr, "failed to subscribe to track\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }

  /* wait for subscription match */
  retries = 200;
  while (retries-- > 0 && !server_state.subscribed) {
    transport_tick(server);
    transport_tick(client);
    usleep(5000);
  }

  if (!server_state.subscribed) {
    fprintf(stderr, "subscription handshake failed\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }

  printf("handshake established. streaming 200 packets at 60fps...\n");

  uint8_t *frame_payload = malloc(PACKET_SIZE);
  memset(frame_payload, 0xAA, PACKET_SIZE);

  double start_benchmark = get_time_ms();
  double frame_interval = 16.666; /* 60 FPS */

  for (int f = 0; f < MAX_PACKETS; f++) {
    double publish_target = start_benchmark + f * frame_interval;
    while (get_time_ms() < publish_target) {
      transport_tick(server);
      transport_tick(client);
      usleep(500);
    }

    client_state.packets[f].send_time = get_time_ms();
    moq_object_t obj = {
        .track_id = track,
        .group_id = 0,
        .object_id = f,
        .data = frame_payload,
        .size = PACKET_SIZE,
        .is_keyframe = (f % 30 == 0) /* keyframe every 30 packets */
    };

    transport_publish(server, &obj);

    transport_tick(server);
    transport_tick(client);
  }

  /* drain/wait for final packets to arrive */
  double drain_start = get_time_ms();
  while (get_time_ms() < drain_start + 1500) {
    transport_tick(server);
    transport_tick(client);
    usleep(5000);
  }

  /* calculate metrics */
  double total_latency = 0;
  double max_latency = 0;
  int samples = 0;
  int freezes = 0;
  double last_recv_time = 0;

  for (int f = 0; f < MAX_PACKETS; f++) {
    if (client_state.packets[f].arrived) {
      double lat =
          client_state.packets[f].recv_time - client_state.packets[f].send_time;
      total_latency += lat;
      if (lat > max_latency) {
        max_latency = lat;
      }
      samples++;

      if (last_recv_time > 0) {
        double gap = client_state.packets[f].recv_time - last_recv_time;
        if (gap > 33.3) { /* missed more than one packet render interval */
          freezes++;
        }
      }
      last_recv_time = client_state.packets[f].recv_time;
    }
  }

  double mean_latency = samples > 0 ? total_latency / samples : 0;

  /* calculate jitter */
  double sum_sq_diff = 0;
  for (int f = 0; f < MAX_PACKETS; f++) {
    if (client_state.packets[f].arrived) {
      double lat =
          client_state.packets[f].recv_time - client_state.packets[f].send_time;
      sum_sq_diff += pow(lat - mean_latency, 2);
    }
  }
  double jitter = samples > 1 ? sqrt(sum_sq_diff / (samples - 1)) : 0;

  printf("--- RESULTS ---\n");
  printf("mode: %s\n", use_reliable ? "reliable" : "fec");
  printf("sent: %d\n", MAX_PACKETS);
  printf("received: %d\n", samples);
  printf("loss_pct: %.1f%%\n",
         ((double)(MAX_PACKETS - samples) / MAX_PACKETS) * 100.0);
  printf("mean_latency: %.3f ms\n", mean_latency);
  printf("max_latency: %.3f ms\n", max_latency);
  printf("jitter: %.3f ms\n", jitter);
  printf("freezes: %d\n", freezes);
  printf("===============\n");

  /* print multipath path statistics for client and server */
  printf("\n--- MULTIPATH PATH STATISTICS (CLIENT) ---\n");
  for (size_t i = 0; i < 4; i++) {
    transport_path_stats_t pstats;
    if (transport_get_path_stats(client, i, &pstats)) {
      printf("path %zu: sent=%lu lost=%lu rtt=%u ms relative_owd=%.3f ms "
             "ewma_latency=%.3f ms\n",
             i, (unsigned long)pstats.sent, (unsigned long)pstats.lost,
             pstats.rtt, pstats.relative_owd, pstats.ewma_latency);
    }
  }
  printf("\n--- MULTIPATH PATH STATISTICS (SERVER) ---\n");
  for (size_t i = 0; i < 4; i++) {
    transport_path_stats_t pstats;
    if (transport_get_path_stats(server, i, &pstats)) {
      printf("path %zu: sent=%lu lost=%lu rtt=%u ms relative_owd=%.3f ms "
             "ewma_latency=%.3f ms\n",
             i, (unsigned long)pstats.sent, (unsigned long)pstats.lost,
             pstats.rtt, pstats.relative_owd, pstats.ewma_latency);
    }
  }
  printf("==========================================\n");

  free(frame_payload);
  transport_destroy(client);
  transport_destroy(server);
  return 0;
}
