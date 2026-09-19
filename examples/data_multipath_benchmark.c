/* examples/data_multipath_benchmark.c */

#include "transport.h"
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_PACKETS 262144
#define MAX_FPS 50000
#define PACKET_SIZE 8000 /* 8KB general data payload */
#define GIGABIT_STREAM_EGRESS_BYTES (16U * 1024U * 1024U)
#define GIGABIT_TOTAL_STREAM_EGRESS_BYTES (32U * 1024U * 1024U)
#define QUALIFICATION_RECOVERY_CACHE_FLOOR (16U * 1024U * 1024U)
#define QUALIFICATION_RECOVERY_CACHE_MAX (128U * 1024U * 1024U)

typedef struct {
  double send_time;
  double recv_time;
  bool arrived;
  bool admitted;
} frame_metrics_t;

typedef struct {
  bool connected;
  bool disconnected;
  bool subscribed;
  bool use_reliable;
  frame_metrics_t packets[MAX_PACKETS];
  int frames_received;
  transport_t *transport;
} benchmark_state_t;

typedef struct {
  double all_active_at, start_ms, end_ms;
  transport_path_stats_t start[4], end[4];
  bool started, interrupted;
} path_window_t;

static double get_time_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

/* Compare paths over the same interval, after hot-added paths have had time to
 * validate and settle. Lifetime totals favor the paths that joined first. */
static void sample_path_window(transport_t *transport, size_t expected_paths,
                               double warmup_ms, path_window_t *window) {
  transport_path_stats_t current[4];
  double now = get_time_ms();
  for (size_t i = 0; i < expected_paths; i++) {
    if (!transport_get_path_stats(transport, i, &current[i]) ||
        current[i].lifecycle != TRANSPORT_PATH_ACTIVE) {
      window->all_active_at = 0;
      window->interrupted |= window->started;
      return;
    }
  }
  if (window->all_active_at == 0)
    window->all_active_at = now;
  if (now - window->all_active_at < warmup_ms)
    return;
  if (!window->started) {
    memcpy(window->start, current, expected_paths * sizeof(current[0]));
    window->start_ms = now;
    window->started = true;
  }
  memcpy(window->end, current, expected_paths * sizeof(current[0]));
  window->end_ms = now;
}

static int compare_latency(const void *a, const void *b) {
  double left = *(const double *)a, right = *(const double *)b;
  return (left > right) - (left < right);
}

static void report_window_delivery(const path_window_t *window,
                                   const benchmark_state_t *client,
                                   int packets_sent) {
  if (!window->started || window->end_ms <= window->start_ms)
    return;
  double latencies[MAX_PACKETS], total_latency = 0;
  size_t sent = 0, admitted = 0, received = 0, completed_in_window = 0;
  for (int i = 0; i < packets_sent; i++) {
    const frame_metrics_t *packet = &client->packets[i];
    if (packet->arrived && packet->recv_time >= window->start_ms &&
        packet->recv_time < window->end_ms)
      completed_in_window++;
    if (packet->send_time < window->start_ms ||
        packet->send_time >= window->end_ms)
      continue;
    sent++;
    admitted += packet->admitted;
    if (packet->arrived) {
      latencies[received] = packet->recv_time - packet->send_time;
      total_latency += latencies[received++];
    }
  }
  qsort(latencies, received, sizeof(latencies[0]), compare_latency);
  printf("window_offered: %zu\nwindow_admitted: %zu\nwindow_received: %zu\n",
         sent, admitted, received);
  printf("window_goodput_mbps: %.3f\n",
         completed_in_window * (double)PACKET_SIZE * 8 /
             ((window->end_ms - window->start_ms) * 1000));
  printf("window_mean_latency_ms: %.3f\n",
         received ? total_latency / received : 0);
  printf("window_p95_latency_ms: %.3f\n",
         received ? latencies[(received * 95 + 99) / 100 - 1] : 0);
  printf("window_p99_latency_ms: %.3f\n",
         received ? latencies[(received * 99 + 99) / 100 - 1] : 0);
}

static double numeric_argument(const char *text, double minimum,
                               double maximum) {
  char *end;
  errno = 0;
  double value = strtod(text, &end);
  if (errno || end == text || *end || !isfinite(value) || value < minimum ||
      value > maximum) {
    fprintf(stderr, "invalid numeric argument: %s\n", text);
    exit(2);
  }
  return value;
}

static size_t qualification_recovery_cache_bytes(double fps) {
  /* Retain two seconds of offered payload so a delayed checkpoint ACK cannot
   * turn a high-rate run into application backpressure. The fixed maximum is
   * the benchmark's explicit memory cap. */
  double requested = fps * PACKET_SIZE * 2.0;
  if (requested < QUALIFICATION_RECOVERY_CACHE_FLOOR)
    return QUALIFICATION_RECOVERY_CACHE_FLOOR;
  if (requested >= QUALIFICATION_RECOVERY_CACHE_MAX)
    return QUALIFICATION_RECOVERY_CACHE_MAX;
  return (size_t)requested;
}

static bool report_path_window(const path_window_t *window, size_t paths,
                               const char *preferred_interface) {
  double seconds = (window->end_ms - window->start_ms) / 1000.0;
  if (!window->started || window->interrupted || seconds < 1) {
    printf("\nall-path comparison: unavailable "
           "(needs >=1 s after all paths settle)\n");
    return preferred_interface == NULL;
  }
  uint64_t total_bytes = 0, preferred_bytes = 0;
  bool found_preferred = false;
  for (size_t i = 0; i < paths; i++)
    total_bytes += window->end[i].bytes_sent - window->start[i].bytes_sent;
  printf("\n--- SERVER TRAFFIC WITH ALL %zu PATHS ACTIVE (%.3f s) ---\n", paths,
         seconds);
  printf("Counts include protocol traffic; rates are observed UDP payload "
         "rates, not link capacity.\n");
  for (size_t i = 0; i < paths; i++) {
    const transport_path_stats_t *end = &window->end[i];
    uint64_t bytes = end->bytes_sent - window->start[i].bytes_sent;
    printf("path %zu: interface=%s address=%s sent=%lu bytes=%lu "
           "rate=%.0f B/s share=%.1f%% quic_rtt=%u ms\n",
           i, end->interface_name, end->local_address,
           (unsigned long)(end->sent - window->start[i].sent),
           (unsigned long)bytes, bytes / seconds,
           total_bytes ? 100.0 * bytes / total_bytes : 0.0, end->rtt);
    if (preferred_interface &&
        strcmp(end->interface_name, preferred_interface) == 0) {
      preferred_bytes = bytes;
      found_preferred = true;
    }
  }
  if (!preferred_interface)
    return true;
  bool passed =
      found_preferred && total_bytes > 0 && preferred_bytes > total_bytes / 2;
  printf("preferred-link check (%s carries >50%% of server bytes): %s\n",
         preferred_interface, passed ? "PASS" : "FAIL");
  return passed;
}

static void report_transport_pressure(const char *role,
                                      transport_t *transport) {
  transport_stats_t stats;
  if (!transport_get_stats(transport, &stats))
    return;
  printf("--- %s TRANSPORT PRESSURE ---\n", role);
  printf("publish: delivered=%" PRIu64 " buffered=%" PRIu64 " partial=%" PRIu64
         " backpressure=%" PRIu64 " errors=%" PRIu64 "\n",
         stats.publish_delivered, stats.publish_buffered, stats.publish_partial,
         stats.publish_backpressure, stats.publish_errors);
  printf("egress: peak_packets=%zu peak_bytes=%zu dropped=%" PRIu64
         " would_block=%" PRIu64 "\n",
         stats.egress_peak_packets, stats.egress_peak_bytes,
         stats.egress_packets_dropped, stats.udp_would_block);
  printf("streams: blocked=%" PRIu64 " peak_frames=%zu peak_bytes=%zu"
         " peak_vectors=%zu\n",
         stats.stream_egress_blocked, stats.stream_egress_peak_frames,
         stats.stream_egress_peak_bytes, stats.stream_egress_peak_vectors);
  printf("recovery: cache_backpressure=%" PRIu64 " peak_bytes=%zu"
         " peak_entries=%zu checkpoints_sent=%" PRIu64
         " checkpoints_received=%" PRIu64 " checkpoint_acks_sent=%" PRIu64
         " checkpoint_acks_received=%" PRIu64 " cache_releases=%" PRIu64
         " checkpoints_pending=%zu\n",
         stats.recovery_cache_backpressure,
         stats.recovery_cache_peak_payload_bytes,
         stats.recovery_cache_peak_entries, stats.recovery_checkpoints_sent,
         stats.recovery_checkpoints_received,
         stats.recovery_checkpoint_acks_sent,
         stats.recovery_checkpoint_acks_received, stats.recovery_cache_releases,
         stats.recovery_checkpoints_pending);
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
  case TRANSPORT_EVENT_DISCONNECTED:
    fprintf(stderr,
            "disconnected: code=%" PRIu64 " raw=%" PRId64
            " remote=%d application=%d reason=%s\n",
            event->disconnect.error_code, event->disconnect.raw_error,
            event->disconnect.remote, event->disconnect.application_error,
            event->disconnect.reason ? event->disconnect.reason : "none");
    state->connected = false;
    state->disconnected = true;
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
      if (state->use_reliable) {
        uint64_t fid;
        if (event->object.size >= sizeof(fid)) {
          memcpy(&fid, event->object.data, sizeof(fid));
          if (fid < MAX_PACKETS && !state->packets[fid].arrived) {
            state->packets[fid].recv_time = get_time_ms();
            state->packets[fid].arrived = true;
            state->frames_received++;
          }
        }
        break;
      }
      size_t remaining = event->object.size;
      const uint8_t *ptr = event->object.data;
      while (remaining >= 2) {
        uint16_t pkt_len;
        memcpy(&pkt_len, ptr, 2);
        pkt_len = ntohs(pkt_len);
        if (remaining < 2 + (size_t)pkt_len) {
          break;
        }
        if (pkt_len >= sizeof(uint64_t)) {
          uint64_t fid;
          memcpy(&fid, ptr + 2, sizeof(uint64_t));
          if (fid < MAX_PACKETS && !state->packets[fid].arrived) {
            state->packets[fid].recv_time = get_time_ms();
            state->packets[fid].arrived = true;
            state->frames_received++;
          }
        }
        ptr += 2 + pkt_len;
        remaining -= 2 + pkt_len;
      }
    }
    break;
  case TRANSPORT_EVENT_DISCONNECTED:
    fprintf(stderr,
            "disconnected: code=%" PRIu64 " raw=%" PRId64
            " remote=%d application=%d reason=%s\n",
            event->disconnect.error_code, event->disconnect.raw_error,
            event->disconnect.remote, event->disconnect.application_error,
            event->disconnect.reason ? event->disconnect.reason : "none");
    state->connected = false;
    state->disconnected = true;
    break;
  default:
    break;
  }
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  bool use_reliable = false;
  bool use_rateless = false;
  const char *server_bind_hosts[4] = {"0.0.0.0"};
  int num_server_bind = 1;
  const char *client_bind_hosts[4] = {"0.0.0.0"};
  int num_client_bind = 1;
  const char *server_path_interfaces[4] = {0};
  int num_server_path_interfaces = 0;
  const char *client_path_interfaces[4] = {0};
  int num_client_path_interfaces = 0;
  const char *client_remote_hosts[4] = {"127.0.0.1"};
  int num_client_remote = 1;
  const char *qlog_socket = NULL;
  const char *preferred_interface = NULL;
  int packet_count = 600;
  double fps = 60, warmup_ms = 500, drain_ms = 1500;
  double warmup_fps = 0;
  bool wait_all_paths = false;
  bool continue_backpressure = false;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--reliable") == 0) {
      use_reliable = true;
    } else if (strcmp(argv[i], "--rateless") == 0) {
      use_rateless = true;
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
    } else if (strcmp(argv[i], "--server-interface") == 0 && i + 1 < argc) {
      num_server_path_interfaces = 0;
      while (i + 1 < argc && argv[i + 1][0] != '-' &&
             num_server_path_interfaces < 4)
        server_path_interfaces[num_server_path_interfaces++] = argv[++i];
    } else if (strcmp(argv[i], "--client-interface") == 0 && i + 1 < argc) {
      num_client_path_interfaces = 0;
      while (i + 1 < argc && argv[i + 1][0] != '-' &&
             num_client_path_interfaces < 4)
        client_path_interfaces[num_client_path_interfaces++] = argv[++i];
    } else if (strcmp(argv[i], "--client-remote") == 0 && i + 1 < argc) {
      client_remote_hosts[0] = argv[++i];
      num_client_remote = 1;
      while (i + 1 < argc && argv[i + 1][0] != '-') {
        client_remote_hosts[num_client_remote++] = argv[++i];
      }
    } else if (strcmp(argv[i], "--qlog-unix-socket") == 0 && i + 1 < argc) {
      qlog_socket = argv[++i];
    } else if (strcmp(argv[i], "--expect-preferred-interface") == 0 &&
               i + 1 < argc) {
      preferred_interface = argv[++i];
    } else if (strcmp(argv[i], "--packets") == 0 && i + 1 < argc) {
      double value = numeric_argument(argv[++i], 1, MAX_PACKETS);
      if (value != floor(value))
        return 2;
      packet_count = (int)value;
    } else if (strcmp(argv[i], "--fps") == 0 && i + 1 < argc) {
      fps = numeric_argument(argv[++i], 1, MAX_FPS);
    } else if (strcmp(argv[i], "--warmup-ms") == 0 && i + 1 < argc) {
      warmup_ms = numeric_argument(argv[++i], 0, 30000);
    } else if (strcmp(argv[i], "--warmup-fps") == 0 && i + 1 < argc) {
      warmup_fps = numeric_argument(argv[++i], 1, MAX_FPS);
    } else if (strcmp(argv[i], "--drain-ms") == 0 && i + 1 < argc) {
      drain_ms = numeric_argument(argv[++i], 0, 10000);
    } else if (strcmp(argv[i], "--wait-all-paths") == 0) {
      wait_all_paths = true;
    } else if (strcmp(argv[i], "--continue-backpressure") == 0) {
      continue_backpressure = true;
    } else {
      fprintf(stderr, "unknown or incomplete option: %s\n", argv[i]);
      return 2;
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

  if (use_reliable && use_rateless) {
    fprintf(stderr, "--reliable and --rateless cannot be combined\n");
    return 2;
  }
  printf("starting data multipath benchmark (%s mode)...\n",
         use_reliable   ? "reliable stream"
         : use_rateless ? "rateless fec"
                        : "fixed fec");
  size_t recovery_cache_bytes = qualification_recovery_cache_bytes(fps);

  /* The gigabit qualification retains enough per-object metrics to exceed the
   * process stack when both endpoint states are automatic variables. */
  static benchmark_state_t server_state;
  static benchmark_state_t client_state;
  client_state.use_reliable = use_reliable;

  /* create server transport config */
  transport_config_t server_cfg = {
      .port = 9999,
      .cert_file = "t/assets/server.crt",
      .key_file = "t/assets/server.key",
      .callback = on_server_event,
      .limits = {.max_stream_egress_bytes = GIGABIT_STREAM_EGRESS_BYTES,
                 .max_total_stream_egress_bytes =
                     GIGABIT_TOTAL_STREAM_EGRESS_BYTES,
                 .max_recovery_cache_bytes = recovery_cache_bytes},
      .allow_insecure_peer = true,
      .user_data = &server_state};
  server_cfg.num_bind_hosts = num_server_bind;
  for (int i = 0; i < num_server_bind; i++)
    server_cfg.bind_hosts[i] = server_bind_hosts[i];
  server_cfg.num_path_interface_names = num_server_path_interfaces;
  for (int i = 0; i < num_server_path_interfaces; i++)
    server_cfg.path_interface_names[i] = server_path_interfaces[i];

  /* create client transport config */
  transport_config_t client_cfg = {
      .port = 9999,
      .cert_file = NULL,
      .key_file = NULL,
      .callback = on_client_event,
      .limits = {.max_stream_egress_bytes = GIGABIT_STREAM_EGRESS_BYTES,
                 .max_total_stream_egress_bytes =
                     GIGABIT_TOTAL_STREAM_EGRESS_BYTES,
                 .max_recovery_cache_bytes = recovery_cache_bytes},
      .allow_insecure_peer = true,
      .user_data = &client_state};
  client_cfg.num_bind_hosts = num_client_bind;
  for (int i = 0; i < num_client_bind; i++)
    client_cfg.bind_hosts[i] = client_bind_hosts[i];
  client_cfg.num_path_interface_names = num_client_path_interfaces;
  for (int i = 0; i < num_client_path_interfaces; i++)
    client_cfg.path_interface_names[i] = client_path_interfaces[i];
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
                          .flags = use_reliable   ? MOQ_TRACK_FLAG_RELIABLE
                                   : use_rateless ? MOQ_TRACK_FLAG_FEC_RATELESS
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

  size_t expected_paths = num_server_path_interfaces
                              ? (size_t)num_server_path_interfaces
                              : (size_t)num_server_bind;
  if (wait_all_paths) {
    bool ready = false;
    double deadline = get_time_ms() + 5000;
    while (!ready && get_time_ms() < deadline) {
      transport_tick(server);
      transport_tick(client);
      ready = true;
      for (size_t i = 0; i < expected_paths; i++) {
        transport_path_stats_t stats;
        ready &= transport_get_path_stats(server, i, &stats) &&
                 stats.lifecycle == TRANSPORT_PATH_ACTIVE;
      }
      usleep(500);
    }
    if (!ready) {
      fprintf(stderr, "not all configured paths became active\n");
      transport_destroy(client);
      transport_destroy(server);
      return 1;
    }
  }
  printf("handshake established. streaming %d packets at %.3ffps...\n",
         packet_count, fps);

  uint8_t *frame_payload = malloc(PACKET_SIZE);
  if (!frame_payload) {
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }
  memset(frame_payload, 0xAA, PACKET_SIZE);

  double start_benchmark = get_time_ms();
  double frame_interval = 1000.0 / fps;
  int packets_sent = 0;
  int packets_admitted = 0, backpressured = 0;
  bool publish_failed = false;
  path_window_t path_window = {0};

  for (int f = 0; f < packet_count; f++) {
    double publish_target = start_benchmark + f * frame_interval;
    if (warmup_fps > 0 && warmup_ms > 0) {
      double seconds = warmup_ms / 1000;
      double ramp_packets = (warmup_fps + fps) * seconds / 2;
      if (f < ramp_packets) {
        double slope = (fps - warmup_fps) / seconds;
        publish_target =
            start_benchmark +
            2000.0 * f /
                (warmup_fps + sqrt(warmup_fps * warmup_fps + 2 * slope * f));
      } else {
        publish_target =
            start_benchmark + warmup_ms + (f - ramp_packets) * frame_interval;
      }
    }
    while (get_time_ms() < publish_target) {
      transport_tick(server);
      transport_tick(client);
      usleep(500);
    }

    client_state.packets[f].send_time = get_time_ms();

    uint64_t *payload_fid = (uint64_t *)frame_payload;
    *payload_fid = f;

    moq_object_t obj = {
        .track_id = track,
        .group_id = 0,
        .object_id = f,
        .priority = 2,
        .data = frame_payload,
        .size = PACKET_SIZE,
        .is_keyframe = (f % 30 == 0) /* keyframe every 30 packets */
    };

    transport_publish_result_t result = transport_publish_ex(server, &obj);
    if (result == TRANSPORT_PUBLISH_BACKPRESSURE && continue_backpressure) {
      backpressured++;
    } else if (result != TRANSPORT_PUBLISH_DELIVERED &&
               result != TRANSPORT_PUBLISH_BUFFERED) {
      fprintf(stderr, "publish failed at packet %d (result=%d)\n", f, result);
      publish_failed = true;
      break;
    } else {
      client_state.packets[f].admitted = true;
      packets_admitted++;
    }
    packets_sent++;

    transport_tick(server);
    transport_tick(client);
    sample_path_window(server, expected_paths, warmup_ms, &path_window);
    if (server_state.disconnected || client_state.disconnected)
      break;
  }

  /* drain/wait for final packets to arrive */
  double drain_start = get_time_ms();
  while (get_time_ms() < drain_start + drain_ms) {
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

  for (int f = 0; f < packets_sent; f++) {
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
  for (int f = 0; f < packets_sent; f++) {
    if (client_state.packets[f].arrived) {
      double lat =
          client_state.packets[f].recv_time - client_state.packets[f].send_time;
      sum_sq_diff += pow(lat - mean_latency, 2);
    }
  }
  double jitter = samples > 1 ? sqrt(sum_sq_diff / (samples - 1)) : 0;

  printf("--- RESULTS ---\n");
  printf("mode: %s\n", use_reliable   ? "reliable"
                       : use_rateless ? "rateless"
                                      : "fixed-fec");
  printf("offered: %d\nsent: %d\nbackpressured: %d\n", packets_sent,
         packets_admitted, backpressured);
  printf("received: %d\n", samples);
  printf("loss_pct: %.1f%%\n",
         packets_sent > 0
             ? ((double)(packets_sent - samples) / packets_sent) * 100.0
             : 0.0);
  printf("mean_latency: %.3f ms\n", mean_latency);
  printf("max_latency: %.3f ms\n", max_latency);
  printf("jitter: %.3f ms\n", jitter);
  printf("freezes: %d\n", freezes);
  printf("===============\n");
  report_transport_pressure("SERVER", server);
  report_transport_pressure("CLIENT", client);

  bool path_check_passed =
      report_path_window(&path_window, expected_paths, preferred_interface);
  report_window_delivery(&path_window, &client_state, packets_sent);

  /* print multipath path statistics for client and server */
  printf("\nLifetime totals include different path join times.\n");
  printf("QUIC RTT includes the ACK return path, which can use a different "
         "link.\n");
  printf("\n--- MULTIPATH PATH STATISTICS (CLIENT) ---\n");
  for (size_t i = 0; i < 4; i++) {
    transport_path_stats_t pstats;
    if (transport_get_path_stats(client, i, &pstats)) {
      printf("path %zu: interface=%s address=%s sent=%lu lost=%lu "
             "quic_rtt=%u ms relative_owd=%.3f ms "
             "ewma_latency=%.3f ms\n",
             i, pstats.interface_name, pstats.local_address,
             (unsigned long)pstats.sent, (unsigned long)pstats.lost, pstats.rtt,
             pstats.relative_owd, pstats.ewma_latency);
    }
  }
  printf("\n--- MULTIPATH PATH STATISTICS (SERVER) ---\n");
  for (size_t i = 0; i < 4; i++) {
    transport_path_stats_t pstats;
    if (transport_get_path_stats(server, i, &pstats)) {
      printf("path %zu: interface=%s address=%s sent=%lu lost=%lu "
             "quic_rtt=%u ms relative_owd=%.3f ms "
             "ewma_latency=%.3f ms\n",
             i, pstats.interface_name, pstats.local_address,
             (unsigned long)pstats.sent, (unsigned long)pstats.lost, pstats.rtt,
             pstats.relative_owd, pstats.ewma_latency);
    }
  }
  printf("==========================================\n");

  free(frame_payload);
  bool failed = !path_check_passed || publish_failed ||
                server_state.disconnected || client_state.disconnected ||
                packets_sent != packet_count;
  transport_destroy(client);
  transport_destroy(server);
  return failed ? 1 : 0;
}
