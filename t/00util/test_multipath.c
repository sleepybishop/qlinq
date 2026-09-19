/* test_multipath.c */

#include "ifmon.h"
#include "pathflow.h"
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "transport.h"
#include "transport_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

typedef struct {
  bool connected;
  bool subscribed;
  bool object_received;
  size_t objects_received;
  uint8_t received_data[100];
  size_t received_size;
  transport_t *transport;
  transport_conn_t *conn;
} test_state_t;

static void on_server_event(void *user_data, const transport_event_t *event) {
  test_state_t *state = user_data;
  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    state->conn = event->conn;
    state->connected = true;
    break;
  case TRANSPORT_EVENT_SUBSCRIBE:
    if (event->track_id.type == MOQ_TRACK_VIDEO &&
        strcmp(event->track_id.name, "video_track") == 0) {
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
  test_state_t *state = user_data;
  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    state->conn = event->conn;
    transport_send_auth(state->transport, event->conn,
                        (const uint8_t *)"secret", 6);
    break;
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    if (event->auth.success) {
      state->connected = true;
    }
    break;
  case TRANSPORT_EVENT_OBJECT:
    if (event->track_id.type == MOQ_TRACK_VIDEO &&
        strcmp(event->track_id.name, "video_track") == 0) {
      state->object_received = true;
      state->objects_received++;
      state->received_size = event->object.size;
      if (event->object.size < sizeof(state->received_data)) {
        memcpy(state->received_data, event->object.data, event->object.size);
        state->received_data[event->object.size] = '\0';
      }
    }
    break;
  default:
    break;
  }
}

static int setup_qlog_listener(const char *path) {
  unlink(path);
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(fd);
    return -1;
  }

  if (listen(fd, 5) < 0) {
    close(fd);
    return -1;
  }

  return fd;
}

static size_t total_qlog_bytes = 0;
static void drain_qlog(int log_fd) {
  if (log_fd < 0)
    return;
  char trash[2048];
  ssize_t r;
  while (1) {
    r = read(log_fd, trash, sizeof(trash));
    if (r > 0) {
      total_qlog_bytes += r;
    } else if (r < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
      break;
    } else {
      break; /* EOF */
    }
  }
}

static bool test_single_remote_fanout(void) {
  test_state_t server_state = {0};
  test_state_t client_state = {0};

  transport_config_t server_cfg = {0};
  server_cfg.bind_hosts[0] = "127.70.1.1";
  server_cfg.num_bind_hosts = 1;
  server_cfg.port = 9877;
  server_cfg.cert_file = "t/assets/server.crt";
  server_cfg.key_file = "t/assets/server.key";
  server_cfg.callback = on_server_event;
  server_cfg.allow_insecure_peer = true;
  server_cfg.user_data = &server_state;

  transport_config_t client_cfg = {0};
  client_cfg.bind_hosts[0] = "127.71.1.2";
  client_cfg.bind_hosts[1] = "127.72.2.23";
  client_cfg.bind_hosts[2] = "127.73.3.34";
  client_cfg.num_bind_hosts = 3;
  client_cfg.remote_hosts[0] = "127.70.1.1";
  client_cfg.num_remote_hosts = 1;
  client_cfg.port = 9877;
  client_cfg.callback = on_client_event;
  client_cfg.allow_insecure_peer = true;
  client_cfg.user_data = &client_state;

  transport_t *server = transport_create(&server_cfg);
  if (!server)
    return false;
  server_state.transport = server;
  transport_t *client = transport_create(&client_cfg);
  if (!client) {
    transport_destroy(server);
    return false;
  }
  client_state.transport = client;

  transport_conn_stats_t stats = {0};
  int retries = 300;
  while (retries-- > 0) {
    transport_tick(server);
    transport_tick(client);
    if (server_state.connected && client_state.connected && client_state.conn &&
        transport_get_conn_stats(client, client_state.conn, &stats) &&
        stats.quic_paths_validated >= 2)
      break;
    usleep(10 * 1000);
  }

  bool ok = server_state.connected && client_state.connected &&
            client_state.conn &&
            transport_get_conn_stats(client, client_state.conn, &stats) &&
            stats.quic_paths_created >= 2 && stats.quic_paths_validated >= 2 &&
            stats.quic_paths_validation_failed == 0;
  if (!ok)
    fprintf(stderr,
            "single-remote path validation failed: created=%lu "
            "validated=%lu failed=%lu\n",
            (unsigned long)stats.quic_paths_created,
            (unsigned long)stats.quic_paths_validated,
            (unsigned long)stats.quic_paths_validation_failed);

  transport_destroy(client);
  transport_destroy(server);
  return ok;
}

#include <signal.h>

typedef struct {
  size_t expected_queue[TRANSPORT_MAX_PATHS];
  size_t events;
  bool valid;
} scheduler_log_check_t;

static void check_scheduler_log(void *data,
                                const transport_log_event_t *event) {
  scheduler_log_check_t *check = data;
  if (strcmp(event->component, "scheduler") != 0)
    return;
  size_t raw_q = SIZE_MAX, used_q = SIZE_MAX;
  const char *raw = strstr(event->message, " raw_q=");
  const char *used = strstr(event->message, " q=");
  check->events++;
  check->valid &= event->level == TRANSPORT_LOG_DEBUG &&
                  event->path_index < TRANSPORT_MAX_PATHS &&
                  strstr(event->message, "mode=pathflow") != NULL &&
                  strstr(event->message, "raw_b_pps=") != NULL &&
                  strstr(event->message, " total=") != NULL && raw && used &&
                  sscanf(raw, " raw_q=%zu", &raw_q) == 1 &&
                  sscanf(used, " q=%zu", &used_q) == 1;
  if (event->path_index < TRANSPORT_MAX_PATHS)
    check->valid &=
        raw_q == check->expected_queue[event->path_index] && used_q == raw_q;
}

/* Exercise the real path mapping, Quicly queues and publication sampler before
 * the allocation-only test installs deterministic bandwidth overrides. */
static bool test_live_path_inputs(test_state_t *server, test_state_t *client,
                                  moq_track_id_t track, int log_fd) {
  transport_t *t = server->transport;
  transport_conn_t *conn = server->conn;
  size_t symbol_size = transport_get_datagram_symbol_size(t);
  uint8_t *payload = calloc(12, symbol_size);
  if (!payload)
    return false;
  moq_object_t object = {.track_id = track,
                         .group_id = 1,
                         .object_id = 2,
                         .data = payload,
                         .size = 12 * symbol_size};
  size_t received_before = client->objects_received;
  memset(conn->path_states, 0, sizeof(conn->path_states));
  /* A short object's shrunken payload must not seed inflated rate units. */
  object.size = 1;
  bool ok = transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_DELIVERED;
  object.size = 12 * symbol_size;
  object.object_id++;
  scheduler_log_check_t check = {.valid = true};
  t->log_callback = check_scheduler_log;
  t->log_user_data = &check;
  fp_t initial_rate[TRANSPORT_MAX_PATHS] = {0};
  for (size_t publication = 0; publication < 2 && ok; publication++) {
    size_t queued = 0;
    for (size_t i = 0; i < t->num_fds; i++) {
      quicly_path_stats_t stats;
      size_t mapped = transport_path_get_stats_by_link(
          conn->quic, t->local_addrs, t->num_fds, i, &stats);
      if (mapped == SIZE_MAX || !quicly_is_path_available(conn->quic, mapped)) {
        ok = false;
        break;
      }
      path_t expected = transport_path_estimate(
          &stats, quicly_get_num_datagram_frames_path(conn->quic, mapped),
          t->egress[i].bytes, symbol_size, conn->latest_owd_fp[i]);
      check.expected_queue[i] = expected.q;
      queued += expected.q;
      initial_rate[i] = expected.b;
    }
    if (!ok || (publication == 1 && queued < 12)) {
      ok = false;
      break;
    }
    check.events = 0;
    ok = transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_DELIVERED;
    for (size_t i = 0; i < t->num_fds; i++)
      ok &= conn->path_states[i].initialized &&
            conn->path_states[i].b_ewma == initial_rate[i] &&
            conn->path_states[i].q_ewma == check.expected_queue[i];
    ok &= check.valid && check.events == t->num_fds;
    object.object_id++;
  }
  t->log_callback = NULL;
  t->log_user_data = NULL;
  free(payload);
  for (size_t i = 0;
       i < 2000 && ok && client->objects_received < received_before + 3; i++) {
    transport_tick(t);
    transport_tick(client->transport);
    drain_qlog(log_fd);
    usleep(500);
  }
  ok &= client->objects_received == received_before + 3;
  /* A preferred path with one slot left cannot fit this three-symbol object.
   * Admission must replan onto an empty alternate, without partially filling
   * the preferred path or requiring an event-loop tick first. */
  if (ok) {
    for (size_t i = 0; i < t->num_fds; i++)
      ok &= transport_mock_path_state(t, i, i == 0 ? 10000 : 1000,
                                      i == 0 ? 1.0 : 100.0, 0);
    size_t primary =
        transport_path_find_by_link(conn->quic, t->local_addrs, t->num_fds, 0);
    uint8_t ignored = 0xff;
    ptls_iovec_t frame = ptls_iovec_init(&ignored, 1);
    while (ok && quicly_get_num_datagram_frames_path(conn->quic, primary) < 63)
      ok &= transport_queue_datagram(conn, primary, frame);
    uint8_t small_payload[2000] = {19};
    object.data = small_payload;
    object.size = sizeof(small_payload);
    ok &= transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_DELIVERED;
    ok &= quicly_get_num_datagram_frames_path(conn->quic, primary) == 63;
    for (size_t i = 0;
         i < 2000 && ok && client->objects_received < received_before + 4;
         i++) {
      transport_tick(t);
      transport_tick(client->transport);
      drain_qlog(log_fd);
      usleep(500);
    }
    ok &= client->objects_received == received_before + 4;
  }
  if (!ok)
    fprintf(
        stderr,
        "live path inputs, queue refresh or scheduler diagnostics failed\n");
  else
    printf(
        "live per-path inputs and queued publication diagnostics verified\n");
  return ok;
}

int main(void) {
  signal(SIGPIPE, SIG_IGN);
  const char *qlog_path = "tmp/test_qlog.sock";
  mkdir("tmp", 0777);

  printf("testing multiple local interfaces with one remote endpoint...\n");
  if (!test_single_remote_fanout())
    return 1;

  int listener_fd = setup_qlog_listener(qlog_path);
  if (listener_fd < 0) {
    fprintf(stderr, "failed to setup qlog listener\n");
    return 1;
  }

  test_state_t server_state = {0};
  test_state_t client_state = {0};

  /* These loopback tuples deliberately do not share /24 prefixes. */
  transport_config_t server_cfg = {0};
  server_cfg.bind_hosts[0] = "127.0.1.1";
  server_cfg.bind_hosts[1] = "127.10.2.41";
  server_cfg.bind_hosts[2] = "127.20.3.77";
  server_cfg.bind_hosts[3] = "127.30.4.99";
  server_cfg.num_bind_hosts = 4;
  server_cfg.port = 9876;
  server_cfg.cert_file = "t/assets/server.crt";
  server_cfg.key_file = "t/assets/server.key";
  server_cfg.callback = on_server_event;
  server_cfg.allow_insecure_peer = true;
  server_cfg.user_data = &server_state;

  /* Start with two configured local paths; add the other two at runtime. */
  transport_config_t client_cfg = {0};
  client_cfg.bind_hosts[0] = "127.0.1.2";
  client_cfg.bind_hosts[1] = "127.40.9.12";
  client_cfg.num_bind_hosts = 2;
  client_cfg.remote_hosts[0] = "127.0.1.1";
  client_cfg.remote_hosts[1] = "127.10.2.41";
  client_cfg.remote_hosts[2] = "127.20.3.77";
  client_cfg.remote_hosts[3] = "127.30.4.99";
  client_cfg.num_remote_hosts = 4;
  client_cfg.port = 9876;
  client_cfg.cert_file = NULL;
  client_cfg.key_file = NULL;
  client_cfg.callback = on_client_event;
  client_cfg.allow_insecure_peer = true;
  client_cfg.user_data = &client_state;

  printf("creating transports...\n");
  transport_t *server = transport_create(&server_cfg);
  if (!server) {
    fprintf(stderr, "failed to create server\n");
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }
  server_state.transport = server;

  transport_t *client = transport_create(&client_cfg);
  if (!client) {
    fprintf(stderr, "failed to create client\n");
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }
  client_state.transport = client;

  /* enable qlog on client */
  if (transport_enable_qlog(qlog_path) != 0) {
    fprintf(stderr, "failed to enable qlog\n");
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }

  printf("accepting qlog connection...\n");
  int log_fd = accept(listener_fd, NULL, NULL);
  if (log_fd < 0) {
    fprintf(stderr, "immediate accept failed: %s (errno=%d)\n", strerror(errno),
            errno);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }
  printf("immediate accept succeeded: log_fd=%d\n", log_fd);

  /* set both sockets to non-blocking */
  int flags = fcntl(listener_fd, F_GETFL, 0);
  fcntl(listener_fd, F_SETFL, flags | O_NONBLOCK);
  flags = fcntl(log_fd, F_GETFL, 0);
  fcntl(log_fd, F_SETFL, flags | O_NONBLOCK);

  int retries = 200;
  printf("connecting client and server...\n");
  while (retries-- > 0 &&
         (!server_state.connected || !client_state.connected)) {
    transport_tick(server);
    transport_tick(client);
    drain_qlog(log_fd);
    usleep(10 * 1000);
  }

  if (!server_state.connected || !client_state.connected) {
    fprintf(stderr, "connection timeout\n");
    close(log_fd);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }

  /* The hot-added addresses also have unrelated prefixes and host octets. */
  printf("triggering secondary loopback path validation...\n");
  transport_mock_iface_add(client, "127.50.8.23");
  transport_mock_iface_add(client, "127.60.7.34");

  /* tick transports to process interface updates and complete validation */
  retries = 200;
  transport_conn_stats_t conn_stats = {0};
  while (retries-- > 0) {
    transport_tick(server);
    transport_tick(client);
    drain_qlog(log_fd);
    if (client_state.conn &&
        transport_get_conn_stats(client, client_state.conn, &conn_stats) &&
        conn_stats.quic_paths_validated >= 3)
      break;
    usleep(10 * 1000);
  }

  if (!client_state.conn ||
      !transport_get_conn_stats(client, client_state.conn, &conn_stats) ||
      conn_stats.quic_paths_created < 3 ||
      conn_stats.quic_paths_validated < 3 ||
      conn_stats.quic_paths_validation_failed != 0) {
    fprintf(stderr,
            "secondary path validation failed: created=%lu validated=%lu "
            "failed=%lu\n",
            (unsigned long)conn_stats.quic_paths_created,
            (unsigned long)conn_stats.quic_paths_validated,
            (unsigned long)conn_stats.quic_paths_validation_failed);
    close(log_fd);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }

  /* subscribe to video track */
  moq_track_id_t t_video = {.type = MOQ_TRACK_VIDEO,
                            .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                            .name = "video_track"};
  transport_subscribe(client, t_video);

  retries = 200;
  while (retries-- > 0 && !server_state.subscribed) {
    transport_tick(server);
    transport_tick(client);
    drain_qlog(log_fd);
    usleep(10 * 1000);
  }

  if (!server_state.subscribed) {
    fprintf(stderr, "subscribe timeout\n");
    close(log_fd);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }

  /* publish object */
  const char *payload = "hello sleepy bishop multipath!";
  moq_object_t obj = {.track_id = t_video,
                      .group_id = 1,
                      .object_id = 1,
                      .data = (const uint8_t *)payload,
                      .size = strlen(payload),
                      .is_keyframe = true};
  transport_publish(server, &obj);

  retries = 200;
  while (retries-- > 0 && !client_state.object_received) {
    transport_tick(server);
    transport_tick(client);
    drain_qlog(log_fd);
    usleep(10 * 1000);
  }

  if (!client_state.object_received) {
    fprintf(stderr, "object receive timeout\n");
    close(log_fd);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }

  if (strcmp((char *)client_state.received_data, payload) != 0) {
    fprintf(stderr, "payload mismatch\n");
    close(log_fd);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }

  /* Verify all four local sockets remain observable. */
  int socket_count = 0;
  for (size_t i = 0; i < 4; i++) {
    transport_path_stats_t stats;
    if (transport_get_path_stats(client, i, &stats))
      socket_count++;
  }

  if (socket_count < 4) {
    fprintf(stderr, "not all 4 path sockets are active: count=%d\n",
            socket_count);
    close(log_fd);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }

  if (!test_live_path_inputs(&server_state, &client_state, t_video, log_fd)) {
    close(log_fd);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }

  /* Test 60/5/10/25 split for 1000 packets */
  printf("testing 60/5/10/25 split for 1000 packets...\n");
  if (!transport_mock_path_state(server, 0, 60, 10.0, 0.0) ||
      !transport_mock_path_state(server, 1, 5, 10.0, 0.0) ||
      !transport_mock_path_state(server, 2, 10, 10.0, 0.0) ||
      !transport_mock_path_state(server, 3, 25, 10.0, 0.0)) {
    fprintf(stderr, "failed to install deterministic path state\n");
    close(log_fd);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }

  /* Fetch baseline stats from server connection paths */
  transport_path_stats_t base_stats[4];
  for (size_t i = 0; i < 4; i++) {
    if (!transport_get_path_stats(server, i, &base_stats[i])) {
      fprintf(stderr, "failed to get server base path stats for path %zu\n", i);
      close(log_fd);
      transport_destroy(client);
      transport_destroy(server);
      close(listener_fd);
      unlink(qlog_path);
      return 1;
    }
  }

  /* Determine exact symbol size to build exact symbol counts */
  size_t symbol_size = transport_get_datagram_symbol_size(server);

  /* Publish 20 objects of 50 symbols each to make 1000 packets total */
  printf("publishing 1000 packets in 20 chunks of 50 packets to prevent socket "
         "overflow...\n");
  for (int chunk = 0; chunk < 20; chunk++) {
    size_t chunk_size = 50 * symbol_size;
    uint8_t *chunk_payload = malloc(chunk_size);
    if (!chunk_payload) {
      fprintf(stderr, "failed to allocate chunk payload\n");
      close(log_fd);
      transport_destroy(client);
      transport_destroy(server);
      close(listener_fd);
      unlink(qlog_path);
      return 1;
    }
    memset(chunk_payload, 'A', chunk_size);

    /* Reset client receive flag/size */
    client_state.object_received = false;
    client_state.received_size = 0;

    moq_object_t chunk_obj = {.track_id = t_video,
                              .group_id = 2 + chunk,
                              .object_id = 2 + chunk,
                              .data = chunk_payload,
                              .size = chunk_size,
                              .is_keyframe = true};
    /* Measure the actual FEC datagram allocation before packet I/O. Native
     * packet counters also include ACKs, control traffic and PTO probes. */
    size_t mapped[4], queued_before[4];
    for (size_t i = 0; i < 4; ++i) {
      mapped[i] = transport_path_find_by_link(
          server_state.conn->quic, server->local_addrs, server->num_fds, i);
      queued_before[i] = quicly_get_num_datagram_frames_path(
          server_state.conn->quic, mapped[i]);
    }
    bool allocation_ok =
        transport_publish_ex(server, &chunk_obj) == TRANSPORT_PUBLISH_DELIVERED;
    /* Data allocation is 31/2/5/12; earliest-finish parity goes to path 3. */
    const size_t expected[4] = {31, 2, 5, 13};
    for (size_t i = 0; i < 4; ++i) {
      size_t queued = quicly_get_num_datagram_frames_path(
          server_state.conn->quic, mapped[i]);
      if (queued != queued_before[i] + expected[i]) {
        fprintf(stderr, "chunk %d path %zu: queued %zu, expected %zu\n", chunk,
                i, queued, queued_before[i] + expected[i]);
        allocation_ok = false;
      }
    }
    free(chunk_payload);
    if (!allocation_ok) {
      close(log_fd);
      transport_destroy(client);
      transport_destroy(server);
      close(listener_fd);
      unlink(qlog_path);
      return 1;
    }

    /* Tick client and server in a loop to transfer this chunk */
    retries = 2000;
    while (retries-- > 0 && !client_state.object_received) {
      transport_tick(server);
      transport_tick(client);
      drain_qlog(log_fd);
      usleep(500);
    }

    if (!client_state.object_received) {
      fprintf(stderr, "chunk %d receive timeout\n", chunk);
      close(log_fd);
      transport_destroy(client);
      transport_destroy(server);
      close(listener_fd);
      unlink(qlog_path);
      return 1;
    }
  }

  /* Report native packet counts separately from the exact allocation above. */
  transport_path_stats_t final_stats[4];
  long diff_sent[4];
  for (size_t i = 0; i < 4; i++) {
    if (!transport_get_path_stats(server, i, &final_stats[i])) {
      fprintf(stderr, "failed to get server final stats for path %zu\n", i);
      close(log_fd);
      transport_destroy(client);
      transport_destroy(server);
      close(listener_fd);
      unlink(qlog_path);
      return 1;
    }
    diff_sent[i] = (long)final_stats[i].sent - (long)base_stats[i].sent;
    printf("path %zu: base_sent=%lu, final_sent=%lu, diff=%ld\n", i,
           (unsigned long)base_stats[i].sent,
           (unsigned long)final_stats[i].sent, diff_sent[i]);
  }

  printf("60/5/10/25 split verified successfully!\n");

  /* Remove one established path at each endpoint. The physical socket and
   * scheduler slot must disappear without taking down the connection. */
  printf("testing interface removal while the connection remains active...\n");
  transport_mock_iface_remove(server, "127.30.4.99");
  transport_mock_iface_remove(client, "127.60.7.34");
  for (int i = 0; i < 100; i++) {
    transport_tick(server);
    transport_tick(client);
    drain_qlog(log_fd);
    usleep(1000);
  }
  transport_path_stats_t removed_path_stats = {0};
  if (transport_get_path_stats(server, 3, &removed_path_stats) ||
      transport_get_path_stats(client, 3, &removed_path_stats)) {
    fprintf(stderr, "removed interface remained scheduler-visible\n");
    close(log_fd);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }

  client_state.object_received = false;
  moq_object_t post_remove = {.track_id = t_video,
                              .group_id = 999,
                              .object_id = 999,
                              .data = (const uint8_t *)payload,
                              .size = strlen(payload),
                              .is_keyframe = true};
  if (!transport_publish(server, &post_remove)) {
    fprintf(stderr, "publication failed after interface removal\n");
    close(log_fd);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }
  retries = 1000;
  while (retries-- > 0 && !client_state.object_received) {
    transport_tick(server);
    transport_tick(client);
    drain_qlog(log_fd);
    usleep(1000);
  }
  if (!client_state.object_received) {
    fprintf(stderr, "connection did not survive interface removal\n");
    close(log_fd);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }

  /* destroy client transport to flush final trace logs to socket */
  printf("destroying client transport to flush qlog...\n");
  transport_destroy(client);

  /* read last trace data (using non-blocking drain) */
  usleep(50 * 1000);
  drain_qlog(log_fd);

  printf("total qlog bytes received: %zu\n", total_qlog_bytes);
  if (total_qlog_bytes == 0) {
    fprintf(stderr, "no qlog data received on debug socket\n");
    close(log_fd);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }

  printf("===MULTIPATH OK===\n");

  close(log_fd);
  transport_destroy(server);
  close(listener_fd);
  unlink(qlog_path);
  return 0;
}
