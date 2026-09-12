/* main.c (daemon) */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "data_uds.h"
#include "portable_sockets.h"
#include "transport.h"
#include <errno.h>
#include <inttypes.h>
#include <openssl/crypto.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_reload_credentials = 0;

static void handle_signal(int sig) {
#ifdef SIGHUP
  if (sig == SIGHUP) {
    g_reload_credentials = 1;
    return;
  }
#endif
  (void)sig;
  g_running = 0;
}

#define MAX_TRANSPORTS 16
#define MAX_DATA_POLL_FDS 17
#define MAX_DAEMON_POLL_FDS                                                    \
  (MAX_DATA_POLL_FDS + MAX_TRANSPORTS * TRANSPORT_MAX_PATHS)

static void show_help(FILE *out, const char *program) {
  fprintf(
      out,
      "usage: %s (--listen PORT | --peer HOST[:PORT]) [options]\n\n"
      "  --bind ADDRESS              numeric listener address\n"
      "  --peer HOST[:PORT]          add an outbound peer (repeatable)\n"
      "  --cert FILE --key FILE      TLS identity\n"
      "  --ca FILE                   peer CA bundle\n"
      "  --auth-token TOKEN          application authentication token\n"
      "  --insecure-no-verify        test-only certificate bypass\n"
      "  --socket NAME               Unix data socket name\n"
      "  --track NAME                subscribe to a track (repeatable)\n"
      "  --stats-ms MS               periodically print transport counters\n"
      "  --reliable                  reliable track mode\n"
      "  --rateless                  rateless FEC track mode\n"
      "  --verbose\n\n"
      "SIGHUP reloads --cert and --key atomically.\n",
      program);
}

static bool parse_port(const char *text, int *port) {
  if (!text || !text[0] || text[0] == '-' || !port)
    return false;
  char *end = NULL;
  errno = 0;
  long value = strtol(text, &end, 10);
  if (errno != 0 || !end || *end != '\0' || value <= 0 || value > UINT16_MAX)
    return false;
  *port = (int)value;
  return true;
}

static bool parse_u32(const char *text, uint32_t *value) {
  if (!text || !text[0] || text[0] == '-' || !value)
    return false;
  char *end = NULL;
  errno = 0;
  unsigned long long parsed = strtoull(text, &end, 10);
  if (errno != 0 || !end || *end != '\0' || parsed == 0 || parsed > UINT32_MAX)
    return false;
  *value = (uint32_t)parsed;
  return true;
}

static bool parse_peer_endpoint(const char *endpoint, char *host,
                                size_t host_capacity, int *port) {
  if (!endpoint || !host || host_capacity == 0 || !port)
    return false;
  const char *host_start = endpoint;
  size_t host_len = strlen(endpoint);
  const char *port_start = NULL;
  if (endpoint[0] == '[') {
    const char *closing = strchr(endpoint + 1, ']');
    if (!closing || (closing[1] != '\0' && closing[1] != ':'))
      return false;
    host_start = endpoint + 1;
    host_len = (size_t)(closing - host_start);
    if (closing[1] == ':')
      port_start = closing + 2;
  } else {
    const char *first_colon = strchr(endpoint, ':');
    const char *last_colon = strrchr(endpoint, ':');
    if (first_colon && first_colon == last_colon) {
      host_len = (size_t)(first_colon - endpoint);
      port_start = first_colon + 1;
    }
  }
  if (host_len == 0 || host_len >= host_capacity)
    return false;
  memcpy(host, host_start, host_len);
  host[host_len] = '\0';
  if (port_start) {
    char *end = NULL;
    errno = 0;
    long parsed = strtol(port_start, &end, 10);
    if (errno != 0 || !port_start[0] || !end || *end != '\0' || parsed <= 0 ||
        parsed > UINT16_MAX)
      return false;
    *port = (int)parsed;
  }
  return true;
}

struct daemon_ctx_s;

typedef struct {
  struct daemon_ctx_s *daemon;
  transport_t *transport;
  bool is_server;
} daemon_transport_ctx_t;

typedef struct daemon_ctx_s {
  daemon_transport_ctx_t transports[MAX_TRANSPORTS];
  size_t num_transports;
  data_uds_t *data_pipe;
  bool running;
  uint32_t data_object_id;
  char subscribe_tracks[16][64];
  size_t num_subscribe_tracks;
  bool use_reliable;
  bool use_rateless;
  bool verbose;
  const char *auth_token;
  size_t auth_token_len;
  const char *cert_file;
  const char *key_file;
  uint32_t stats_ms;
  int64_t next_stats_at;
} daemon_ctx_t;

static void subscribe_to_tracks(transport_t *t, daemon_ctx_t *ctx) {
  for (size_t i = 0; i < ctx->num_subscribe_tracks; i++) {
    uint8_t flags = MOQ_TRACK_FLAG_FEC_ENABLED;
    if (ctx->use_reliable) {
      flags = MOQ_TRACK_FLAG_RELIABLE;
    } else if (ctx->use_rateless) {
      flags = MOQ_TRACK_FLAG_FEC_RATELESS;
    }
    moq_track_id_t t_data = {.type = MOQ_TRACK_DATA, .flags = flags};
    strncpy(t_data.name, ctx->subscribe_tracks[i], sizeof(t_data.name) - 1);
    t_data.name[sizeof(t_data.name) - 1] = '\0';
    transport_subscribe(t, t_data);
  }
}

static void on_transport_event(void *user_data,
                               const transport_event_t *event) {
  daemon_transport_ctx_t *tctx = user_data;
  daemon_ctx_t *ctx = tctx->daemon;
  transport_t *t = tctx->transport;

  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    printf("peer connected\n");
    if (!tctx->is_server) {
      transport_send_auth(t, event->conn, (const uint8_t *)ctx->auth_token,
                          ctx->auth_token_len);
    }
    break;
  case TRANSPORT_EVENT_AUTH:
    if (tctx->is_server) {
      bool success = false;
      if (event->auth.token_len == ctx->auth_token_len &&
          CRYPTO_memcmp(event->auth.token, ctx->auth_token,
                        event->auth.token_len) == 0) {
        success = true;
        printf("peer authentication successful\n");
      } else {
        printf("peer authentication failed\n");
      }
      transport_respond_auth(t, event->conn, success);
      if (success)
        subscribe_to_tracks(t, ctx);
    }
    break;
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    if (event->auth.success) {
      printf("authentication to peer successful\n");
      subscribe_to_tracks(t, ctx);
    } else {
      fprintf(stderr, "authentication failed, disconnecting from peer\n");
      transport_close_conn(t, event->conn);
    }
    break;
  case TRANSPORT_EVENT_DISCONNECTED:
    printf("peer disconnected origin=%s class=%s code=%" PRIu64 " raw=%" PRId64
           " reason=%s\n",
           event->disconnect.remote ? "remote" : "local",
           event->disconnect.application_error ? "application"
           : event->disconnect.raw_error >= 0  ? "transport"
                                               : "internal",
           event->disconnect.error_code, event->disconnect.raw_error,
           event->disconnect.reason && event->disconnect.reason[0]
               ? event->disconnect.reason
               : "none");
    break;
  case TRANSPORT_EVENT_SUBSCRIBE:
    printf("daemon: peer subscribed to track '%s' (type %d)\n",
           event->track_id.name, event->track_id.type);
    break;
  case TRANSPORT_EVENT_UNSUBSCRIBE:
    printf("daemon: peer unsubscribed from track '%s' (type %d)\n",
           event->track_id.name, event->track_id.type);
    break;
  case TRANSPORT_EVENT_OBJECT:
    if (ctx->verbose && event->track_id.type == MOQ_TRACK_DATA) {
      printf("daemon: received object from peer on track '%s', size=%zu, "
             "flags=%d, type=%d\n",
             event->track_id.name, event->object.size, event->track_id.flags,
             event->track_id.type);
    }
    if (ctx->data_pipe && event->track_id.type == MOQ_TRACK_DATA &&
        (event->track_id.flags & (MOQ_TRACK_FLAG_FEC_ENABLED | MOQ_TRACK_FLAG_FEC_RATELESS))) {
      /* Extract datagram packets from aggregated symbol */
      size_t remaining = event->object.size;
      const uint8_t *ptr = event->object.data;
      while (remaining >= 2) {
        uint16_t pkt_len;
        memcpy(&pkt_len, ptr, 2);
        pkt_len = ntohs(pkt_len);
        if (remaining < 2 + (size_t)pkt_len) {
          break;
        }
        if (!data_uds_send(ctx->data_pipe, &event->track_id, ptr + 2, pkt_len,
                           event->object.priority) &&
            ctx->verbose)
          fprintf(stderr, "daemon: UDS output queue unavailable\n");
        ptr += 2 + pkt_len;
        remaining -= 2 + pkt_len;
      }
    } else if (ctx->data_pipe) {
      /* Forward raw packet for reliable tracks */
      if (!data_uds_send(ctx->data_pipe, &event->track_id, event->object.data,
                         event->object.size, event->object.priority) &&
          ctx->verbose)
        fprintf(stderr, "daemon: UDS output queue unavailable\n");
    }
    break;
  case TRANSPORT_EVENT_OBJECT_LOST:
    printf("daemon: object lost event\n");
    break;
  case TRANSPORT_EVENT_KEYFRAME_REQUEST:
    break;
  }
}

static void on_data_packet(void *user_data, const moq_track_id_t *track_id,
                           const uint8_t *buf, size_t size, uint8_t priority) {
  daemon_ctx_t *ctx = user_data;
  if (!ctx)
    return;

  moq_object_t obj = {.track_id = *track_id,
                      .group_id = 0,
                      .object_id = ctx->data_object_id++,
                      .data = buf,
                      .size = size,
                      .is_keyframe = false,
                      .priority = priority};

  /* Broadcast to all peers */
  for (size_t i = 0; i < ctx->num_transports; i++) {
    if (ctx->transports[i].transport) {
      if (!transport_publish(ctx->transports[i].transport, &obj) &&
          ctx->verbose)
        fprintf(stderr, "daemon: transport backpressure rejected object\n");
    }
  }
}

static bool on_is_track_ready(void *user_data, const moq_track_id_t *track_id) {
  daemon_ctx_t *ctx = user_data;
  if (!ctx)
    return false;
  for (size_t i = 0; i < ctx->num_transports; i++) {
    if (ctx->transports[i].transport &&
        !transport_is_track_ready(ctx->transports[i].transport, track_id)) {
      return false;
    }
  }
  return true;
}

/* drive daemon event loop processing */
static void daemon_tick(daemon_ctx_t *ctx) {
  data_uds_tick(ctx->data_pipe);
  for (size_t i = 0; i < ctx->num_transports; i++) {
    transport_tick(ctx->transports[i].transport);
  }
}

static void daemon_print_stats(daemon_ctx_t *ctx, int64_t now_ms) {
  if (!ctx || ctx->stats_ms == 0)
    return;
  if (ctx->next_stats_at == 0) {
    ctx->next_stats_at = now_ms + ctx->stats_ms;
    return;
  }
  if (now_ms < ctx->next_stats_at)
    return;
  for (size_t i = 0; i < ctx->num_transports; i++) {
    transport_stats_t stats = {0};
    if (!transport_get_stats(ctx->transports[i].transport, &stats))
      continue;
    fprintf(stderr,
            "daemon: stats transport=%zu role=%s connections=%zu "
            "reconnect_attempts=%" PRIu64 " reconnect_succeeded=%" PRIu64
            " reconnect_failed=%" PRIu64 " repair_requests_sent=%" PRIu64
            " repair_requests_received=%" PRIu64
            " repair_requests_deferred=%" PRIu64
            " recovery_pending=%zu recovery_oldest_ms=%" PRIu64
            " egress_packets=%zu egress_bytes=%zu udp_would_block=%" PRIu64
            " publish_backpressure=%" PRIu64 " publish_errors=%" PRIu64 "\n",
            i, ctx->transports[i].is_server ? "server" : "client",
            stats.active_connections, stats.reconnect_attempts,
            stats.reconnect_succeeded, stats.reconnect_failed,
            stats.repair_requests_sent, stats.repair_requests_received,
            stats.repair_requests_deferred, stats.recovery_checkpoints_pending,
            stats.recovery_oldest_checkpoint_age_ms,
            stats.egress_current_packets, stats.egress_current_bytes,
            stats.udp_would_block, stats.publish_backpressure,
            stats.publish_errors);
  }
  ctx->next_stats_at = now_ms + ctx->stats_ms;
}

/* run daemon loop driven by socket polling and quicly pacer timeouts */
static void daemon_run(daemon_ctx_t *ctx) {
  printf("daemon is running. press ctrl+c to exit.\n");
  while (ctx->running && g_running) {
#ifdef SIGHUP
    if (g_reload_credentials) {
      g_reload_credentials = 0;
      if (!ctx->cert_file) {
        fprintf(stderr, "daemon: TLS credential reload skipped; no identity "
                        "configured\n");
      } else {
        bool ok = true;
        for (size_t i = 0; i < ctx->num_transports; i++) {
          if (!transport_reload_credentials(ctx->transports[i].transport,
                                            ctx->cert_file, ctx->key_file))
            ok = false;
        }
        fprintf(stderr, "daemon: TLS credential reload %s\n",
                ok ? "complete" : "failed");
      }
    }
#endif
    daemon_tick(ctx);

    int64_t now_ms = transport_get_time_ms();
    daemon_print_stats(ctx, now_ms);
    int64_t earliest_timeout_ms = INT64_MAX;

    for (size_t i = 0; i < ctx->num_transports; i++) {
      if (ctx->transports[i].transport) {
        int64_t to = transport_get_first_timeout(ctx->transports[i].transport);
        if (to < earliest_timeout_ms) {
          earliest_timeout_ms = to;
        }
      }
    }

    int timeout_ms = 10; /* default maximum poll timeout */
    if (earliest_timeout_ms != INT64_MAX) {
      int delta = (int)(earliest_timeout_ms - now_ms);
      if (delta < 0) {
        timeout_ms = 0;
      } else if (delta < timeout_ms) {
        timeout_ms = delta;
      }
    }

    struct pollfd fds[MAX_DAEMON_POLL_FDS];
    size_t num_fds = 0;

    if (ctx->data_pipe) {
      num_fds += data_uds_get_poll_fds(ctx->data_pipe, fds + num_fds,
                                       MAX_DAEMON_POLL_FDS - num_fds);
    }
    for (size_t i = 0; i < ctx->num_transports; i++) {
      if (ctx->transports[i].transport) {
        num_fds +=
            transport_get_poll_fds(ctx->transports[i].transport, fds + num_fds,
                                   MAX_DAEMON_POLL_FDS - num_fds);
      }
    }

    if (num_fds > 0) {
      poll(fds, num_fds, timeout_ms);
    } else if (timeout_ms > 0) {
      usleep(timeout_ms * 1000);
    }
  }
  printf("\nshutting down daemon cleanly...\n");
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

#ifndef _WIN32
  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);
#ifdef SIGHUP
  signal(SIGHUP, handle_signal);
#endif
#endif

  printf("starting qlinqd peer mesh daemon...\n");

  if (portable_socket_init() != 0) {
    fprintf(stderr, "failed to initialize sockets\n");
    return 1;
  }

  daemon_ctx_t ctx = {0};
  ctx.running = true;

  int listen_port = -1;
  const char *listen_host = "0.0.0.0";
  const char *peers[MAX_TRANSPORTS];
  size_t num_peers = 0;

  const char *cert_file = NULL;
  const char *key_file = NULL;
  const char *ca_file = NULL;
  bool verify_peer = true;
  bool allow_insecure_peer = false;
  const char *socket_name = "qlinq-data";
  bool invalid_args = false;

  for (int i = 1; i < argc; i++) {
    const char *arg = argv[i];
    if (strcmp(arg, "--help") == 0) {
      show_help(stdout, argv[0]);
      portable_socket_cleanup();
      return 0;
    } else if (strcmp(arg, "--listen") == 0) {
      if (++i >= argc || !parse_port(argv[i], &listen_port)) {
        invalid_args = true;
        break;
      }
    } else if (strcmp(arg, "--bind") == 0) {
      if (++i >= argc) {
        invalid_args = true;
        break;
      }
      listen_host = argv[i];
    } else if (strcmp(arg, "--cert") == 0) {
      if (++i >= argc) {
        invalid_args = true;
        break;
      }
      cert_file = argv[i];
    } else if (strcmp(arg, "--key") == 0) {
      if (++i >= argc) {
        invalid_args = true;
        break;
      }
      key_file = argv[i];
    } else if (strcmp(arg, "--ca") == 0) {
      if (++i >= argc) {
        invalid_args = true;
        break;
      }
      ca_file = argv[i];
    } else if (strcmp(argv[i], "--verify-peer") == 0) {
      verify_peer = true;
      allow_insecure_peer = false;
    } else if (strcmp(argv[i], "--insecure-no-verify") == 0) {
      verify_peer = false;
      allow_insecure_peer = true;
    } else if (strcmp(arg, "--auth-token") == 0) {
      if (++i >= argc) {
        invalid_args = true;
        break;
      }
      ctx.auth_token = argv[i];
    } else if (strcmp(argv[i], "--verbose") == 0) {
      ctx.verbose = true;
    } else if (strcmp(arg, "--socket") == 0 || strcmp(arg, "-s") == 0) {
      if (++i >= argc) {
        invalid_args = true;
        break;
      }
      socket_name = argv[i];
    } else if (strcmp(arg, "--peer") == 0) {
      if (++i >= argc || num_peers >= MAX_TRANSPORTS - 1) {
        invalid_args = true;
        break;
      }
      char parsed_host[256];
      int parsed_port = 8888;
      if (!parse_peer_endpoint(argv[i], parsed_host, sizeof(parsed_host),
                               &parsed_port)) {
        invalid_args = true;
        break;
      }
      peers[num_peers++] = argv[i];
    } else if (strcmp(arg, "--track") == 0) {
      if (++i >= argc || ctx.num_subscribe_tracks >= 15 ||
          strlen(argv[i]) >= sizeof(ctx.subscribe_tracks[0])) {
        invalid_args = true;
        break;
      }
      strcpy(ctx.subscribe_tracks[ctx.num_subscribe_tracks++], argv[i]);
    } else if (strcmp(arg, "--stats-ms") == 0) {
      if (++i >= argc || !parse_u32(argv[i], &ctx.stats_ms)) {
        invalid_args = true;
        break;
      }
    } else if (strcmp(argv[i], "--reliable") == 0) {
      ctx.use_reliable = true;
    } else if (strcmp(argv[i], "--rateless") == 0) {
      ctx.use_rateless = true;
    } else {
      invalid_args = true;
      break;
    }
  }

  if (invalid_args || (ctx.use_reliable && ctx.use_rateless)) {
    fprintf(stderr, "invalid command line\n");
    show_help(stderr, argv[0]);
    portable_socket_cleanup();
    return 1;
  }

  if (!ctx.auth_token)
    ctx.auth_token = getenv("QLINQ_AUTH_TOKEN");
  if (!ctx.auth_token || ctx.auth_token[0] == '\0') {
    fprintf(stderr, "an authentication token is required; use --auth-token or "
                    "QLINQ_AUTH_TOKEN\n");
    portable_socket_cleanup();
    return 1;
  }
  if ((cert_file == NULL) != (key_file == NULL) ||
      ((listen_port > 0 || verify_peer) && cert_file == NULL)) {
    fprintf(stderr, "a TLS identity is required; use both --cert and --key "
                    "(insecure clients may omit both)\n");
    portable_socket_cleanup();
    return 1;
  }
  ctx.auth_token_len = strlen(ctx.auth_token);
  ctx.cert_file = cert_file;
  ctx.key_file = key_file;
  if (ctx.auth_token_len > UINT16_MAX) {
    fprintf(stderr, "authentication token is too long\n");
    portable_socket_cleanup();
    return 1;
  }

  if (ctx.num_subscribe_tracks == 0) {
    strcpy(ctx.subscribe_tracks[ctx.num_subscribe_tracks++], "bishnc/default");
    strcpy(ctx.subscribe_tracks[ctx.num_subscribe_tracks++], "tund/tun0");
    strcpy(ctx.subscribe_tracks[ctx.num_subscribe_tracks++], "");
  }

  if (listen_port > 0) {
    /* Create server transport */
    transport_config_t config = {0};
    config.port = listen_port;
    config.bind_hosts[config.num_bind_hosts++] = listen_host;
    config.cert_file = cert_file;
    config.key_file = key_file;
    config.ca_file = ca_file;
    config.verify_peer = verify_peer;
    config.allow_insecure_peer = allow_insecure_peer;

    daemon_transport_ctx_t *tctx = &ctx.transports[ctx.num_transports];
    tctx->daemon = &ctx;
    tctx->is_server = true;
    config.callback = on_transport_event;
    config.user_data = tctx;

    tctx->transport = transport_create(&config);
    if (!tctx->transport) {
      fprintf(stderr, "failed to create server transport\n");
      return 1;
    }
    ctx.num_transports++;
    printf("listening on %s:%d\n", listen_host, listen_port);
  }

  for (size_t i = 0; i < num_peers; i++) {
    /* Create client transport for each peer */
    transport_config_t config = {0};
    char peer_ip[256];
    int port = 8888;
    if (!parse_peer_endpoint(peers[i], peer_ip, sizeof(peer_ip), &port)) {
      fprintf(stderr, "invalid peer endpoint: %s\n", peers[i]);
      continue;
    }

    config.port = port;
    config.remote_hosts[config.num_remote_hosts++] = peer_ip;
    config.bind_hosts[config.num_bind_hosts++] =
        strchr(peer_ip, ':') ? "::" : "0.0.0.0";
    config.cert_file = cert_file;
    config.key_file = key_file;
    config.ca_file = ca_file;
    config.verify_peer = verify_peer;
    config.allow_insecure_peer = allow_insecure_peer;
    config.reconnect_enabled = true;

    daemon_transport_ctx_t *tctx = &ctx.transports[ctx.num_transports];
    tctx->daemon = &ctx;
    tctx->is_server = false;
    config.callback = on_transport_event;
    config.user_data = tctx;

    tctx->transport = transport_create(&config);
    if (!tctx->transport) {
      fprintf(stderr, "failed to create client transport for %s\n", peers[i]);
      continue;
    }
    ctx.num_transports++;
    printf("connecting to peer %s:%d\n", peer_ip, port);
  }

  if (ctx.num_transports == 0) {
    fprintf(stderr, "no listener or peers specified. exiting.\n");
    return 1;
  }

  ctx.data_pipe =
      data_uds_create(socket_name, on_data_packet, on_is_track_ready, &ctx);
  if (!ctx.data_pipe) {
    fprintf(stderr, "failed to create UDS data pipe\n");
    return 1;
  }

  daemon_run(&ctx);

  for (size_t i = 0; i < ctx.num_transports; i++)
    transport_shutdown(ctx.transports[i].transport, "daemon shutdown");
  int64_t shutdown_started = transport_get_time_ms();
  bool drained = false;
  while (!drained && transport_get_time_ms() - shutdown_started < 1000) {
    drained = true;
    for (size_t i = 0; i < ctx.num_transports; i++) {
      transport_tick(ctx.transports[i].transport);
      if (!transport_is_drained(ctx.transports[i].transport))
        drained = false;
    }
    if (!drained)
      usleep(1000);
  }

  data_uds_destroy(ctx.data_pipe);
  for (size_t i = 0; i < ctx.num_transports; i++) {
    transport_destroy(ctx.transports[i].transport);
  }

  portable_socket_cleanup();
  return 0;
}
