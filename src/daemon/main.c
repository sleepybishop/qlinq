/* main.c (daemon) */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "data_uds.h"
#include "transport.h"
#include "portable_sockets.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_TRANSPORTS 16

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
} daemon_ctx_t;

static void subscribe_to_tracks(transport_t *t, daemon_ctx_t *ctx) {
  for (size_t i = 0; i < ctx->num_subscribe_tracks; i++) {
    moq_track_id_t t_data = {.type = MOQ_TRACK_DATA,
                             .flags = ctx->use_reliable ? MOQ_TRACK_FLAG_RELIABLE : MOQ_TRACK_FLAG_FEC_ENABLED};
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
      transport_send_auth(t, event->conn, (const uint8_t *)"secret_token_123",
                          strlen("secret_token_123"));
    }
    break;
  case TRANSPORT_EVENT_AUTH:
    if (tctx->is_server) {
      bool success = false;
      if (event->auth.token_len == strlen("secret_token_123") &&
          memcmp(event->auth.token, "secret_token_123",
                 event->auth.token_len) == 0) {
        success = true;
        printf("peer authentication successful\n");
        subscribe_to_tracks(t, ctx);
      } else {
        printf("peer authentication failed\n");
      }
      transport_respond_auth(t, event->conn, success);
    }
    break;
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    if (event->auth.success) {
      printf("authentication to peer successful\n");
      subscribe_to_tracks(t, ctx);
    } else {
      fprintf(stderr, "authentication failed, disconnecting from peer\n");
    }
    break;
  case TRANSPORT_EVENT_DISCONNECTED:
    printf("peer disconnected\n");
    break;
  case TRANSPORT_EVENT_SUBSCRIBE:
    printf("daemon: peer subscribed to track '%s' (type %d)\n", event->track_id.name, event->track_id.type);
    break;
  case TRANSPORT_EVENT_UNSUBSCRIBE:
    printf("daemon: peer unsubscribed from track '%s' (type %d)\n", event->track_id.name, event->track_id.type);
    break;
  case TRANSPORT_EVENT_OBJECT:
    if (event->track_id.type == MOQ_TRACK_DATA) {
      printf("daemon: received object from peer on track '%s', size=%zu, flags=%d, type=%d\n",
             event->track_id.name, event->object.size, event->track_id.flags,
             event->track_id.type);
    }
    if (ctx->data_pipe && event->track_id.type == MOQ_TRACK_DATA && (event->track_id.flags & MOQ_TRACK_FLAG_FEC_ENABLED)) {
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
        printf("daemon: forwarding packet to UDS client, len=%d\n", pkt_len);
        data_uds_send(ctx->data_pipe, &event->track_id, ptr + 2, pkt_len,
                      event->object.priority);
        ptr += 2 + pkt_len;
        remaining -= 2 + pkt_len;
      }
    } else if (ctx->data_pipe) {
      /* Forward raw packet for reliable tracks */
      printf("daemon: forwarding raw packet to UDS client, len=%zu\n", event->object.size);
      data_uds_send(ctx->data_pipe, &event->track_id, event->object.data,
                    event->object.size, event->object.priority);
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
      printf("daemon: forwarding UDS packet to transport %zu, size=%zu, track='%s'\n",
             i, size, track_id->name);
      transport_publish(ctx->transports[i].transport, &obj);
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

int main(int argc, char **argv) {
  /* Rest of main remains unchanged... */
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  printf("starting bishlinkd peer mesh daemon...\n");

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

  const char *cert_file = "t/assets/server.crt";
  const char *key_file = "t/assets/server.key";
  const char *ca_file = NULL;
  bool verify_peer = false;
  const char *socket_name = "bishlink-data";

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
      listen_port = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) {
      listen_host = argv[++i];
    } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
      cert_file = argv[++i];
    } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
      key_file = argv[++i];
    } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
      ca_file = argv[++i];
    } else if (strcmp(argv[i], "--verify-peer") == 0) {
      verify_peer = true;
    } else if ((strcmp(argv[i], "--socket") == 0 || strcmp(argv[i], "-s") == 0) && i + 1 < argc) {
      socket_name = argv[++i];
    } else if (strcmp(argv[i], "--peer") == 0 && i + 1 < argc) {
      if (num_peers < MAX_TRANSPORTS - 1) {
        peers[num_peers++] = argv[++i];
      }
    } else if (strcmp(argv[i], "--track") == 0 && i + 1 < argc) {
      if (ctx.num_subscribe_tracks < 15) {
        strncpy(ctx.subscribe_tracks[ctx.num_subscribe_tracks++], argv[++i], 63);
      }
    } else if (strcmp(argv[i], "--reliable") == 0) {
      ctx.use_reliable = true;
    }
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
    /* parse ip:port */
    char peer_ip[256];
    strncpy(peer_ip, peers[i], sizeof(peer_ip));
    peer_ip[sizeof(peer_ip) - 1] = '\0';
    char *colon = strchr(peer_ip, ':');
    int port = 8888;
    if (colon) {
      *colon = '\0';
      port = atoi(colon + 1);
    }
    
    config.port = port;
    config.remote_hosts[config.num_remote_hosts++] = peer_ip;
    config.bind_hosts[config.num_bind_hosts++] = "0.0.0.0";
    config.cert_file = cert_file;
    config.key_file = key_file;
    config.ca_file = ca_file;
    config.verify_peer = verify_peer;
    
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

  ctx.data_pipe = data_uds_create(socket_name, on_data_packet, on_is_track_ready, &ctx);
  if (!ctx.data_pipe) {
    fprintf(stderr, "failed to create UDS data pipe\n");
    return 1;
  }

  printf("daemon is running. press ctrl+c to exit.\n");
  while (ctx.running) {
    data_uds_tick(ctx.data_pipe);
    for (size_t i = 0; i < ctx.num_transports; i++) {
      transport_tick(ctx.transports[i].transport);
    }
    usleep(3000); /* 3ms tick rate for optimal packet batching */
  }

  data_uds_destroy(ctx.data_pipe);
  for (size_t i = 0; i < ctx.num_transports; i++) {
    transport_destroy(ctx.transports[i].transport);
  }

  portable_socket_cleanup();
  return 0;
}
