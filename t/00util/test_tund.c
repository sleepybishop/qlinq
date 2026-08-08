/* test_tund.c */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "data_uds.h"
#include "transport.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
  transport_t *transport;
  transport_conn_t *conn;
  data_uds_t *data_pipe;
  bool is_server;
} pipe_ctx_t;

static void on_uds_packet(void *user_data, const moq_track_id_t *track_id,
                          const uint8_t *buf, size_t size, uint8_t priority) {
  pipe_ctx_t *ctx = user_data;
  if (!ctx || !ctx->transport)
    return;

  moq_object_t obj = {.track_id = *track_id,
                      .group_id = 0,
                      .object_id = 0,
                      .data = buf,
                      .size = size,
                      .is_keyframe = false,
                      .priority = priority};
  transport_publish(ctx->transport, &obj);
}

static void on_quic_event(void *user_data, const transport_event_t *event) {
  pipe_ctx_t *ctx = user_data;
  if (!ctx)
    return;

  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    ctx->conn = event->conn;
    if (!ctx->is_server) {
      transport_send_auth(ctx->transport, ctx->conn,
                          (const uint8_t *)"secret_token_123",
                          strlen("secret_token_123"));
    }
    break;
  case TRANSPORT_EVENT_AUTH:
    if (ctx->is_server) {
      transport_respond_auth(ctx->transport, event->conn, true);
    }
    break;
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    if (!ctx->is_server && event->auth.success) {
      moq_track_id_t t_data = {.type = MOQ_TRACK_DATA,
                               .flags = MOQ_TRACK_FLAG_FEC_ENABLED};
      strcpy(t_data.name, "test-track");
      transport_subscribe(ctx->transport, t_data);
    }
    break;
  case TRANSPORT_EVENT_OBJECT:
    if (event->track_id.type == MOQ_TRACK_DATA && ctx->data_pipe) {
      /* Unpack length-prefixed packets */
      const uint8_t *ptr = event->object.data;
      size_t remaining = event->object.size;
      while (remaining >= 2) {
        uint16_t pkt_len;
        memcpy(&pkt_len, ptr, 2);
        pkt_len = ntohs(pkt_len);
        if (remaining < 2 + (size_t)pkt_len) {
          break;
        }
        data_uds_send(ctx->data_pipe, &event->track_id, ptr + 2, pkt_len,
                      event->object.priority);
        ptr += 2 + pkt_len;
        remaining -= 2 + pkt_len;
      }
    }
    break;
  default:
    break;
  }
}

int main(void) {
  printf("starting bidirectional TUN tunneling integration test...\n");

  pipe_ctx_t server_ctx = {0};
  pipe_ctx_t client_ctx = {0};

  /* 1. setup server transport */
  transport_config_t server_cfg = {0};
  server_cfg.bind_hosts[0] = "127.0.0.1";
  server_cfg.num_bind_hosts = 1;
  server_cfg.port = 9001;
  server_cfg.cert_file = "t/assets/server.crt";
  server_cfg.key_file = "t/assets/server.key";
  server_cfg.callback = on_quic_event;
  server_cfg.user_data = &server_ctx;
  server_ctx.is_server = true;
  server_ctx.transport = transport_create(&server_cfg);
  if (!server_ctx.transport) {
    fprintf(stderr, "failed to create server transport\n");
    return 1;
  }

  /* register test event hooks */
  /* note: since user_data is server_ctx/client_ctx, we can use a wrapper or
   * just drive state */
  /* we'll drive loop ticks and check client subscription directly */

  /* 2. setup client transport */
  transport_config_t client_cfg = {0};
  client_cfg.bind_hosts[0] = "127.0.0.1";
  client_cfg.num_bind_hosts = 1;
  client_cfg.remote_hosts[0] = "127.0.0.1";
  client_cfg.num_remote_hosts = 1;
  client_cfg.port = 9001;
  client_cfg.cert_file = NULL;
  client_cfg.key_file = NULL;
  client_cfg.callback = on_quic_event;
  client_cfg.user_data = &client_ctx;
  client_ctx.is_server = false;
  client_ctx.transport = transport_create(&client_cfg);
  if (!client_ctx.transport) {
    fprintf(stderr, "failed to create client transport\n");
    transport_destroy(server_ctx.transport);
    return 1;
  }

  /* 3. setup UDS data pipes */
  server_ctx.data_pipe =
      data_uds_create("qlinq-data", on_uds_packet, NULL, &server_ctx);
  client_ctx.data_pipe =
      data_uds_create("qlinq-data-client", on_uds_packet, NULL, &client_ctx);

  /* 4. loop transport ticks until connected and subscribed */
  printf("connecting loopback QUIC sockets...\n");
  int retries = 150;
  while (retries-- > 0) {
    transport_tick(server_ctx.transport);
    transport_tick(client_ctx.transport);
    usleep(10 * 1000);
  }

  /* 5. fork and run mock tund hosts */
  unlink("/tmp/tund_host.log");
  unlink("/tmp/tund_client.log");

  pid_t pid_host = fork();
  if (pid_host == 0) {
    int log_fd = open("/tmp/tund_host.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    dup2(log_fd, STDOUT_FILENO);
    close(log_fd);

    char *args[] = {
        "./qlinq-tund", "--mock",     "--socket",    "qlinq-data", "-i",
        "tun-host",     "-a",         "10.8.0.1/24", "--priority", "high",
        "--track",      "test-track", NULL};
    execv(args[0], args);
    exit(1);
  }

  pid_t pid_client = fork();
  if (pid_client == 0) {
    int log_fd =
        open("/tmp/tund_client.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    dup2(log_fd, STDOUT_FILENO);
    close(log_fd);

    char *args[] = {
        "./qlinq-tund", "--mock",     "--socket",    "qlinq-data-client", "-i",
        "tun-client",   "-a",         "10.8.0.2/24", "--priority",        "low",
        "--track",      "test-track", NULL};
    execv(args[0], args);
    exit(1);
  }

  /* 6. run traffic loop for 1.5 seconds */
  printf("running traffic loop for bidirectional mock tunnel...\n");
  for (int i = 0; i < 150; i++) {
    data_uds_tick(server_ctx.data_pipe);
    data_uds_tick(client_ctx.data_pipe);
    transport_tick(server_ctx.transport);
    transport_tick(client_ctx.transport);
    usleep(10 * 1000);
  }

  /* 7. kill mock tund instances */
  kill(pid_host, SIGTERM);
  kill(pid_client, SIGTERM);
  waitpid(pid_host, NULL, 0);
  waitpid(pid_client, NULL, 0);

  /* 8. destroy resources */
  data_uds_destroy(server_ctx.data_pipe);
  data_uds_destroy(client_ctx.data_pipe);
  transport_destroy(client_ctx.transport);
  transport_destroy(server_ctx.transport);

  /* 9. verify log files contain cross-transmitted packets */
  FILE *h_log = fopen("/tmp/tund_host.log", "r");
  FILE *c_log = fopen("/tmp/tund_client.log", "r");
  if (!h_log || !c_log) {
    fprintf(stderr, "failed to open mock tund logs\n");
    if (h_log)
      fclose(h_log);
    if (c_log)
      fclose(c_log);
    return 1;
  }

  char line[256];
  bool host_got_packet = false;
  bool client_got_packet = false;

  while (fgets(line, sizeof(line), h_log)) {
    if (strstr(line, "MOCK: received packet starting with 0x45") &&
        strstr(line, "priority=0")) {
      host_got_packet = true;
    }
  }
  while (fgets(line, sizeof(line), c_log)) {
    if (strstr(line, "MOCK: received packet starting with 0x45") &&
        strstr(line, "priority=2")) {
      client_got_packet = true;
    }
  }

  fclose(h_log);
  fclose(c_log);

  if (!host_got_packet || !client_got_packet) {
    fprintf(stderr,
            "verification failed: host_got_packet=%d client_got_packet=%d\n",
            host_got_packet, client_got_packet);
    return 1;
  }

  printf("===TUND OK===\n");
  return 0;
}
