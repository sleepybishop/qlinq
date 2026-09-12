/* test_transport.c */

#include "transport.h"
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
  bool connected;
  bool subscribed;
  bool object_received;
  uint8_t received_data[100];
  size_t received_size;
  transport_t *transport;
  int data_subscriptions;
  bool data_a_received;
  bool data_b_received;
  bool checkpoint_subscribed;
  bool checkpoint_unsubscribed;
  size_t checkpoint_objects_received;
  uint64_t catalog_group_id;
  uint64_t catalog_object_id;
  uint8_t catalog_priority;
  uint64_t video_group_id;
  uint64_t video_object_id;
  bool protocol_ready_observed;
  uint32_t connection_id;
  bool disconnected;
  bool disconnect_remote;
  uint64_t disconnect_error;
  char disconnect_reason[128];
  uint64_t log_records;
  uint64_t insecure_warnings;
} test_state_t;

static void record_disconnect(test_state_t *state,
                              const transport_event_t *event) {
  state->disconnected = true;
  state->disconnect_remote = event->disconnect.remote;
  state->disconnect_error = event->disconnect.error_code;
  snprintf(state->disconnect_reason, sizeof(state->disconnect_reason), "%s",
           event->disconnect.reason ? event->disconnect.reason : "");
}

static void on_log(void *user_data, const transport_log_event_t *event) {
  test_state_t *state = user_data;
  state->log_records++;
  if (event->level == TRANSPORT_LOG_WARNING &&
      strcmp(event->component, "tls") == 0 &&
      strstr(event->message, "verification is disabled"))
    state->insecure_warnings++;
}

static void record_connection(test_state_t *state, transport_conn_t *conn) {
  transport_conn_stats_t stats;
  if (transport_get_conn_stats(state->transport, conn, &stats)) {
    state->protocol_ready_observed = stats.protocol_ready;
    state->connection_id = transport_get_conn_id(state->transport, conn);
  }
}

static void on_server_event(void *user_data, const transport_event_t *event) {
  test_state_t *state = user_data;
  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    state->connected = true;
    record_connection(state, event->conn);
    break;
  case TRANSPORT_EVENT_SUBSCRIBE:
    if (event->track_id.type == MOQ_TRACK_TEXT &&
        strcmp(event->track_id.name, "catalog") == 0) {
      /* serialize catalog manifest */
      const char *manifest = "video:fec:video_track\ndata:fec:data_track\n";
      moq_object_t cat_obj = {.track_id = event->track_id,
                              .group_id = UINT64_C(0x12345678abcdef01),
                              .object_id = UINT64_C(0xfedcba9876543210),
                              .data = (const uint8_t *)manifest,
                              .size = strlen(manifest),
                              .is_keyframe = true,
                              .priority = 2};
      transport_publish(state->transport, &cat_obj);
    } else if (event->track_id.type == MOQ_TRACK_VIDEO &&
               strcmp(event->track_id.name, "video_track") == 0) {
      state->subscribed = true;
    } else if ((event->track_id.type == MOQ_TRACK_DATA &&
                (strcmp(event->track_id.name, "data-a") == 0 ||
                 strcmp(event->track_id.name, "data-b") == 0)) ||
               (event->track_id.type == MOQ_TRACK_AUDIO &&
                strcmp(event->track_id.name, "queue-limit") == 0)) {
      state->data_subscriptions++;
    } else if (event->track_id.type == MOQ_TRACK_DATA &&
               strcmp(event->track_id.name, "checkpoint-data") == 0) {
      state->checkpoint_subscribed = true;
    }
    break;
  case TRANSPORT_EVENT_AUTH:
    transport_respond_auth(state->transport, event->conn, true);
    break;
  case TRANSPORT_EVENT_DISCONNECTED:
    record_disconnect(state, event);
    break;
  case TRANSPORT_EVENT_UNSUBSCRIBE:
    if (event->track_id.type == MOQ_TRACK_DATA &&
        strcmp(event->track_id.name, "checkpoint-data") == 0)
      state->checkpoint_unsubscribed = true;
    break;
  default:
    break;
  }
}

static void on_client_event(void *user_data, const transport_event_t *event) {
  test_state_t *state = user_data;
  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    record_connection(state, event->conn);
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
    if (event->track_id.type == MOQ_TRACK_TEXT &&
        strcmp(event->track_id.name, "catalog") == 0) {
      state->catalog_group_id = event->object.group_id;
      state->catalog_object_id = event->object.object_id;
      state->catalog_priority = event->object.priority;
      char manifest[256];
      if (event->object.size < sizeof(manifest)) {
        memcpy(manifest, event->object.data, event->object.size);
        manifest[event->object.size] = '\0';

        char *line = manifest;
        while (*line) {
          size_t line_len = strcspn(line, "\n");
          if (line_len > 0) {
            char saved_char = line[line_len];
            line[line_len] = '\0';

            char *type_str = line;
            size_t type_len = strcspn(type_str, ":");
            if (type_str[type_len] == ':') {
              type_str[type_len] = '\0';

              char *flags_str = type_str + type_len + 1;
              size_t flags_len = strcspn(flags_str, ":");
              if (flags_str[flags_len] == ':') {
                flags_str[flags_len] = '\0';

                char *name_str = flags_str + flags_len + 1;

                moq_track_id_t disc_track = {0};
                if (strcmp(type_str, "video") == 0) {
                  disc_track.type = MOQ_TRACK_VIDEO;
                } else if (strcmp(type_str, "data") == 0) {
                  disc_track.type = MOQ_TRACK_DATA;
                } else if (strcmp(type_str, "text") == 0) {
                  disc_track.type = MOQ_TRACK_TEXT;
                }

                if (strcmp(flags_str, "fec") == 0) {
                  disc_track.flags = MOQ_TRACK_FLAG_FEC_ENABLED;
                } else if (strcmp(flags_str, "reliable") == 0) {
                  disc_track.flags = MOQ_TRACK_FLAG_RELIABLE;
                }

                strcpy(disc_track.name, name_str);
                printf("client parsed discovered track: type=%s, name=%s\n",
                       type_str, name_str);
                transport_subscribe(state->transport, disc_track);
              }
            }
            line[line_len] = saved_char;
          }
          line += line_len;
          if (*line == '\n') {
            line++;
          }
        }
      }
    } else if (event->track_id.type == MOQ_TRACK_VIDEO &&
               strcmp(event->track_id.name, "video_track") == 0) {
      state->object_received = true;
      state->video_group_id = event->object.group_id;
      state->video_object_id = event->object.object_id;
      state->received_size = event->object.size;
      if (event->object.size < sizeof(state->received_data)) {
        memcpy(state->received_data, event->object.data, event->object.size);
        state->received_data[event->object.size] = '\0';
      }
    } else if (event->track_id.type == MOQ_TRACK_DATA &&
               strcmp(event->track_id.name, "data-a") == 0) {
      state->data_a_received = true;
    } else if (event->track_id.type == MOQ_TRACK_DATA &&
               strcmp(event->track_id.name, "data-b") == 0) {
      state->data_b_received = true;
    } else if (event->track_id.type == MOQ_TRACK_DATA &&
               strcmp(event->track_id.name, "checkpoint-data") == 0) {
      state->checkpoint_objects_received++;
    }
    break;
  case TRANSPORT_EVENT_DISCONNECTED:
    record_disconnect(state, event);
    break;
  default:
    break;
  }
}

int main(void) {
  test_state_t server_state = {0};
  test_state_t client_state = {0};

  transport_config_t rejected_cfg = {0};
  rejected_cfg.bind_hosts[0] = "127.0.0.1";
  rejected_cfg.num_bind_hosts = 1;
  rejected_cfg.port = 9998;
  rejected_cfg.cert_file = "t/assets/server.crt";
  rejected_cfg.key_file = "t/assets/server.key";
  rejected_cfg.callback = on_server_event;
  if (transport_create(&rejected_cfg) != NULL) {
    fprintf(stderr,
            "insecure transport was accepted without explicit opt-in\n");
    return 1;
  }
  rejected_cfg.allow_insecure_peer = true;
  rejected_cfg.remote_hosts[0] = "127.0.0.1";
  rejected_cfg.num_remote_hosts = 1;
  rejected_cfg.reconnect_enabled = true;
  rejected_cfg.reconnect_initial_delay_ms =
      TRANSPORT_DEFAULT_RECONNECT_MAX_DELAY_MS + 1U;
  if (transport_create(&rejected_cfg) != NULL) {
    fprintf(stderr, "invalid reconnect backoff configuration was accepted\n");
    return 1;
  }
  rejected_cfg.num_remote_hosts = 0;
  rejected_cfg.reconnect_enabled = false;
  rejected_cfg.reconnect_initial_delay_ms = 0;
  rejected_cfg.num_bind_hosts = TRANSPORT_MAX_PATHS + 1;
  if (transport_create(&rejected_cfg) != NULL) {
    fprintf(stderr, "oversized path configuration was accepted\n");
    return 1;
  }

  /* create server transport config */
  transport_config_t server_cfg = {0};
  server_cfg.bind_hosts[0] = "127.0.0.1";
  server_cfg.num_bind_hosts = 1;
  server_cfg.port = 9999;
  server_cfg.cert_file = "t/assets/server.crt";
  server_cfg.key_file = "t/assets/server.key";
  server_cfg.callback = on_server_event;
  server_cfg.allow_insecure_peer = true;
  server_cfg.user_data = &server_state;
  server_cfg.log_callback = on_log;
  server_cfg.log_user_data = &server_state;

  /* create client transport config */
  transport_config_t client_cfg = {0};
  client_cfg.bind_hosts[0] = "127.0.0.1";
  client_cfg.num_bind_hosts = 1;
  client_cfg.remote_hosts[0] = "127.0.0.1";
  client_cfg.num_remote_hosts = 1;
  client_cfg.port = 9999;
  client_cfg.cert_file = NULL;
  client_cfg.key_file = NULL;
  client_cfg.callback = on_client_event;
  client_cfg.allow_insecure_peer = true;
  client_cfg.user_data = &client_state;
  client_cfg.log_callback = on_log;
  client_cfg.log_user_data = &client_state;

  printf("creating server and client transports...\n");
  transport_t *server = transport_create(&server_cfg);
  if (!server) {
    fprintf(stderr, "failed to create server transport\n");
    return 1;
  }
  server_state.transport = server;

  const uint8_t no_peer_data[] = {0};
  moq_object_t no_peer_object = {.track_id = {.type = MOQ_TRACK_TEXT,
                                              .flags = MOQ_TRACK_FLAG_RELIABLE,
                                              .name = "no-peer"},
                                 .data = no_peer_data,
                                 .size = sizeof(no_peer_data)};
  if (transport_publish_ex(server, &no_peer_object) !=
      TRANSPORT_PUBLISH_NO_RECIPIENTS) {
    fprintf(stderr, "no-recipient publication result was not explicit\n");
    transport_destroy(server);
    return 1;
  }

  transport_t *client = transport_create(&client_cfg);
  if (!client) {
    fprintf(stderr, "failed to create client transport\n");
    transport_destroy(server);
    return 1;
  }
  client_state.transport = client;

  /* wait for connection */
  printf("connecting...\n");
  int retries = 100;
  while (retries-- > 0 &&
         (!server_state.connected || !client_state.connected)) {
    transport_tick(server);
    transport_tick(client);
    usleep(10 * 1000);
  }

  if (!server_state.connected || !client_state.connected) {
    fprintf(stderr, "failed to establish connection\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }
  if (!client_state.protocol_ready_observed ||
      !server_state.protocol_ready_observed ||
      client_state.connection_id == 0 || server_state.connection_id == 0) {
    fprintf(stderr, "protocol handshake was not observable at connect time\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }
  transport_path_stats_t connected_path = {0};
  if (!transport_get_path_stats(client, 0, &connected_path) ||
      connected_path.lifecycle != TRANSPORT_PATH_ACTIVE) {
    fprintf(stderr, "connected primary path was not reported active\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }

  /* client subscribes to the catalog track */
  printf("subscribing to catalog track...\n");
  moq_track_id_t t_catalog = {.type = MOQ_TRACK_TEXT,
                              .flags = MOQ_TRACK_FLAG_RELIABLE,
                              .name = "catalog"};
  if (!transport_subscribe(client, t_catalog)) {
    fprintf(stderr, "failed to subscribe to catalog\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }

  /* wait for client to receive catalog, parse it, and subscribe to video track
   */
  retries = 200;
  while (retries-- > 0 && !server_state.subscribed) {
    transport_tick(server);
    transport_tick(client);
    usleep(10 * 1000);
  }

  if (!server_state.subscribed) {
    fprintf(stderr,
            "server did not receive dynamic video_track subscribe event\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }
  if (client_state.catalog_group_id != UINT64_C(0x12345678abcdef01) ||
      client_state.catalog_object_id != UINT64_C(0xfedcba9876543210) ||
      client_state.catalog_priority != 2) {
    fprintf(stderr, "reliable object metadata was not preserved\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }

  /* server publishes test media frame on the dynamically discovered track */
  printf("publishing video frame on dynamically discovered track...\n");
  const char *payload = "hello sleepy bishop!";
  moq_object_t obj = {.track_id = {.type = MOQ_TRACK_VIDEO,
                                   .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                                   .name = "video_track"},
                      .group_id = UINT64_C(0x10000002a),
                      .object_id = UINT64_C(0x100000001),
                      .data = (const uint8_t *)payload,
                      .size = strlen(payload),
                      .is_keyframe = true};

  if (!transport_publish(server, &obj)) {
    fprintf(stderr, "failed to publish object\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }

  retries = 100;
  while (retries-- > 0 && !client_state.object_received) {
    transport_tick(server);
    transport_tick(client);
    usleep(10 * 1000);
  }

  if (!client_state.object_received) {
    transport_stats_t client_diagnostic = {0};
    transport_stats_t server_diagnostic = {0};
    (void)transport_get_stats(client, &client_diagnostic);
    (void)transport_get_stats(server, &server_diagnostic);
    fprintf(stderr,
            "client did not receive published object on dynamic track "
            "(rx=%" PRIu64 ", malformed=%" PRIu64 ", sent=%" PRIu64
            ", queued=%zu, dropped=%" PRIu64 ", errors=%" PRIu64 ")\n",
            client_diagnostic.datagrams_received,
            client_diagnostic.malformed_datagrams,
            server_diagnostic.udp_packets_sent,
            server_diagnostic.egress_current_packets,
            server_diagnostic.egress_packets_dropped,
            server_diagnostic.udp_send_errors);
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }

  /* verify packet payloads */
  if (strcmp((char *)client_state.received_data, payload) != 0) {
    fprintf(stderr, "payload verification failed\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }
  if (client_state.video_group_id != UINT64_C(0x10000002a) ||
      client_state.video_object_id != UINT64_C(0x100000001)) {
    fprintf(stderr, "datagram object IDs were truncated\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }

  moq_track_id_t data_a = {.type = MOQ_TRACK_DATA,
                           .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                           .name = "data-a"};
  moq_track_id_t data_b = {.type = MOQ_TRACK_DATA,
                           .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                           .name = "data-b"};
  moq_track_id_t queue_track = {
      .type = MOQ_TRACK_AUDIO, .flags = 0, .name = "queue-limit"};
  if (!transport_subscribe(client, data_a) ||
      !transport_subscribe(client, data_b) ||
      !transport_subscribe(client, queue_track)) {
    fprintf(stderr, "edge-case subscriptions failed\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }
  retries = 100;
  while (retries-- > 0 && server_state.data_subscriptions < 3) {
    transport_tick(server);
    transport_tick(client);
    usleep(10 * 1000);
  }

  const uint8_t packet_a[] = "A";
  const uint8_t packet_b[] = "B";
  moq_object_t obj_a = {.track_id = data_a,
                        .object_id = 10,
                        .data = packet_a,
                        .size = sizeof(packet_a)};
  moq_object_t obj_b = {.track_id = data_b,
                        .object_id = 11,
                        .data = packet_b,
                        .size = sizeof(packet_b)};
  if (!transport_publish(server, &obj_a) ||
      !transport_publish(server, &obj_b)) {
    fprintf(stderr, "mixed-track publication failed\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }
  retries = 100;
  while (retries-- > 0 &&
         (!client_state.data_a_received || !client_state.data_b_received)) {
    transport_tick(server);
    transport_tick(client);
    usleep(10 * 1000);
  }
  if (!client_state.data_a_received || !client_state.data_b_received) {
    fprintf(stderr, "mixed FEC tracks were not delivered independently\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }

  /* Indexed FEC uses the grouped-object path, but rolling recovery
   * checkpoints are rateless-only. Cross the 32-object checkpoint boundary
   * and verify that the indexed session remains open. */
  for (uint64_t i = 0; i < 132; i++) {
    moq_object_t indexed_record = {.track_id = data_a,
                                   .object_id = 100 + i,
                                   .data = packet_a,
                                   .size = sizeof(packet_a),
                                   .priority = 1};
    if (!transport_publish(server, &indexed_record)) {
      fprintf(stderr,
              "indexed FEC checkpoint-boundary publication failed at record "
              "%" PRIu64 "\n",
              i);
      transport_destroy(client);
      transport_destroy(server);
      return 1;
    }
  }
  retries = 100;
  while (retries-- > 0) {
    transport_tick(server);
    transport_tick(client);
    usleep(5 * 1000);
  }
  transport_stats_t indexed_source_stats = {0};
  transport_stats_t indexed_receiver_stats = {0};
  if (!transport_get_stats(server, &indexed_source_stats) ||
      !transport_get_stats(client, &indexed_receiver_stats) ||
      indexed_source_stats.active_connections != 1 ||
      indexed_receiver_stats.active_connections != 1 ||
      indexed_source_stats.recovery_checkpoints_sent != 0 ||
      indexed_receiver_stats.recovery_checkpoints_received != 0 ||
      indexed_source_stats.protocol_errors != 0 ||
      indexed_receiver_stats.protocol_errors != 0) {
    fprintf(stderr, "indexed FEC incorrectly entered checkpoint recovery\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }

  moq_track_id_t checkpoint_track = {.type = MOQ_TRACK_DATA,
                                     .flags = MOQ_TRACK_FLAG_FEC_RATELESS,
                                     .name = "checkpoint-data"};
  if (!transport_subscribe(client, checkpoint_track)) {
    fprintf(stderr, "checkpoint subscription failed\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }
  retries = 200;
  while (retries-- > 0 && !server_state.checkpoint_subscribed) {
    transport_tick(server);
    transport_tick(client);
    usleep(10 * 1000);
  }
  if (!server_state.checkpoint_subscribed) {
    fprintf(stderr, "checkpoint subscription was not observed\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }

  const uint8_t checkpoint_record[] = "checkpoint-record";
  for (uint64_t i = 0; i < 260; i++) {
    moq_object_t record = {.track_id = checkpoint_track,
                           .object_id = i,
                           .data = checkpoint_record,
                           .size = sizeof(checkpoint_record),
                           .priority = 1};
    if (!transport_publish(server, &record)) {
      fprintf(stderr,
              "rolling checkpoint publication failed at record %" PRIu64 "\n",
              i);
      transport_destroy(client);
      transport_destroy(server);
      return 1;
    }
  }
  retries = 500;
  while (!transport_finish_track(server, checkpoint_track) && retries-- > 0) {
    transport_tick(server);
    transport_tick(client);
    usleep(1000);
  }
  if (retries <= 0) {
    fprintf(stderr, "checkpoint track completion failed\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }
  transport_stats_t checkpoint_source_stats = {0};
  transport_stats_t checkpoint_receiver_stats = {0};
  retries = 500;
  while (retries-- > 0) {
    transport_tick(server);
    transport_tick(client);
    (void)transport_get_stats(server, &checkpoint_source_stats);
    (void)transport_get_stats(client, &checkpoint_receiver_stats);
    if (client_state.checkpoint_objects_received == 65 &&
        checkpoint_source_stats.recovery_checkpoint_acks_received >= 3 &&
        checkpoint_source_stats.recovery_cache_releases >= 65)
      break;
    usleep(10 * 1000);
  }
  if (client_state.checkpoint_objects_received != 65 ||
      checkpoint_source_stats.recovery_checkpoints_sent != 2 ||
      checkpoint_receiver_stats.recovery_checkpoints_received != 2 ||
      checkpoint_source_stats.recovery_checkpoint_acks_received < 3 ||
      checkpoint_receiver_stats.recovery_checkpoint_acks_sent < 3 ||
      checkpoint_source_stats.recovery_cache_releases < 65 ||
      checkpoint_source_stats.track_ends_sent != 1 ||
      checkpoint_receiver_stats.track_ends_received != 1) {
    fprintf(stderr,
            "rolling checkpoint lifecycle failed (objects=%zu, cp_tx=%" PRIu64
            ", cp_rx=%" PRIu64 ", ack_tx=%" PRIu64 ", ack_rx=%" PRIu64
            ", released=%" PRIu64 ", end_tx=%" PRIu64 ", end_rx=%" PRIu64 ")\n",
            client_state.checkpoint_objects_received,
            checkpoint_source_stats.recovery_checkpoints_sent,
            checkpoint_receiver_stats.recovery_checkpoints_received,
            checkpoint_receiver_stats.recovery_checkpoint_acks_sent,
            checkpoint_source_stats.recovery_checkpoint_acks_received,
            checkpoint_source_stats.recovery_cache_releases,
            checkpoint_source_stats.track_ends_sent,
            checkpoint_receiver_stats.track_ends_received);
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }
  if (!transport_unsubscribe(client, checkpoint_track)) {
    fprintf(stderr, "checkpoint unsubscribe failed\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }
  retries = 100;
  while (retries-- > 0 && !server_state.checkpoint_unsubscribed) {
    transport_tick(server);
    transport_tick(client);
    usleep(10 * 1000);
  }
  if (!server_state.checkpoint_unsubscribed) {
    fprintf(stderr, "targeted unsubscribe was not observed\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }

  size_t too_large_size = TRANSPORT_MAX_RELIABLE_OBJECT_SIZE + 1U;
  uint8_t *too_large = malloc(too_large_size);
  moq_object_t large_reliable = {.track_id = {.type = MOQ_TRACK_TEXT,
                                              .flags = MOQ_TRACK_FLAG_RELIABLE,
                                              .name = "catalog"},
                                 .data = too_large,
                                 .size = too_large_size};
  if (!too_large || transport_publish(server, &large_reliable)) {
    fprintf(stderr, "oversized reliable object was accepted\n");
    free(too_large);
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }
  free(too_large);

  size_t queue_size = 500000;
  uint8_t *queue_payload = malloc(queue_size);
  moq_object_t queue_obj = {
      .track_id = queue_track, .data = queue_payload, .size = queue_size};
  if (!queue_payload || transport_publish(server, &queue_obj)) {
    fprintf(stderr, "object exceeding datagram queue capacity was accepted\n");
    free(queue_payload);
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }
  free(queue_payload);

  transport_stats_t client_stats;
  transport_stats_t server_stats;
  if (!transport_get_stats(client, &client_stats) ||
      !transport_get_stats(server, &server_stats) ||
      client_stats.protocol_handshakes_completed != 1 ||
      server_stats.protocol_handshakes_completed != 1 ||
      client_stats.stream_frames_received == 0 ||
      server_stats.stream_frames_received == 0 ||
      client_stats.active_connections != 1 ||
      server_stats.active_connections != 1 ||
      server_stats.publish_no_recipients == 0 ||
      server_stats.publish_delivered == 0 ||
      server_stats.publish_invalid == 0 ||
      server_stats.publish_backpressure == 0 ||
      client_state.insecure_warnings != 1 ||
      server_state.insecure_warnings != 1) {
    fprintf(stderr, "transport observability snapshot was incomplete\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }

  transport_shutdown(client, "test shutdown");
  retries = 500;
  while (retries-- > 0 &&
         (!transport_is_drained(client) || !transport_is_drained(server))) {
    transport_tick(client);
    transport_tick(server);
    usleep(10 * 1000);
  }
  if (!transport_is_drained(client) || !transport_is_drained(server) ||
      !client_state.disconnected || !server_state.disconnected ||
      client_state.disconnect_remote || !server_state.disconnect_remote ||
      client_state.disconnect_error != 0 ||
      server_state.disconnect_error != 0 ||
      strcmp(client_state.disconnect_reason, "test shutdown") != 0 ||
      strcmp(server_state.disconnect_reason, "test shutdown") != 0) {
    fprintf(stderr,
            "graceful shutdown or disconnect diagnostics were incomplete "
            "(client_drained=%d server_drained=%d client_seen=%d "
            "server_seen=%d client_remote=%d server_remote=%d "
            "client_error=%" PRIu64 " server_error=%" PRIu64
            " client_reason=%s server_reason=%s)\n",
            transport_is_drained(client), transport_is_drained(server),
            client_state.disconnected, server_state.disconnected,
            client_state.disconnect_remote, server_state.disconnect_remote,
            client_state.disconnect_error, server_state.disconnect_error,
            client_state.disconnect_reason, server_state.disconnect_reason);
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }

  printf("===TRANSPORT OK===\n");

  transport_destroy(client);
  transport_destroy(server);
  return 0;
}
