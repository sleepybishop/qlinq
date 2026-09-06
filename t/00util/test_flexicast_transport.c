#include "portable_sockets.h"
#include "transport.h"
#include "transport_internal.h"

#include <inttypes.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
  transport_t *transport;
  bool connected;
  size_t subscriptions;
  size_t unsubscriptions;
  size_t auth_requests;
  bool received;
  size_t objects_received;
  uint8_t payload[64];
  size_t payload_size;
} flexicast_test_state_t;

static void on_server(void *user_data, const transport_event_t *event) {
  flexicast_test_state_t *state = user_data;
  if (event->type == TRANSPORT_EVENT_CONNECTED) {
    state->connected = true;
  } else if (event->type == TRANSPORT_EVENT_AUTH) {
    state->auth_requests++;
    (void)transport_respond_auth(state->transport, event->conn, true);
  } else if (event->type == TRANSPORT_EVENT_SUBSCRIBE) {
    state->subscriptions++;
  } else if (event->type == TRANSPORT_EVENT_UNSUBSCRIBE) {
    state->unsubscriptions++;
  }
}

static void on_client(void *user_data, const transport_event_t *event) {
  flexicast_test_state_t *state = user_data;
  if (event->type == TRANSPORT_EVENT_CONNECTED) {
    (void)transport_send_auth(state->transport, event->conn,
                              (const uint8_t *)"flexicast-test", 14);
  } else if (event->type == TRANSPORT_EVENT_AUTH_COMPLETE &&
             event->auth.success) {
    state->connected = true;
  } else if (event->type == TRANSPORT_EVENT_OBJECT) {
    state->objects_received++;
    if (event->object.size <= sizeof(state->payload)) {
      memcpy(state->payload, event->object.data, event->object.size);
      state->payload_size = event->object.size;
      state->received = true;
    }
  }
}

static void drive(transport_t *server, transport_t *a, transport_t *b) {
  transport_tick(server);
  if (a)
    transport_tick(a);
  if (b)
    transport_tick(b);
}

static void drive_mesh(transport_t **transports, size_t count) {
  for (size_t i = 0; i < count; i++)
    if (transports[i])
      transport_tick(transports[i]);
}

static void configure_adaptive_controller(transport_config_t *config,
                                          bool adaptive) {
  if (!adaptive)
    return;
  config->flexicast_cc_mode = TRANSPORT_FLEXICAST_CC_ADAPTIVE;
  /* Correctness-matrix profile: keep deadlines short enough that lifecycle
   * tests measure state transitions rather than a deliberately slow floor. */
  config->flexicast_cc_startup_rate = 128U * 1024U;
  config->flexicast_cc_minimum_rate = 64U * 1024U;
  config->flexicast_cc_maximum_rate = 256U * 1024U;
  config->flexicast_cc_aggregate_rate_limit = 256U * 1024U;
  config->flexicast_cc_feedback_timeout_ms = 100;
}

static bool parse_u16(const char *value, uint16_t *parsed) {
  char *end = NULL;
  unsigned long number = strtoul(value, &end, 10);
  if (!value[0] || !end || *end != '\0' || number == 0 || number > UINT16_MAX)
    return false;
  *parsed = (uint16_t)number;
  return true;
}

static int run_netns_server(int family, const char *bind_host,
                            const char *group, uint16_t port,
                            uint16_t group_port, size_t expected_subscribers) {
  flexicast_test_state_t state = {0};
  transport_config_t config = {.bind_hosts = {bind_host},
                               .num_bind_hosts = 1,
                               .port = port,
                               .cert_file = "t/assets/server.crt",
                               .key_file = "t/assets/server.key",
                               .allow_insecure_peer = true,
                               .enable_flexicast = true,
                               .flexicast_group = group,
                               .flexicast_group_port = group_port,
                               .flexicast_interface = bind_host,
                               .callback = on_server,
                               .user_data = &state};
  transport_t *server = transport_create(&config);
  if (!server) {
    fprintf(stderr, "network-namespace source creation failed\n");
    return 1;
  }
  state.transport = server;
  transport_stats_t stats = {0};
  int retries = 3000;
  while (retries-- > 0) {
    transport_tick(server);
    (void)transport_get_stats(server, &stats);
    if (state.subscriptions >= expected_subscribers &&
        stats.flexicast_active_members >= expected_subscribers)
      break;
    usleep(5000);
  }
  if (state.subscriptions < expected_subscribers ||
      stats.flexicast_active_members < expected_subscribers) {
    fprintf(stderr,
            "network-namespace cohort not ready (subscriptions=%zu, "
            "members=%zu)\n",
            state.subscriptions, stats.flexicast_active_members);
    transport_destroy(server);
    return 1;
  }

  static const uint8_t payload[] = "cross-namespace native SSM";
  moq_track_id_t track = {.type = MOQ_TRACK_VIDEO, .name = "netns/video"};
  moq_object_t object = {.track_id = track,
                         .group_id = 1,
                         .object_id = 1,
                         .data = payload,
                         .size = sizeof(payload),
                         .priority = 1};
  if (!transport_publish(server, &object)) {
    fprintf(stderr, "network-namespace publication failed\n");
    transport_destroy(server);
    return 1;
  }
  retries = 800;
  while (retries-- > 0) {
    transport_tick(server);
    (void)transport_get_stats(server, &stats);
    if (stats.flexicast_native_packets_sent > 0 &&
        stats.flexicast_acks_received >= expected_subscribers)
      break;
    usleep(5000);
  }
  if (stats.flexicast_native_packets_sent == 0 ||
      stats.flexicast_acks_received < expected_subscribers) {
    fprintf(stderr,
            "native SSM was not acknowledged (native=%" PRIu64 ", acks=%" PRIu64
            ", fallbacks=%" PRIu64 ")\n",
            stats.flexicast_native_packets_sent, stats.flexicast_acks_received,
            stats.flexicast_fallbacks);
    transport_destroy(server);
    return 1;
  }
  for (int i = 0; i < 700; i++) {
    transport_tick(server);
    usleep(5000);
  }
  printf(family == 6 ? "===FLEXICAST NETNS IPV6 SOURCE OK===\n"
                     : "===FLEXICAST NETNS IPV4 SOURCE OK===\n");
  transport_destroy(server);
  return 0;
}

static int run_netns_client(int family, const char *bind_host,
                            const char *server_host, uint16_t port) {
  flexicast_test_state_t state = {0};
  transport_config_t config = {.bind_hosts = {bind_host},
                               .num_bind_hosts = 1,
                               .remote_hosts = {server_host},
                               .num_remote_hosts = 1,
                               .port = port,
                               .allow_insecure_peer = true,
                               .enable_flexicast = true,
                               .flexicast_interface = bind_host,
                               .callback = on_client,
                               .user_data = &state};
  transport_t *client = transport_create(&config);
  if (!client) {
    fprintf(stderr, "network-namespace receiver creation failed\n");
    return 1;
  }
  state.transport = client;
  int retries = 2400;
  while (retries-- > 0 && !state.connected) {
    transport_tick(client);
    usleep(5000);
  }
  moq_track_id_t track = {.type = MOQ_TRACK_VIDEO, .name = "netns/video"};
  if (!state.connected || !transport_subscribe(client, track)) {
    fprintf(stderr, "network-namespace receiver subscription failed\n");
    transport_destroy(client);
    return 1;
  }
  retries = 3000;
  while (retries-- > 0 && !state.received) {
    transport_tick(client);
    usleep(5000);
  }
  if (!state.received) {
    fprintf(stderr, "network-namespace receiver got no object\n");
    transport_destroy(client);
    return 1;
  }
  /* Keep the SSM socket open while the harness injects wrong-source traffic. */
  for (int i = 0; i < 600; i++) {
    transport_tick(client);
    usleep(5000);
  }
  transport_stats_t stats = {0};
  (void)transport_get_stats(client, &stats);
  bool valid = stats.flexicast_packets_received > 0 &&
               stats.flexicast_multicast_datagrams_received ==
                   stats.flexicast_packets_received &&
               stats.flexicast_multicast_datagrams_rejected == 0 &&
               stats.flexicast_fallbacks == 0;
  if (!transport_unsubscribe(client, track))
    valid = false;
  (void)transport_get_stats(client, &stats);
  if (stats.flexicast_active_memberships != 0 ||
      stats.flexicast_membership_leaves != 1)
    valid = false;
  if (!valid) {
    fprintf(stderr,
            "network-namespace receiver validation failed (packets=%" PRIu64
            ", socket=%" PRIu64 ", rejected=%" PRIu64 ", fallbacks=%" PRIu64
            ", leaves=%" PRIu64 ")\n",
            stats.flexicast_packets_received,
            stats.flexicast_multicast_datagrams_received,
            stats.flexicast_multicast_datagrams_rejected,
            stats.flexicast_fallbacks, stats.flexicast_membership_leaves);
    transport_destroy(client);
    return 1;
  }
  printf(family == 6 ? "===FLEXICAST NETNS IPV6 RECEIVER OK===\n"
                     : "===FLEXICAST NETNS IPV4 RECEIVER OK===\n");
  transport_destroy(client);
  return 0;
}

static int run_netns_noise(int family, const char *bind_host, const char *group,
                           uint16_t port, size_t count) {
  int af = family == 6 ? AF_INET6 : AF_INET;
  int fd = socket(af, SOCK_DGRAM, 0);
  if (fd < 0)
    return 1;
  struct sockaddr_storage local = {0}, destination = {0};
  socklen_t local_len, destination_len;
  if (family == 4) {
    struct sockaddr_in *src = (struct sockaddr_in *)&local;
    struct sockaddr_in *dst = (struct sockaddr_in *)&destination;
    src->sin_family = AF_INET;
    dst->sin_family = AF_INET;
    dst->sin_port = htons(port);
    if (inet_pton(AF_INET, bind_host, &src->sin_addr) != 1 ||
        inet_pton(AF_INET, group, &dst->sin_addr) != 1 ||
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &src->sin_addr,
                   sizeof(src->sin_addr)) != 0) {
      CLOSE_SOCKET(fd);
      return 1;
    }
    local_len = sizeof(*src);
    destination_len = sizeof(*dst);
  } else {
    struct sockaddr_in6 *src = (struct sockaddr_in6 *)&local;
    struct sockaddr_in6 *dst = (struct sockaddr_in6 *)&destination;
    unsigned int interface_index = if_nametoindex("eth0");
    src->sin6_family = AF_INET6;
    dst->sin6_family = AF_INET6;
    dst->sin6_port = htons(port);
    dst->sin6_scope_id = interface_index;
    if (interface_index == 0 ||
        inet_pton(AF_INET6, bind_host, &src->sin6_addr) != 1 ||
        inet_pton(AF_INET6, group, &dst->sin6_addr) != 1 ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &interface_index,
                   sizeof(interface_index)) != 0) {
      CLOSE_SOCKET(fd);
      return 1;
    }
    src->sin6_scope_id = interface_index;
    local_len = sizeof(*src);
    destination_len = sizeof(*dst);
  }
  if (bind(fd, (struct sockaddr *)&local, local_len) != 0) {
    CLOSE_SOCKET(fd);
    return 1;
  }
  static const uint8_t noise[] = "wrong-source-flexicast-probe";
  for (size_t i = 0; i < count; i++) {
    if (sendto(fd, noise, sizeof(noise), 0, (struct sockaddr *)&destination,
               destination_len) < 0) {
      CLOSE_SOCKET(fd);
      return 1;
    }
    usleep(10000);
  }
  CLOSE_SOCKET(fd);
  return 0;
}

static int run_mesh(bool shared_group, bool adaptive) {
  flexicast_test_state_t states[6] = {{0}};
  transport_config_t configs[6] = {
      {.bind_hosts = {"127.0.0.1"},
       .num_bind_hosts = 1,
       .port = 10011,
       .cert_file = "t/assets/server.crt",
       .key_file = "t/assets/server.key",
       .allow_insecure_peer = true,
       .enable_flexicast = true,
       .flexicast_group = "232.42.42.11",
       .flexicast_group_port = 10021,
       .flexicast_interface = "127.0.0.1",
       .callback = on_server,
       .user_data = &states[0]},
      {.bind_hosts = {"127.0.0.1"},
       .num_bind_hosts = 1,
       .port = 10012,
       .cert_file = "t/assets/server.crt",
       .key_file = "t/assets/server.key",
       .allow_insecure_peer = true,
       .enable_flexicast = true,
       .flexicast_group = "232.42.42.11",
       .flexicast_group_port = 10021,
       .flexicast_interface = "127.0.0.1",
       .callback = on_server,
       .user_data = &states[1]},
  };
  if (!shared_group) {
    configs[1].flexicast_group = "232.42.42.12";
    configs[1].flexicast_group_port = 10022;
  }
  configure_adaptive_controller(&configs[0], adaptive);
  configure_adaptive_controller(&configs[1], adaptive);
  for (size_t i = 2; i < 6; i++) {
    size_t source = i < 4 ? 0 : 1;
    configs[i] = (transport_config_t){.bind_hosts = {"127.0.0.1"},
                                      .num_bind_hosts = 1,
                                      .remote_hosts = {"127.0.0.1"},
                                      .num_remote_hosts = 1,
                                      .port = source == 0 ? 10011 : 10012,
                                      .allow_insecure_peer = true,
                                      .enable_flexicast = true,
                                      .flexicast_interface = "127.0.0.1",
                                      .callback = on_client,
                                      .user_data = &states[i]};
  }

  transport_t *transports[6] = {0};
  for (size_t i = 0; i < 6; i++) {
    transports[i] = transport_create(&configs[i]);
    if (!transports[i]) {
      fprintf(stderr, "failed to create mesh transport %zu\n", i);
      goto Fail;
    }
    states[i].transport = transports[i];
  }

  int retries = 1200;
  while (retries-- > 0 && (!states[2].connected || !states[3].connected ||
                           !states[4].connected || !states[5].connected)) {
    drive_mesh(transports, 6);
    usleep(5000);
  }
  if (!states[2].connected || !states[3].connected || !states[4].connected ||
      !states[5].connected) {
    fprintf(stderr, "mesh clients did not authenticate\n");
    goto Fail;
  }

  moq_track_id_t track_a = {.type = MOQ_TRACK_VIDEO, .name = "mesh/source-a"};
  moq_track_id_t track_b = {.type = MOQ_TRACK_AUDIO, .name = "mesh/source-b"};
  if (!transport_subscribe(transports[2], track_a) ||
      !transport_subscribe(transports[3], track_a) ||
      !transport_subscribe(transports[4], track_b) ||
      !transport_subscribe(transports[5], track_b)) {
    fprintf(stderr, "mesh subscriptions failed\n");
    goto Fail;
  }

  transport_stats_t source_a_stats = {0}, source_b_stats = {0};
  retries = 600;
  while (retries-- > 0) {
    drive_mesh(transports, 6);
    (void)transport_get_stats(transports[0], &source_a_stats);
    (void)transport_get_stats(transports[1], &source_b_stats);
    if (source_a_stats.flexicast_active_members == 2 &&
        source_b_stats.flexicast_active_members == 2)
      break;
    usleep(5000);
  }
  if (source_a_stats.flexicast_active_members != 2 ||
      source_b_stats.flexicast_active_members != 2 ||
      source_a_stats.flexicast_rekeys == 0 ||
      source_b_stats.flexicast_rekeys == 0) {
    fprintf(stderr, "mesh Flexicast cohorts did not become ready\n");
    goto Fail;
  }

  static const uint8_t payload_a[] = "publisher-a multicast";
  static const uint8_t payload_b[] = "publisher-b multicast";
  moq_object_t object_a = {.track_id = track_a,
                           .group_id = 1,
                           .object_id = 1,
                           .data = payload_a,
                           .size = sizeof(payload_a),
                           .priority = 2};
  moq_object_t object_b = {.track_id = track_b,
                           .group_id = 1,
                           .object_id = 1,
                           .data = payload_b,
                           .size = sizeof(payload_b),
                           .priority = 2};
  if (!transport_publish(transports[0], &object_a) ||
      !transport_publish(transports[1], &object_b)) {
    fprintf(stderr, "mesh publication failed\n");
    goto Fail;
  }
  retries = 600;
  while (retries-- > 0 && (!states[2].received || !states[3].received ||
                           !states[4].received || !states[5].received)) {
    drive_mesh(transports, 6);
    usleep(5000);
  }
  for (int i = 0; i < 10; i++)
    drive_mesh(transports, 6);
  (void)transport_get_stats(transports[0], &source_a_stats);
  (void)transport_get_stats(transports[1], &source_b_stats);
  if (!states[2].received || !states[3].received || !states[4].received ||
      !states[5].received || states[2].payload_size != sizeof(payload_a) ||
      states[3].payload_size != sizeof(payload_a) ||
      states[4].payload_size != sizeof(payload_b) ||
      states[5].payload_size != sizeof(payload_b) ||
      memcmp(states[2].payload, payload_a, sizeof(payload_a)) != 0 ||
      memcmp(states[3].payload, payload_a, sizeof(payload_a)) != 0 ||
      memcmp(states[4].payload, payload_b, sizeof(payload_b)) != 0 ||
      memcmp(states[5].payload, payload_b, sizeof(payload_b)) != 0 ||
      source_a_stats.flexicast_native_packets_sent == 0 ||
      source_b_stats.flexicast_native_packets_sent == 0 ||
      source_a_stats.flexicast_acks_received < 2 ||
      source_b_stats.flexicast_acks_received < 2) {
    fprintf(stderr, "concurrent mesh delivery failed\n");
    goto Fail;
  }

  /* Tear down and recreate publisher A and its subscribers while publisher B
   * keeps using the same multicast endpoint. B must remain deliverable, and A
   * must return with fresh flow/key state without disturbing it. */
  transport_destroy(transports[3]);
  transports[3] = NULL;
  transport_destroy(transports[2]);
  transports[2] = NULL;
  transport_destroy(transports[0]);
  transports[0] = NULL;
  memset(&states[0], 0, sizeof(states[0]));
  memset(&states[2], 0, sizeof(states[2]));
  memset(&states[3], 0, sizeof(states[3]));
  states[4].received = false;
  states[5].received = false;

  static const uint8_t payload_b_after_restart[] =
      "publisher-b survives peer restart";
  object_b.object_id = 2;
  object_b.data = payload_b_after_restart;
  object_b.size = sizeof(payload_b_after_restart);
  if (!transport_publish(transports[1], &object_b)) {
    fprintf(stderr, "uninterrupted publisher B publication failed\n");
    goto Fail;
  }
  retries = 600;
  while (retries-- > 0 && (!states[4].received || !states[5].received)) {
    drive_mesh(transports, 6);
    usleep(5000);
  }
  if (!states[4].received || !states[5].received ||
      states[4].payload_size != sizeof(payload_b_after_restart) ||
      states[5].payload_size != sizeof(payload_b_after_restart) ||
      memcmp(states[4].payload, payload_b_after_restart,
             sizeof(payload_b_after_restart)) != 0 ||
      memcmp(states[5].payload, payload_b_after_restart,
             sizeof(payload_b_after_restart)) != 0) {
    fprintf(stderr, "publisher B was interrupted by publisher A teardown\n");
    goto Fail;
  }

  for (size_t i = 0; i < 6; i++) {
    if (i != 0 && i != 2 && i != 3)
      continue;
    transports[i] = transport_create(&configs[i]);
    if (!transports[i]) {
      fprintf(stderr, "failed to restart mesh transport %zu\n", i);
      goto Fail;
    }
    states[i].transport = transports[i];
  }
  retries = 1200;
  while (retries-- > 0 && (!states[2].connected || !states[3].connected)) {
    drive_mesh(transports, 6);
    usleep(5000);
  }
  if (!states[2].connected || !states[3].connected ||
      !transport_subscribe(transports[2], track_a) ||
      !transport_subscribe(transports[3], track_a)) {
    fprintf(stderr, "publisher A restart subscriptions failed\n");
    goto Fail;
  }
  retries = 600;
  while (retries-- > 0) {
    drive_mesh(transports, 6);
    (void)transport_get_stats(transports[0], &source_a_stats);
    if (source_a_stats.flexicast_active_members == 2)
      break;
    usleep(5000);
  }
  static const uint8_t payload_a_after_restart[] = "publisher-a restarted";
  object_a.object_id = 2;
  object_a.data = payload_a_after_restart;
  object_a.size = sizeof(payload_a_after_restart);
  if (source_a_stats.flexicast_active_members != 2 ||
      !transport_publish(transports[0], &object_a)) {
    fprintf(stderr, "publisher A did not restore its protected cohort\n");
    goto Fail;
  }
  retries = 600;
  while (retries-- > 0 && (!states[2].received || !states[3].received)) {
    drive_mesh(transports, 6);
    usleep(5000);
  }
  if (!states[2].received || !states[3].received ||
      states[2].payload_size != sizeof(payload_a_after_restart) ||
      states[3].payload_size != sizeof(payload_a_after_restart) ||
      memcmp(states[2].payload, payload_a_after_restart,
             sizeof(payload_a_after_restart)) != 0 ||
      memcmp(states[3].payload, payload_a_after_restart,
             sizeof(payload_a_after_restart)) != 0) {
    fprintf(stderr, "restarted publisher A did not recover exact delivery\n");
    goto Fail;
  }

  printf("===FLEXICAST MESH OK===\n");
  for (size_t i = 6; i-- > 0;)
    transport_destroy(transports[i]);
  return 0;

Fail:
  for (size_t i = 6; i-- > 0;)
    if (transports[i])
      transport_destroy(transports[i]);
  return 1;
}

static int run_unsubscribe_lifecycle(bool ipv6, bool adaptive) {
  flexicast_test_state_t server_state = {0}, client_a_state = {0},
                         client_b_state = {0};
  transport_config_t server_config = {.bind_hosts = {"127.0.0.1"},
                                      .num_bind_hosts = 1,
                                      .port = 10041,
                                      .cert_file = "t/assets/server.crt",
                                      .key_file = "t/assets/server.key",
                                      .allow_insecure_peer = true,
                                      .enable_flexicast = true,
                                      .flexicast_group = "232.42.42.41",
                                      .flexicast_group_port = 10042,
                                      .flexicast_interface = "127.0.0.1",
                                      .callback = on_server,
                                      .user_data = &server_state};
  transport_config_t client_config = {.bind_hosts = {"127.0.0.1"},
                                      .num_bind_hosts = 1,
                                      .remote_hosts = {"127.0.0.1"},
                                      .num_remote_hosts = 1,
                                      .port = 10041,
                                      .allow_insecure_peer = true,
                                      .enable_flexicast = true,
                                      .flexicast_interface = "127.0.0.1",
                                      .callback = on_client,
                                      .user_data = &client_a_state};
  if (ipv6) {
    server_config.bind_hosts[0] = "::1";
    server_config.flexicast_group = "ff32::8000:41";
    server_config.flexicast_interface = "::1";
    client_config.bind_hosts[0] = "::1";
    client_config.remote_hosts[0] = "::1";
    client_config.flexicast_interface = "::1";
  }
  configure_adaptive_controller(&server_config, adaptive);
  transport_config_t client_b_config = client_config;
  client_b_config.user_data = &client_b_state;

  transport_t *server = transport_create(&server_config);
  transport_t *client_a = transport_create(&client_config);
  transport_t *client_b = transport_create(&client_b_config);
  if (!server || !client_a || !client_b) {
    fprintf(stderr, "failed to create unsubscribe lifecycle transports\n");
    goto Fail;
  }
  server_state.transport = server;
  client_a_state.transport = client_a;
  client_b_state.transport = client_b;

  int retries = 1200;
  while (retries-- > 0 &&
         (!client_a_state.connected || !client_b_state.connected)) {
    drive(server, client_a, client_b);
    usleep(5000);
  }
  if (!client_a_state.connected || !client_b_state.connected) {
    fprintf(stderr, "unsubscribe lifecycle clients did not authenticate\n");
    goto Fail;
  }

  moq_track_id_t track = {.type = MOQ_TRACK_VIDEO, .name = "unsubscribe/video"};
  if (!transport_subscribe(client_a, track) ||
      !transport_subscribe(client_b, track)) {
    fprintf(stderr, "unsubscribe lifecycle subscriptions failed\n");
    goto Fail;
  }

  transport_stats_t source_stats = {0}, a_stats = {0}, b_stats = {0};
  retries = 600;
  while (retries-- > 0) {
    drive(server, client_a, client_b);
    (void)transport_get_stats(server, &source_stats);
    (void)transport_get_stats(client_a, &a_stats);
    (void)transport_get_stats(client_b, &b_stats);
    if (source_stats.flexicast_active_members == 2 &&
        a_stats.flexicast_active_memberships == 1 &&
        b_stats.flexicast_active_memberships == 1)
      break;
    usleep(5000);
  }
  if (source_stats.flexicast_active_members != 2 ||
      a_stats.flexicast_active_memberships != 1 ||
      b_stats.flexicast_active_memberships != 1) {
    fprintf(stderr, "unsubscribe lifecycle cohort did not become ready\n");
    goto Fail;
  }

  uint64_t rekeys_before_leave = source_stats.flexicast_rekeys;
  if (!transport_unsubscribe(client_a, track) ||
      !transport_get_stats(client_a, &a_stats) ||
      a_stats.flexicast_active_flows != 0 ||
      a_stats.flexicast_active_memberships != 0 ||
      a_stats.flexicast_membership_leaves != 1) {
    fprintf(stderr, "unsubscribe did not immediately release membership\n");
    goto Fail;
  }

  retries = 600;
  while (retries-- > 0) {
    drive(server, client_a, client_b);
    (void)transport_get_stats(server, &source_stats);
    if (server_state.unsubscriptions == 1 &&
        source_stats.flexicast_active_members == 1 &&
        source_stats.flexicast_rekeys > rekeys_before_leave)
      break;
    usleep(5000);
  }
  if (server_state.unsubscriptions != 1 ||
      source_stats.flexicast_active_members != 1 ||
      source_stats.flexicast_rekeys <= rekeys_before_leave) {
    fprintf(stderr, "remaining cohort was not rekeyed after unsubscribe\n");
    goto Fail;
  }

  static const uint8_t remaining_payload[] = "remaining subscriber";
  moq_object_t object = {.track_id = track,
                         .group_id = 1,
                         .object_id = 1,
                         .data = remaining_payload,
                         .size = sizeof(remaining_payload),
                         .priority = 1};
  client_a_state.received = false;
  client_b_state.received = false;
  if (!transport_publish(server, &object)) {
    fprintf(stderr, "remaining cohort publication failed\n");
    goto Fail;
  }
  retries = 400;
  while (retries-- > 0 && !client_b_state.received) {
    drive(server, client_a, client_b);
    usleep(5000);
  }
  if (client_a_state.received || !client_b_state.received) {
    fprintf(stderr, "unsubscribed receiver still received publication\n");
    goto Fail;
  }

  uint64_t rekeys_before_rejoin = source_stats.flexicast_rekeys;
  if (!transport_subscribe(client_a, track)) {
    fprintf(stderr, "resubscribe failed\n");
    goto Fail;
  }
  retries = 600;
  while (retries-- > 0) {
    drive(server, client_a, client_b);
    (void)transport_get_stats(server, &source_stats);
    (void)transport_get_stats(client_a, &a_stats);
    if (source_stats.flexicast_active_members == 2 &&
        source_stats.flexicast_rekeys > rekeys_before_rejoin &&
        a_stats.flexicast_active_memberships == 1)
      break;
    usleep(5000);
  }
  if (source_stats.flexicast_active_members != 2 ||
      source_stats.flexicast_rekeys <= rekeys_before_rejoin ||
      a_stats.flexicast_membership_joins != 2 ||
      a_stats.flexicast_active_memberships != 1) {
    fprintf(stderr, "resubscribe did not establish a fresh SSM join\n");
    goto Fail;
  }

  static const uint8_t rejoined_payload[] = "rejoined subscriber";
  object.object_id++;
  object.data = rejoined_payload;
  object.size = sizeof(rejoined_payload);
  client_a_state.received = false;
  client_b_state.received = false;
  if (!transport_publish(server, &object)) {
    fprintf(stderr, "rejoined cohort publication failed\n");
    goto Fail;
  }
  retries = 400;
  while (retries-- > 0 &&
         (!client_a_state.received || !client_b_state.received)) {
    drive(server, client_a, client_b);
    usleep(5000);
  }
  if (!client_a_state.received || !client_b_state.received) {
    fprintf(stderr, "rejoined cohort did not receive publication\n");
    goto Fail;
  }

  if (!transport_unsubscribe(client_a, track) ||
      !transport_unsubscribe(client_b, track)) {
    fprintf(stderr, "final unsubscribe failed\n");
    goto Fail;
  }
  (void)transport_get_stats(client_a, &a_stats);
  (void)transport_get_stats(client_b, &b_stats);
  if (a_stats.flexicast_membership_leaves != 2 ||
      b_stats.flexicast_membership_leaves != 1 ||
      a_stats.flexicast_active_memberships != 0 ||
      b_stats.flexicast_active_memberships != 0) {
    fprintf(stderr, "final unsubscribe retained a kernel membership\n");
    goto Fail;
  }
  retries = 400;
  while (retries-- > 0) {
    drive(server, client_a, client_b);
    (void)transport_get_stats(server, &source_stats);
    if (server_state.unsubscriptions == 3 &&
        source_stats.flexicast_active_flows == 0)
      break;
    usleep(5000);
  }
  if (server_state.unsubscriptions != 3 ||
      source_stats.flexicast_active_flows != 0) {
    fprintf(stderr, "source retained the final unsubscribed cohort\n");
    goto Fail;
  }

  printf(ipv6 ? "===FLEXICAST IPV6 UNSUBSCRIBE OK===\n"
              : "===FLEXICAST UNSUBSCRIBE OK===\n");
  transport_destroy(client_b);
  transport_destroy(client_a);
  transport_destroy(server);
  return 0;

Fail:
  if (client_b)
    transport_destroy(client_b);
  if (client_a)
    transport_destroy(client_a);
  if (server)
    transport_destroy(server);
  return 1;
}

static int run_membership_lifecycle(bool ipv6, bool adaptive) {
  flexicast_test_state_t server_state = {0}, client_state = {0};
  transport_config_t server_config = {.bind_hosts = {"127.0.0.1"},
                                      .num_bind_hosts = 1,
                                      .port = 10031,
                                      .cert_file = "t/assets/server.crt",
                                      .key_file = "t/assets/server.key",
                                      .allow_insecure_peer = true,
                                      .enable_flexicast = true,
                                      .flexicast_group = "232.42.42.31",
                                      .flexicast_group_port = 10032,
                                      .flexicast_interface = "127.0.0.1",
                                      /* This test verifies shared kernel
                                       * membership teardown, not low-rate
                                       * serialization. Keep the floor-aware
                                       * feedback deadline short. */
                                      .flexicast_cc_minimum_rate = 64000,
                                      .flexicast_cc_feedback_timeout_ms = 100,
                                      .callback = on_server,
                                      .user_data = &server_state};
  transport_config_t client_config = {.bind_hosts = {"127.0.0.1"},
                                      .num_bind_hosts = 1,
                                      .remote_hosts = {"127.0.0.1"},
                                      .num_remote_hosts = 1,
                                      .port = 10031,
                                      .allow_insecure_peer = true,
                                      .enable_flexicast = true,
                                      .flexicast_interface = "127.0.0.1",
                                      .callback = on_client,
                                      .user_data = &client_state};
  if (ipv6) {
    server_config.bind_hosts[0] = "::1";
    server_config.flexicast_group = "ff32::8000:31";
    server_config.flexicast_interface = "::1";
    client_config.bind_hosts[0] = "::1";
    client_config.remote_hosts[0] = "::1";
    client_config.flexicast_interface = "::1";
  }
  configure_adaptive_controller(&server_config, adaptive);
  transport_t *server = transport_create(&server_config);
  transport_t *client = transport_create(&client_config);
  if (!server || !client) {
    fprintf(stderr, "failed to create membership lifecycle transports\n");
    goto Fail;
  }
  server_state.transport = server;
  client_state.transport = client;

  int retries = 1000;
  while (retries-- > 0 && !client_state.connected) {
    drive(server, client, NULL);
    usleep(5000);
  }
  if (!client_state.connected) {
    fprintf(stderr, "membership lifecycle client did not authenticate\n");
    goto Fail;
  }

  moq_track_id_t tracks[2] = {
      {.type = MOQ_TRACK_VIDEO, .name = "membership/video"},
      {.type = MOQ_TRACK_AUDIO, .name = "membership/audio"}};
  if (!transport_subscribe(client, tracks[0]) ||
      !transport_subscribe(client, tracks[1])) {
    fprintf(stderr, "membership lifecycle subscriptions failed\n");
    goto Fail;
  }

  transport_stats_t source_stats = {0}, receiver_stats = {0};
  retries = 600;
  while (retries-- > 0) {
    drive(server, client, NULL);
    (void)transport_get_stats(server, &source_stats);
    (void)transport_get_stats(client, &receiver_stats);
    if (source_stats.flexicast_active_flows == 2 &&
        source_stats.flexicast_active_members == 2 &&
        receiver_stats.flexicast_active_memberships == 1)
      break;
    usleep(5000);
  }
  if (source_stats.flexicast_active_flows != 2 ||
      source_stats.flexicast_active_members != 2 ||
      receiver_stats.flexicast_membership_joins != 1 ||
      receiver_stats.flexicast_active_memberships != 1) {
    fprintf(stderr,
            "two flows did not share one kernel membership "
            "(flows=%zu, members=%zu, joins=%" PRIu64 ", active=%zu)\n",
            source_stats.flexicast_active_flows,
            source_stats.flexicast_active_members,
            receiver_stats.flexicast_membership_joins,
            receiver_stats.flexicast_active_memberships);
    goto Fail;
  }

  uint8_t interface_address[16] = {0};
  uint32_t interface_index = if_nametoindex("lo");
  int family = ipv6 ? AF_INET6 : AF_INET;
  if (interface_index == 0 ||
      inet_pton(family, ipv6 ? "::1" : "127.0.0.1", interface_address) != 1) {
    fprintf(stderr, "unable to identify loopback multicast interface\n");
    goto Fail;
  }
  /* Link deletion can arrive without an address, so exercise the interface
   * index-only teardown path used by AF_UNSPEC ifmon notifications. */
  transport_flexicast_interface_removed(client, 0, NULL, interface_index);
  (void)transport_get_stats(client, &receiver_stats);
  if (receiver_stats.flexicast_active_memberships != 0 ||
      receiver_stats.flexicast_membership_leaves != 1 ||
      receiver_stats.flexicast_interface_fallbacks != 2) {
    fprintf(stderr, "interface loss did not release shared membership\n");
    goto Fail;
  }
  retries = 400;
  while (retries-- > 0) {
    drive(server, client, NULL);
    (void)transport_get_stats(server, &source_stats);
    if (source_stats.flexicast_active_members == 0)
      break;
    usleep(5000);
  }
  if (source_stats.flexicast_active_members != 0) {
    fprintf(stderr, "source did not fall back after interface loss\n");
    goto Fail;
  }

  transport_flexicast_interface_added(client, ipv6 ? 6U : 4U, interface_address,
                                      interface_index);
  retries = 600;
  while (retries-- > 0) {
    drive(server, client, NULL);
    (void)transport_get_stats(server, &source_stats);
    (void)transport_get_stats(client, &receiver_stats);
    if (source_stats.flexicast_active_members == 2 &&
        receiver_stats.flexicast_active_memberships == 1)
      break;
    usleep(5000);
  }
  if (source_stats.flexicast_active_members != 2 ||
      receiver_stats.flexicast_active_memberships != 1 ||
      receiver_stats.flexicast_membership_joins != 2 ||
      receiver_stats.flexicast_interface_rejoins != 2) {
    fprintf(stderr,
            "Flexicast cohort did not recover after interface return\n");
    goto Fail;
  }

  static const uint8_t probe[] = "membership timeout probe";
  for (size_t track_index = 0; track_index < 2; track_index++) {
    for (uint64_t i = 0; i < 40; i++) {
      moq_object_t object = {.track_id = tracks[track_index],
                             .group_id = 1,
                             .object_id = i,
                             .data = probe,
                             .size = sizeof(probe),
                             .priority = 1};
      if (!transport_publish(server, &object)) {
        fprintf(stderr, "membership timeout probe publication failed\n");
        goto Fail;
      }
    }
  }

  retries = 800;
  while (retries-- > 0) {
    transport_tick(server); /* deliberately withhold receiver PATH_ACKs */
    (void)transport_get_stats(server, &source_stats);
    if (source_stats.flexicast_feedback_fallbacks >= 2 &&
        source_stats.flexicast_active_members == 0)
      break;
    usleep(5000);
  }
  if (source_stats.flexicast_feedback_fallbacks != 2 ||
      source_stats.flexicast_active_members != 0) {
    fprintf(stderr,
            "feedback loss did not retire both multicast flows "
            "(fallbacks=%" PRIu64 ", members=%zu)\n",
            source_stats.flexicast_feedback_fallbacks,
            source_stats.flexicast_active_members);
    goto Fail;
  }

  retries = 300;
  while (retries-- > 0) {
    drive(server, client, NULL);
    (void)transport_get_stats(client, &receiver_stats);
    if (receiver_stats.flexicast_active_memberships == 0 &&
        receiver_stats.flexicast_membership_leaves == 2)
      break;
    usleep(5000);
  }
  if (receiver_stats.flexicast_membership_joins != 2 ||
      receiver_stats.flexicast_membership_leaves != 2 ||
      receiver_stats.flexicast_active_memberships != 0) {
    fprintf(stderr,
            "last flow did not drop the shared kernel membership "
            "(joins=%" PRIu64 ", leaves=%" PRIu64 ", active=%zu)\n",
            receiver_stats.flexicast_membership_joins,
            receiver_stats.flexicast_membership_leaves,
            receiver_stats.flexicast_active_memberships);
    goto Fail;
  }

  printf(ipv6 ? "===FLEXICAST IPV6 MEMBERSHIP OK===\n"
              : "===FLEXICAST MEMBERSHIP OK===\n");
  transport_destroy(client);
  transport_destroy(server);
  return 0;

Fail:
  if (client)
    transport_destroy(client);
  if (server)
    transport_destroy(server);
  return 1;
}

int main(int argc, char **argv) {
  if (argc == 8 && strcmp(argv[1], "--netns-server") == 0) {
    uint16_t port, group_port;
    char *end = NULL;
    unsigned long subscribers = strtoul(argv[7], &end, 10);
    int family = strcmp(argv[2], "6") == 0 ? 6 : 4;
    if (!parse_u16(argv[5], &port) || !parse_u16(argv[6], &group_port) ||
        !argv[7][0] || !end || *end != '\0' || subscribers == 0)
      return 1;
    return run_netns_server(family, argv[3], argv[4], port, group_port,
                            (size_t)subscribers);
  }
  if (argc == 6 && strcmp(argv[1], "--netns-client") == 0) {
    uint16_t port;
    int family = strcmp(argv[2], "6") == 0 ? 6 : 4;
    if (!parse_u16(argv[5], &port))
      return 1;
    return run_netns_client(family, argv[3], argv[4], port);
  }
  if (argc == 7 && strcmp(argv[1], "--netns-noise") == 0) {
    uint16_t port;
    char *end = NULL;
    unsigned long count = strtoul(argv[6], &end, 10);
    int family = strcmp(argv[2], "6") == 0 ? 6 : 4;
    if (!parse_u16(argv[5], &port) || !argv[6][0] || !end || *end != '\0' ||
        count == 0)
      return 1;
    return run_netns_noise(family, argv[3], argv[4], port, (size_t)count);
  }
  bool matrix_adaptive = argc == 3 && strcmp(argv[2], "--cc-adaptive") == 0;
  int mode_argc = matrix_adaptive ? 2 : argc;
  const char *mode = mode_argc == 2 ? argv[1] : NULL;
  if (mode_argc == 2 && strcmp(mode, "--mesh") == 0)
    return run_mesh(true, matrix_adaptive);
  if (mode_argc == 2 && strcmp(mode, "--mesh-split") == 0)
    return run_mesh(false, matrix_adaptive);
  if (mode_argc == 2 && strcmp(mode, "--membership") == 0)
    return run_membership_lifecycle(false, matrix_adaptive);
  if (mode_argc == 2 && strcmp(mode, "--membership6") == 0)
    return run_membership_lifecycle(true, matrix_adaptive);
  if (mode_argc == 2 && strcmp(mode, "--unsubscribe") == 0)
    return run_unsubscribe_lifecycle(false, matrix_adaptive);
  if (mode_argc == 2 && strcmp(mode, "--unsubscribe6") == 0)
    return run_unsubscribe_lifecycle(true, matrix_adaptive);
  bool native_multicast =
      mode_argc == 2 &&
      (strcmp(mode, "--native") == 0 || strcmp(mode, "--native6") == 0 ||
       strcmp(mode, "--join-fallback") == 0 ||
       strcmp(mode, "--ack-fallback") == 0 || strcmp(mode, "--pacing") == 0);
  bool join_fallback = mode_argc == 2 && strcmp(mode, "--join-fallback") == 0;
  bool ack_fallback = mode_argc == 2 && strcmp(mode, "--ack-fallback") == 0;
  bool pacing = mode_argc == 2 && strcmp(mode, "--pacing") == 0;
  bool adaptive_only = mode_argc == 2 && strcmp(mode, "--adaptive") == 0;
  bool adaptive = adaptive_only || matrix_adaptive;
  bool indexed_repair = mode_argc == 2 && strcmp(mode, "--repair-indexed") == 0;
  bool exhausted_repair =
      mode_argc == 2 && strcmp(mode, "--repair-exhaustion") == 0;
  bool control_flood = mode_argc == 2 && strcmp(mode, "--control-flood") == 0;
  bool repair = mode_argc == 2 && (strcmp(mode, "--repair") == 0 ||
                                   indexed_repair || exhausted_repair);
  bool base = mode_argc == 1 || (mode_argc == 2 && strcmp(mode, "--base") == 0);
  bool ipv6 = mode_argc == 2 && strcmp(mode, "--native6") == 0;
  if ((!matrix_adaptive && argc > 2) ||
      (!base && !native_multicast && !adaptive_only && !repair &&
       !control_flood)) {
    fprintf(
        stderr,
        "usage: %s "
        "[--base|--native|--native6|--join-fallback|--ack-fallback|--pacing|"
        "--adaptive|--repair|--repair-indexed|--repair-exhaustion|"
        "--control-flood|--mesh|"
        "--mesh-split|--membership|"
        "--membership6|--unsubscribe|"
        "--unsubscribe6] [--cc-adaptive]\n",
        argv[0]);
    return 1;
  }
  flexicast_test_state_t server_state = {0};
  flexicast_test_state_t client_a_state = {0};
  flexicast_test_state_t client_b_state = {0};
  transport_config_t server_config = {.bind_hosts = {"127.0.0.1"},
                                      .num_bind_hosts = 1,
                                      .port = 10001,
                                      .cert_file = "t/assets/server.crt",
                                      .key_file = "t/assets/server.key",
                                      .allow_insecure_peer = true,
                                      .enable_flexicast = true,
                                      .callback = on_server,
                                      .user_data = &server_state};
  transport_config_t client_a_config = {.bind_hosts = {"127.0.0.1"},
                                        .num_bind_hosts = 1,
                                        .remote_hosts = {"127.0.0.1"},
                                        .num_remote_hosts = 1,
                                        .port = 10001,
                                        .allow_insecure_peer = true,
                                        .enable_flexicast = true,
                                        .callback = on_client,
                                        .user_data = &client_a_state};
  if (ipv6) {
    server_config.bind_hosts[0] = "::1";
    client_a_config.bind_hosts[0] = "::1";
    client_a_config.remote_hosts[0] = "::1";
  }
  if (native_multicast) {
    server_config.flexicast_group = ipv6 ? "ff32::8000:1" : "232.42.42.1";
    server_config.flexicast_group_port = 10002;
    server_config.flexicast_interface = ipv6 ? "::1" : "127.0.0.1";
    client_a_config.flexicast_interface =
        join_fallback ? "192.0.2.99" : "127.0.0.1";
    if (ipv6)
      client_a_config.flexicast_interface = "::1";
  }
  transport_config_t client_b_config = client_a_config;
  client_b_config.user_data = &client_b_state;
  if (ack_fallback) {
    client_b_config.simulated_flexicast_feedback_loss_rate = 100;
    /* Keep this deterministic fallback test short while exercising the same
     * floor-aware membership deadline used by production configurations. */
    server_config.flexicast_cc_minimum_rate = 12000;
  }
  if (repair) {
    client_a_config.simulated_loss_rate = 30;
    client_b_config.simulated_loss_rate = 30;
    if (indexed_repair) {
      client_a_config.repair_mode = TRANSPORT_REPAIR_MODE_INDEXED;
      client_b_config.repair_mode = TRANSPORT_REPAIR_MODE_INDEXED;
    }
  }
  configure_adaptive_controller(&server_config, adaptive);
  if (adaptive_only) {
    server_config.flexicast_cc_startup_rate = 12000;
    server_config.flexicast_cc_minimum_rate = 1000;
    server_config.flexicast_cc_maximum_rate = 16000;
    server_config.flexicast_cc_aggregate_rate_limit = 16000;
  }

  transport_t *server = transport_create(&server_config);
  transport_t *client_a = transport_create(&client_a_config);
  transport_t *client_b = NULL;
  if (!server || !client_a) {
    fprintf(stderr, "failed to create Flexicast transports\n");
    if (client_a)
      transport_destroy(client_a);
    if (server)
      transport_destroy(server);
    return 1;
  }
  server_state.transport = server;
  client_a_state.transport = client_a;

  int retries = 1000;
  while (retries-- > 0 && !client_a_state.connected) {
    drive(server, client_a, NULL);
    usleep(5000);
  }
  if (!client_a_state.connected) {
    fprintf(stderr, "first Flexicast client did not authenticate\n");
    goto Fail;
  }

  client_b = transport_create(&client_b_config);
  if (!client_b) {
    fprintf(stderr, "failed to create second Flexicast client\n");
    goto Fail;
  }
  client_b_state.transport = client_b;
  retries = 1000;
  while (retries-- > 0 && !client_b_state.connected) {
    drive(server, client_a, client_b);
    usleep(5000);
  }
  if (!client_b_state.connected) {
    transport_stats_t connection_stats = {0};
    transport_stats_t b_stats = {0};
    (void)transport_get_stats(server, &connection_stats);
    (void)transport_get_stats(client_b, &b_stats);
    fprintf(stderr,
            "Flexicast clients did not authenticate (server=%d, a=%d, b=%d, "
            "connections=%zu, handshakes=%" PRIu64 ", auth=%zu, "
            "protocol_errors=%" PRIu64 "; b_handshakes=%" PRIu64
            ", b_closed=%" PRIu64 ")\n",
            server_state.connected, client_a_state.connected,
            client_b_state.connected, connection_stats.active_connections,
            connection_stats.protocol_handshakes_completed,
            server_state.auth_requests, connection_stats.protocol_errors,
            b_stats.protocol_handshakes_completed, b_stats.connections_closed);
    goto Fail;
  }

  moq_track_id_t track = {
      .type = repair ? MOQ_TRACK_DATA : MOQ_TRACK_VIDEO,
      .flags =
          repair ? MOQ_TRACK_FLAG_FEC_RATELESS
                 : ((ack_fallback || pacing) ? 0 : MOQ_TRACK_FLAG_FEC_ENABLED)};
  strcpy(track.name, repair ? "shared-repair" : "shared-video");
  if (!transport_subscribe(client_a, track) ||
      !transport_subscribe(client_b, track)) {
    fprintf(stderr, "Flexicast subscriptions failed\n");
    goto Fail;
  }

  transport_stats_t source_stats = {0};
  retries = 300;
  while (retries-- > 0) {
    drive(server, client_a, client_b);
    (void)transport_get_stats(server, &source_stats);
    if (server_state.subscriptions == 2 &&
        source_stats.flexicast_active_flows == 1 &&
        source_stats.flexicast_active_members == (join_fallback ? 0U : 2U))
      break;
    usleep(5000);
  }
  if (source_stats.flexicast_active_flows != 1 ||
      source_stats.flexicast_active_members != (join_fallback ? 0U : 2U)) {
    fprintf(stderr, "subscribers did not join one shared flow\n");
    goto Fail;
  }

  if (repair) {
    static const uint8_t repair_payload[] = "shared repair record";
    for (uint64_t i = 0; i < 40; i++) {
      moq_object_t record = {.track_id = track,
                             .object_id = i,
                             .data = repair_payload,
                             .size = sizeof(repair_payload),
                             .priority = 1};
      if (!transport_publish(server, &record)) {
        fprintf(stderr, "shared repair publication failed\n");
        goto Fail;
      }
    }
    if (exhausted_repair) {
      /* Deterministically exercise the finite-ESI recovery path. The source
       * symbols are still retained, so subsequent rateless deficit requests
       * must cycle systematic symbols instead of abandoning the object. */
      size_t exhausted_objects = 0;
      for (size_t i = 0; i < TRANSPORT_SENT_CACHE_SIZE; i++) {
        sent_object_cache_t *cached = &server->sent_cache.entries[i];
        if (!cached->data)
          continue;
        cached->next_repair_symbol = QLINQ_FEC_MAX_TOTAL_SYMBOLS;
        exhausted_objects++;
      }
      if (exhausted_objects == 0) {
        fprintf(stderr, "rateless exhaustion fixture was not cached\n");
        goto Fail;
      }
    }
    if (!transport_finish_track(server, track)) {
      fprintf(stderr, "shared repair completion failed\n");
      goto Fail;
    }
    retries = 2000;
    while (retries-- > 0 && (client_a_state.objects_received < 10 ||
                             client_b_state.objects_received < 10)) {
      drive(server, client_a, client_b);
      usleep(5000);
    }
    retries = 400;
    while (retries-- > 0) {
      (void)transport_get_stats(server, &source_stats);
      if (source_stats.repair_pending_objects == 0 &&
          source_stats.repair_queued_packets == 0)
        break;
      drive(server, client_a, client_b);
      usleep(5000);
    }
    (void)transport_get_stats(server, &source_stats);
    if (client_a_state.objects_received != 10 ||
        client_b_state.objects_received != 10 ||
        source_stats.repair_multicast_symbols_sent == 0 ||
        (indexed_repair
             ? source_stats.repair_indexed_requests_received == 0 ||
                   source_stats.repair_rateless_requests_received != 0 ||
                   source_stats.repair_rateless_symbols_sent != 0
             : source_stats.repair_rateless_requests_received == 0 ||
                   source_stats.repair_rateless_symbols_sent == 0 ||
                   (exhausted_repair &&
                    source_stats.repair_rateless_exhausted == 0)) ||
        source_stats.repair_batches_emitted == 0 ||
        source_stats.repair_physical_bytes_sent == 0 ||
        source_stats.flexicast_physical_bytes_sent <
            source_stats.repair_physical_bytes_sent ||
        source_stats.repair_pending_objects != 0 ||
        source_stats.repair_queued_packets != 0 ||
        source_stats.repair_oldest_age_ms != 0) {
      fprintf(stderr,
              "shared repair recovery failed (a=%zu, b=%zu, repairs=%" PRIu64
              ", batches=%" PRIu64 ", repair_bytes=%" PRIu64
              ", total_bytes=%" PRIu64 ", pending=%zu, queued=%zu, age=%" PRIu64
              ", indexed_req=%" PRIu64 ", rateless_req=%" PRIu64
              ", rateless_symbols=%" PRIu64 ")\n",
              client_a_state.objects_received, client_b_state.objects_received,
              source_stats.repair_multicast_symbols_sent,
              source_stats.repair_batches_emitted,
              source_stats.repair_physical_bytes_sent,
              source_stats.flexicast_physical_bytes_sent,
              source_stats.repair_pending_objects,
              source_stats.repair_queued_packets,
              source_stats.repair_oldest_age_ms,
              source_stats.repair_indexed_requests_received,
              source_stats.repair_rateless_requests_received,
              source_stats.repair_rateless_symbols_sent);
      goto Fail;
    }
    printf(indexed_repair ? "===FLEXICAST INDEXED REPAIR OK===\n"
           : exhausted_repair
               ? "===FLEXICAST RATELESS EXHAUSTION RECOVERY OK===\n"
               : "===FLEXICAST RATELESS REPAIR OK===\n");
    transport_destroy(client_b);
    transport_destroy(client_a);
    transport_destroy(server);
    return 0;
  }

  static const uint8_t payload[] = "one ciphertext, two subscribers";
  moq_object_t object = {.track_id = track,
                         .group_id = 7,
                         .object_id = 11,
                         .data = payload,
                         .size = sizeof(payload),
                         .is_keyframe = true,
                         .priority = 2};
  if (!transport_publish(server, &object)) {
    fprintf(stderr, "shared publication failed\n");
    goto Fail;
  }
  retries = 300;
  while (retries-- > 0 &&
         (!client_a_state.received || !client_b_state.received)) {
    drive(server, client_a, client_b);
    usleep(5000);
  }
  for (int i = 0; i < 10; i++)
    drive(server, client_a, client_b);
  (void)transport_get_stats(server, &source_stats);
  transport_stats_t client_a_stats = {0}, client_b_stats = {0};
  (void)transport_get_stats(client_a, &client_a_stats);
  (void)transport_get_stats(client_b, &client_b_stats);
  if (!client_a_state.received || !client_b_state.received ||
      client_a_state.payload_size != sizeof(payload) ||
      client_b_state.payload_size != sizeof(payload) ||
      memcmp(client_a_state.payload, payload, sizeof(payload)) != 0 ||
      memcmp(client_b_state.payload, payload, sizeof(payload)) != 0 ||
      (!join_fallback && source_stats.flexicast_packets_sent == 0) ||
      (native_multicast && !join_fallback &&
       source_stats.flexicast_native_packets_sent == 0 &&
       (!ipv6 || source_stats.flexicast_fallbacks == 0)) ||
      (!join_fallback && source_stats.flexicast_rekeys == 0) ||
      (join_fallback && (client_a_stats.flexicast_fallbacks == 0 ||
                         client_b_stats.flexicast_fallbacks == 0)) ||
      (!join_fallback && !ack_fallback &&
       source_stats.flexicast_acks_received < 2) ||
      (ack_fallback && source_stats.flexicast_acks_received < 1)) {
    fprintf(stderr,
            "shared delivery failed (a=%d, b=%d, packets=%" PRIu64
            ", acks=%" PRIu64 ")\n",
            client_a_state.received, client_b_state.received,
            source_stats.flexicast_packets_sent,
            source_stats.flexicast_acks_received);
    goto Fail;
  }
  uint64_t expected_min_rate = adaptive_only ? 1000U : 64U * 1024U;
  uint64_t expected_max_rate = adaptive_only ? 16000U : 256U * 1024U;
  if (adaptive &&
      (source_stats.flexicast_cc_mode != TRANSPORT_FLEXICAST_CC_ADAPTIVE ||
       (!join_fallback &&
        (source_stats.flexicast_cc_rate_bytes_per_second < expected_min_rate ||
         source_stats.flexicast_cc_rate_bytes_per_second > expected_max_rate ||
         source_stats.flexicast_cc_burst_bytes == 0)) ||
       (adaptive_only &&
        source_stats.flexicast_cc_rate_reduction_events != 0))) {
    fprintf(stderr,
            "adaptive controller configuration was not active (mode=%d, "
            "rate=%" PRIu64 ", burst=%" PRIu64 ", growth=%" PRIu64
            ", reductions=%" PRIu64 ")\n",
            source_stats.flexicast_cc_mode,
            source_stats.flexicast_cc_rate_bytes_per_second,
            source_stats.flexicast_cc_burst_bytes,
            source_stats.flexicast_cc_rate_increase_events,
            source_stats.flexicast_cc_rate_reduction_events);
    goto Fail;
  }
  if (!adaptive &&
      source_stats.flexicast_cc_mode != TRANSPORT_FLEXICAST_CC_MULTICAST) {
    fprintf(stderr,
            "zero-config Flexicast did not select multicast (mode=%d)\n",
            source_stats.flexicast_cc_mode);
    goto Fail;
  }
  if (source_stats.flexicast_cc_rate_increase_events !=
          source_stats.flexicast_cc_ack_growth_events +
              source_stats.flexicast_cc_other_growth_events ||
      source_stats.flexicast_cc_rate_reduction_events !=
          source_stats.flexicast_cc_loss_reduction_events +
              source_stats.flexicast_cc_rtt_reduction_events +
              source_stats.flexicast_cc_ecn_reduction_events +
              source_stats.flexicast_cc_timeout_reduction_events +
              source_stats.flexicast_cc_rate_limit_reduction_events +
              source_stats.flexicast_cc_other_reduction_events) {
    fprintf(stderr,
            "Flexicast controller transition telemetry is incomplete\n");
    goto Fail;
  }

  if (ack_fallback) {
    client_a_state.received = false;
    client_b_state.received = false;
    static const uint8_t loss_probe[] = "multicast health probe";
    for (uint64_t i = 0; i < 40; i++) {
      moq_object_t probe = {.track_id = track,
                            .group_id = 8,
                            .object_id = 100 + i,
                            .data = loss_probe,
                            .size = sizeof(loss_probe),
                            .priority = 1};
      if (!transport_publish(server, &probe)) {
        fprintf(stderr, "feedback fallback probe failed\n");
        goto Fail;
      }
      drive(server, client_a, client_b);
    }
    retries = 2000;
    while (retries-- > 0) {
      drive(server, client_a, client_b);
      (void)transport_get_stats(server, &source_stats);
      if (source_stats.flexicast_feedback_fallbacks >= 1 &&
          source_stats.flexicast_active_members == 1)
        break;
      usleep(5000);
    }
    if (source_stats.flexicast_feedback_fallbacks != 1 ||
        source_stats.flexicast_active_members != 1) {
      fprintf(stderr,
              "missing PATH_ACK did not demote one member (fallbacks=%" PRIu64
              ", members=%zu)\n",
              source_stats.flexicast_feedback_fallbacks,
              source_stats.flexicast_active_members);
      goto Fail;
    }

    for (int i = 0; i < 40; i++)
      drive(server, client_a, client_b);
    static const uint8_t fallback_payload[] = "unicast after feedback timeout";
    moq_object_t fallback_object = {.track_id = track,
                                    .group_id = 9,
                                    .object_id = 200,
                                    .data = fallback_payload,
                                    .size = sizeof(fallback_payload),
                                    .priority = 2};
    client_a_state.received = false;
    client_b_state.received = false;
    if (!transport_publish(server, &fallback_object)) {
      fprintf(stderr, "post-timeout publication failed\n");
      goto Fail;
    }
    retries = 300;
    while (retries-- > 0 &&
           (!client_a_state.received || !client_b_state.received)) {
      drive(server, client_a, client_b);
      usleep(5000);
    }
    if (!client_a_state.received || !client_b_state.received ||
        client_a_state.payload_size != sizeof(fallback_payload) ||
        client_b_state.payload_size != sizeof(fallback_payload) ||
        memcmp(client_a_state.payload, fallback_payload,
               sizeof(fallback_payload)) != 0 ||
        memcmp(client_b_state.payload, fallback_payload,
               sizeof(fallback_payload)) != 0) {
      transport_stats_t a_diagnostic = {0}, b_diagnostic = {0};
      (void)transport_get_stats(client_a, &a_diagnostic);
      (void)transport_get_stats(client_b, &b_diagnostic);
      fprintf(
          stderr,
          "post-timeout unicast fallback delivery failed "
          "(a=%d/%zu rx=%" PRIu64 " errors=%" PRIu64 ", b=%d/%zu rx=%" PRIu64
          " errors=%" PRIu64 " conns=%zu closed=%" PRIu64
          ", source_packets=%" PRIu64 " udp=%" PRIu64
          " egress=%zu conns=%zu queued=%zu drops=%" PRIu64 ")\n",
          client_a_state.received, client_a_state.payload_size,
          a_diagnostic.datagrams_received, a_diagnostic.protocol_errors,
          client_b_state.received, client_b_state.payload_size,
          b_diagnostic.datagrams_received, b_diagnostic.protocol_errors,
          b_diagnostic.active_connections, b_diagnostic.connections_closed,
          source_stats.flexicast_packets_sent, source_stats.udp_packets_sent,
          source_stats.egress_current_packets, source_stats.active_connections,
          source_stats.flexicast_queued_packets,
          source_stats.flexicast_pacing_dropped);
      goto Fail;
    }
  }

  if (pacing) {
    static const uint8_t paced_payload[32] = {0x51, 0x4c, 0x49, 0x4e, 0x51};
    size_t accepted = 0;
    bool saw_backpressure = false;
    client_a_state.received = false;
    client_b_state.received = false;
    for (uint64_t i = 0; i < 400; i++) {
      moq_object_t paced = {.track_id = track,
                            .group_id = 10,
                            .object_id = 300 + i,
                            .data = paced_payload,
                            .size = sizeof(paced_payload),
                            .priority = 1};
      if (!transport_publish(server, &paced)) {
        saw_backpressure = true;
        break;
      }
      accepted++;
    }
    (void)transport_get_stats(server, &source_stats);
    if (!saw_backpressure || accepted == 0 ||
        source_stats.flexicast_queued_packets == 0 ||
        source_stats.flexicast_pacing_delays == 0 ||
        source_stats.flexicast_pacing_backpressure == 0 ||
        transport_is_track_ready(server, &track) ||
        source_stats.flexicast_pacing_rate_bytes_per_second == 0) {
      fprintf(stderr,
              "multicast burst bypassed bounds (accepted=%zu, queued=%zu, "
              "delays=%" PRIu64 ", backpressure=%" PRIu64
              ", ready=%d, rate=%" PRIu64 ")\n",
              accepted, source_stats.flexicast_queued_packets,
              source_stats.flexicast_pacing_delays,
              source_stats.flexicast_pacing_backpressure,
              transport_is_track_ready(server, &track),
              source_stats.flexicast_pacing_rate_bytes_per_second);
      goto Fail;
    }
    retries = 600;
    while (retries-- > 0) {
      drive(server, client_a, client_b);
      (void)transport_get_stats(server, &source_stats);
      if (source_stats.flexicast_queued_packets == 0 &&
          client_a_state.received && client_b_state.received)
        break;
      usleep(5000);
    }
    if (source_stats.flexicast_queued_packets != 0 ||
        !client_a_state.received || !client_b_state.received ||
        source_stats.flexicast_paced_packets < accepted + 1U) {
      fprintf(stderr,
              "paced queue did not drain (queued=%zu, paced=%" PRIu64 ")\n",
              source_stats.flexicast_queued_packets,
              source_stats.flexicast_paced_packets);
      goto Fail;
    }
  }

  if (control_flood) {
    transport_flexicast_flow_t *flow =
        transport_flexicast_find_source(server, &track);
    if (!flow || flow->member_count < 2) {
      fprintf(stderr, "control-throttle flow was not established\n");
      goto Fail;
    }
    transport_flexicast_member_t *member = &flow->members[0];
    quicly_flexicast_frame_t frame = {.type = QUICLY_FRAME_TYPE_FC_STATE};
    frame.data.state.flow_id.len = QUICLY_FLEXICAST_FLOW_ID_SIZE;
    quicly_encode64(frame.data.state.flow_id.bytes, flow->flow_id);
    frame.data.state.sequence = flow->key_epoch;
    for (size_t i = 0;
         i < TRANSPORT_FLEXICAST_MEMBER_TRANSITIONS_PER_SECOND + 1U; i++) {
      frame.data.state.action = member->joined ? QUICLY_FLEXICAST_STATE_LEAVE
                                               : QUICLY_FLEXICAST_STATE_JOIN;
      if (!transport_flexicast_receive_quic_frame(server, member->conn,
                                                  &frame)) {
        fprintf(stderr, "control transition was rejected at %zu\n", i);
        goto Fail;
      }
    }
    (void)transport_get_stats(server, &source_stats);
    if (source_stats.flexicast_control_frames_throttled == 0 ||
        member->joined || member->listening) {
      fprintf(stderr,
              "control transition flood was not safely demoted "
              "(throttled=%" PRIu64 ")\n",
              source_stats.flexicast_control_frames_throttled);
      goto Fail;
    }
  }

  printf(ipv6               ? "===FLEXICAST IPV6 MULTICAST OK===\n"
         : pacing           ? "===FLEXICAST PACING OK===\n"
         : adaptive_only    ? "===FLEXICAST ADAPTIVE CC OK===\n"
         : control_flood    ? "===FLEXICAST CONTROL THROTTLE OK===\n"
         : ack_fallback     ? "===FLEXICAST ACK FALLBACK OK===\n"
         : join_fallback    ? "===FLEXICAST JOIN FALLBACK OK===\n"
         : native_multicast ? "===FLEXICAST MULTICAST OK===\n"
                            : "===FLEXICAST TRANSPORT OK===\n");
  transport_destroy(client_b);
  transport_destroy(client_a);
  transport_destroy(server);
  return 0;

Fail:
  if (client_b)
    transport_destroy(client_b);
  transport_destroy(client_a);
  transport_destroy(server);
  return 1;
}
