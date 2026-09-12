#include "portable_sockets.h"
#include "transport.h"

#include <stdio.h>
#include <string.h>

#define CLIENTS 64
static void ignore_event(void *data, const transport_event_t *event) {
  (void)data;
  (void)event;
}

static void ignore_log(void *data, const transport_log_event_t *event) {
  (void)data;
  (void)event;
}

/* A small deterministic socket-policy check plus a live ephemeral-port cohort.
 * Looking only for a random collision would make this regression flaky. */
static unsigned exclusive_port(transport_t *transport, int family) {
  struct pollfd fds[TRANSPORT_MAX_PATHS + 2];
  size_t count =
      transport_get_poll_fds(transport, fds, sizeof(fds) / sizeof(fds[0]));
  for (size_t i = 0; i < count; i++) {
    struct sockaddr_storage address;
    socklen_t length = sizeof(address);
    if (getsockname(fds[i].fd, (struct sockaddr *)&address, &length) ||
        address.ss_family != family)
      continue;
    int reuse = -1;
    length = sizeof(reuse);
    if (getsockopt(fds[i].fd, SOL_SOCKET, SO_REUSEADDR, &reuse, &length) ||
        reuse)
      return 0;
    return family == AF_INET
               ? ntohs(((struct sockaddr_in *)&address)->sin_port)
               : ntohs(((struct sockaddr_in6 *)&address)->sin6_port);
  }
  return 0;
}

static int run_family(const char *host, int family) {
  transport_config_t config = {.bind_hosts = {host},
                               .num_bind_hosts = 1,
                               .port = 19865,
                               .cert_file = "t/assets/server.crt",
                               .key_file = "t/assets/server.key",
                               .allow_insecure_peer = true,
                               .callback = ignore_event,
                               .log_callback = ignore_log,
                               .limits = {.max_connections = CLIENTS}};
  transport_t *listener = NULL, *duplicate = NULL, *clients[CLIENTS] = {0};
  unsigned ports[CLIENTS] = {0};
  int result = 1;
  listener = transport_create(&config);
  if (!listener || exclusive_port(listener, family) != config.port)
    goto Exit;
  duplicate = transport_create(&config);
  if (duplicate)
    goto Exit;
  config.remote_hosts[0] = host;
  config.num_remote_hosts = 1;
  config.limits.max_connections = 1;
  for (size_t i = 0; i < CLIENTS; i++) {
    clients[i] = transport_create(&config);
    if (!clients[i] || !(ports[i] = exclusive_port(clients[i], family)) ||
        ports[i] == config.port)
      goto Exit;
    for (size_t j = 0; j < i; j++)
      if (ports[j] == ports[i])
        goto Exit;
  }
  result = 0;
Exit:
  for (size_t i = 0; i < CLIENTS; i++)
    if (clients[i])
      transport_destroy(clients[i]);
  if (duplicate)
    transport_destroy(duplicate);
  if (listener)
    transport_destroy(listener);
  if (result)
    fprintf(stderr, "exclusive unicast binding failed for %s\n", host);
  return result;
}

static int run_dual_wildcard(void) {
  const char *hosts[] = {"0.0.0.0", "::"};
  for (size_t order = 0; order < 2; order++) {
    transport_config_t config = {.bind_hosts = {hosts[order], hosts[1 - order]},
                                 .num_bind_hosts = 2,
                                 .port = 19866,
                                 .cert_file = "t/assets/server.crt",
                                 .key_file = "t/assets/server.key",
                                 .allow_insecure_peer = true,
                                 .callback = ignore_event,
                                 .log_callback = ignore_log};
    transport_t *listener = transport_create(&config);
    if (!listener)
      return 1;
    bool valid = exclusive_port(listener, AF_INET) == config.port &&
                 exclusive_port(listener, AF_INET6) == config.port;
    transport_destroy(listener);
    if (!valid)
      return 1;
  }
  return 0;
}

int main(void) {
  if (portable_socket_init())
    return 1;
  int result = run_family("127.0.0.1", AF_INET) ||
               run_family("::1", AF_INET6) || run_dual_wildcard();
  portable_socket_cleanup();
  if (!result)
    puts("===UNICAST BIND OWNERSHIP OK===");
  return result;
}
