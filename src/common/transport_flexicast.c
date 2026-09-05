#include "transport_flexicast.h"

#include "portable_sockets.h"
#include "transport_egress.h"
#include "transport_internal.h"
#include "transport_paths.h"
#include "transport_publish.h"
#include "transport_scheduler.h"
#include "transport_stream.h"
#include "transport_subscriptions.h"
#include "transport_tracks.h"

#include "picotls/openssl.h"
#include "quicly/defaults.h"
#include "quicly/sendstate.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <ifaddrs.h>
#include <net/if.h>
#endif

#define FLEXICAST_EXTERNAL_LOAD_SCALE 1000000U

static bool set_multicast_fd_nonblocking(int fd) {
#ifdef _WIN32
  u_long enabled = 1;
  return ioctlsocket(fd, FIONBIO, &enabled) == 0;
#else
  int flags = fcntl(fd, F_GETFL, 0);
  return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

static bool ipv4_is_multicast(const uint8_t *address) {
  uint32_t value;
  memcpy(&value, address, sizeof(value));
  return IN_MULTICAST(ntohl(value));
}

static bool ipv6_is_ssm(const uint8_t *address) {
  uint8_t scope = address[1] & 0x0fU;
  return address[0] == 0xffU && (address[1] & 0xf0U) == 0x30U &&
         address[2] == 0 && address[3] == 0 &&
         (scope == 1 || scope == 2 || scope == 3 || scope == 4 || scope == 5 ||
          scope == 8 || scope == 14);
}

static bool ipv6_is_multicast(const uint8_t *address) {
  struct in6_addr value;
  memcpy(&value, address, sizeof(value));
  return IN6_IS_ADDR_MULTICAST(&value);
}

static bool ipv6_is_unicast_source(const uint8_t *address) {
  struct in6_addr value;
  memcpy(&value, address, sizeof(value));
  return !IN6_IS_ADDR_UNSPECIFIED(&value) && !IN6_IS_ADDR_MULTICAST(&value);
}

static size_t ip_address_size(uint8_t ip_version) {
  return ip_version == 4 ? 4U : ip_version == 6 ? 16U : 0U;
}

static size_t ip_version_slot(uint8_t ip_version) {
  return ip_version == 4 ? 0U : ip_version == 6 ? 1U : SIZE_MAX;
}

static uint32_t find_interface_index(int family, const void *address) {
  if (!address)
    return 0;
#ifndef _WIN32
  struct ifaddrs *addresses = NULL;
  if (getifaddrs(&addresses) != 0)
    return 0;
  uint32_t result = 0;
  for (const struct ifaddrs *item = addresses; item; item = item->ifa_next) {
    if (!item->ifa_addr || item->ifa_addr->sa_family != family)
      continue;
    const void *candidate =
        family == AF_INET
            ? (const void *)&((const struct sockaddr_in *)item->ifa_addr)
                  ->sin_addr
            : (const void *)&((const struct sockaddr_in6 *)item->ifa_addr)
                  ->sin6_addr;
    size_t size =
        family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr);
    if (memcmp(candidate, address, size) == 0) {
      result = if_nametoindex(item->ifa_name);
      break;
    }
  }
  freeifaddrs(addresses);
  return result;
#else
  ifmon_list_t interfaces;
  uint8_t scratchpad[IFMON_SCRATCHPAD_SIZE];
  if (ifmon_list_get(&interfaces, scratchpad, sizeof(scratchpad)) != 0)
    return 0;
  for (int i = 0; i < interfaces.count; i++) {
    for (int a = 0; a < interfaces.ifaces[i].addr_count; a++) {
      const ifmon_addr_t *candidate = &interfaces.ifaces[i].addrs[a];
      if (candidate->family != family)
        continue;
      const void *candidate_address = family == AF_INET
                                          ? (const void *)&candidate->ip.v4
                                          : (const void *)&candidate->ip.v6;
      size_t size =
          family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr);
      if (memcmp(candidate_address, address, size) == 0)
        return interfaces.ifaces[i].index;
    }
  }
  return 0;
#endif
}

static transport_flexicast_flow_t *find_flow(transport_t *t, uint64_t flow_id) {
  if (!t || flow_id == 0)
    return NULL;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (flow->active && flow->flow_id == flow_id)
      return flow;
  }
  return NULL;
}

static transport_flexicast_queued_payload_t *
queue_at(transport_flexicast_queue_t *queue, size_t index) {
  if (!queue || index >= queue->count || !queue->entries)
    return NULL;
  return &queue->entries[(queue->head + index) % queue->capacity];
}

static const transport_flexicast_queued_payload_t *
queue_at_const(const transport_flexicast_queue_t *queue, size_t index) {
  if (!queue || index >= queue->count || !queue->entries)
    return NULL;
  return &queue->entries[(queue->head + index) % queue->capacity];
}

static transport_flexicast_queued_payload_t *
queue_front(transport_flexicast_queue_t *queue) {
  return queue_at(queue, 0);
}

static bool queue_push(transport_flexicast_queue_t *queue,
                       const transport_flexicast_queued_payload_t *payload) {
  if (!queue || !payload || !payload->data || queue->count >= queue->capacity)
    return false;
  if (!queue->entries) {
    queue->entries = calloc(queue->capacity, sizeof(*queue->entries));
    if (!queue->entries)
      return false;
  }
  size_t tail = (queue->head + queue->count) % queue->capacity;
  queue->entries[tail] = *payload;
  queue->count++;
  queue->bytes += payload->size;
  return true;
}

static void queue_pop(transport_flexicast_queue_t *queue) {
  transport_flexicast_queued_payload_t *payload = queue_front(queue);
  if (!payload)
    return;
  queue->bytes -= payload->size;
  free(payload->data);
  memset(payload, 0, sizeof(*payload));
  queue->head = (queue->head + 1U) % queue->capacity;
  queue->count--;
}

static size_t queue_clear(transport_flexicast_queue_t *queue) {
  if (!queue)
    return 0;
  size_t cleared = queue->count;
  while (queue->count != 0)
    queue_pop(queue);
  queue->head = 0;
  return cleared;
}

static void queue_dispose(transport_flexicast_queue_t *queue) {
  if (!queue)
    return;
  (void)queue_clear(queue);
  free(queue->entries);
  memset(queue, 0, sizeof(*queue));
}

static transport_flexicast_flow_t *alloc_flow(transport_t *t) {
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (!flow->active) {
      memset(flow, 0, sizeof(*flow));
      flow->active = true;
      flow->member_capacity = t->flexicast.member_capacity;
      flow->data_queue.capacity = TRANSPORT_FLEXICAST_QUEUE_CAPACITY;
      flow->repair_queue.capacity = TRANSPORT_FLEXICAST_REPAIR_QUEUE_CAPACITY;
      return flow;
    }
  }
  return NULL;
}

static bool retired_flow_epoch(const transport_t *t, uint64_t flow_id,
                               uint32_t *epoch) {
  for (size_t i = 0; i < t->flexicast_retired_flow_count; i++) {
    if (t->flexicast_retired_flow_ids[i] == flow_id) {
      if (epoch)
        *epoch = t->flexicast_retired_flow_epochs[i];
      return true;
    }
  }
  return false;
}

static bool retired_flow_contains(const transport_t *t, uint64_t flow_id) {
  return retired_flow_epoch(t, flow_id, NULL);
}

static void retire_flow_id(transport_t *t, uint64_t flow_id, uint32_t epoch) {
  if (!t)
    return;
  for (size_t i = 0; i < t->flexicast_retired_flow_count; i++) {
    if (t->flexicast_retired_flow_ids[i] != flow_id)
      continue;
    if (epoch > t->flexicast_retired_flow_epochs[i])
      t->flexicast_retired_flow_epochs[i] = epoch;
    return;
  }
  size_t slot = t->flexicast_retired_flow_next;
  t->flexicast_retired_flow_ids[slot] = flow_id;
  t->flexicast_retired_flow_epochs[slot] = epoch;
  t->flexicast_retired_flow_next = (slot + 1U) % TRANSPORT_FLEXICAST_MAX_FLOWS;
  if (t->flexicast_retired_flow_count < TRANSPORT_FLEXICAST_MAX_FLOWS)
    t->flexicast_retired_flow_count++;
}

static size_t clear_flow_repair_queue(transport_flexicast_flow_t *flow) {
  if (!flow)
    return 0;
  size_t cleared = queue_clear(&flow->repair_queue);
  memset(flow->pending_repairs, 0, sizeof(flow->pending_repairs));
  flow->pending_repair_count = 0;
  free(flow->repair_requesters.entries);
  memset(&flow->repair_requesters, 0, sizeof(flow->repair_requesters));
  memset(flow->shadow_observations, 0, sizeof(flow->shadow_observations));
  flow->shadow_observation_count = 0;
  free(flow->shadow_requesters.entries);
  memset(&flow->shadow_requesters, 0, sizeof(flow->shadow_requesters));
  memset(flow->recent_repairs, 0, sizeof(flow->recent_repairs));
  flow->next_recent_repair = 0;
  flow->data_airtime_since_repair = 0;
  flow->repair_priority_available = false;
  flow->cc_interval_repair_bytes = 0;
  flow->cc_external_load_fraction_ppm = 0;
  flow->cc_external_load_interval_started_ms = 0;
  if (flow->cc_external_load_epoch != UINT64_MAX)
    flow->cc_external_load_epoch++;
  return cleared;
}

static size_t clear_flow_queue(transport_flexicast_flow_t *flow) {
  if (!flow)
    return 0;
  size_t cleared = queue_clear(&flow->data_queue);
  cleared += clear_flow_repair_queue(flow);
  flow->cc_interval_physical_bytes = 0;
  return cleared;
}

static void dispose_flow(transport_flexicast_flow_t *flow) {
  if (!flow)
    return;
  (void)clear_flow_queue(flow);
  queue_dispose(&flow->data_queue);
  queue_dispose(&flow->repair_queue);
  quicly_flexicast_flow_free(flow->crypto);
  free(flow->members);
  free(flow->member_map);
  free(flow->repair_requesters.entries);
  free(flow->shadow_requesters.entries);
  memset(flow, 0, sizeof(*flow));
}

static bool create_crypto_with_secret(transport_flexicast_flow_t *flow,
                                      const uint8_t *secret,
                                      uint64_t first_packet_number,
                                      quicly_flexicast_flow_t **crypto) {
  quicly_flexicast_config_t config = {
      .flow_id = flow->flow_id,
      .first_packet_number = first_packet_number,
      .cipher_suite = &ptls_openssl_aes128gcmsha256,
      .crypto_engine = &quicly_default_crypto_engine,
      .crypto_conn = NULL,
      .traffic_secret =
          ptls_iovec_init(secret, TRANSPORT_FLEXICAST_SECRET_SIZE),
      .max_members = flow->source ? flow->member_capacity : 1,
      .cc_type = flow->source ? flow->cc_type : NULL,
      .cc_config = flow->cc_config,
      .ack_delay_msec = flow->ack_delay_msec != 0
                            ? flow->ack_delay_msec
                            : QUICLY_DEFAULT_MAX_ACK_DELAY,
      .now = transport_get_time_ms()};
  return quicly_flexicast_flow_create(crypto, &config) == QUICLY_FLEXICAST_OK;
}

static bool create_crypto(transport_flexicast_flow_t *flow,
                          uint64_t first_packet_number) {
  return create_crypto_with_secret(flow, flow->secret, first_packet_number,
                                   &flow->crypto);
}

bool transport_flexicast_registry_init(transport_flexicast_registry_t *registry,
                                       size_t capacity,
                                       size_t member_capacity) {
  if (!registry || capacity == 0 || capacity > TRANSPORT_FLEXICAST_MAX_FLOWS ||
      member_capacity == 0 ||
      member_capacity > QUICLY_FLEXICAST_HARD_MAX_MEMBERS)
    return false;
  memset(registry, 0, sizeof(*registry));
  registry->flows = calloc(capacity, sizeof(*registry->flows));
  registry->memberships = calloc(capacity, sizeof(*registry->memberships));
  if (!registry->flows || !registry->memberships) {
    free(registry->flows);
    free(registry->memberships);
    memset(registry, 0, sizeof(*registry));
    return false;
  }
  registry->capacity = capacity;
  registry->member_capacity = member_capacity;
  return true;
}

void transport_flexicast_registry_destroy(
    transport_flexicast_registry_t *registry) {
  if (!registry)
    return;
  for (size_t i = 0; i < registry->capacity; i++)
    dispose_flow(&registry->flows[i]);
  free(registry->flows);
  free(registry->memberships);
  memset(registry, 0, sizeof(*registry));
}

bool transport_flexicast_configure(transport_t *t, const char *group,
                                   uint16_t port, const char *interface) {
  if (!t)
    return false;
  if (!t->flexicast_enabled)
    return !group && port == 0 && !interface;

  if (interface) {
    if (inet_pton(AF_INET, interface, &t->flexicast_interface_v4) == 1) {
      t->flexicast_interface_family = AF_INET;
      t->flexicast_interface_index =
          find_interface_index(AF_INET, &t->flexicast_interface_v4);
    } else if (inet_pton(AF_INET6, interface, &t->flexicast_interface_v6) ==
               1) {
      t->flexicast_interface_family = AF_INET6;
      t->flexicast_interface_index =
          find_interface_index(AF_INET6, &t->flexicast_interface_v6);
    } else {
      fprintf(stderr, "transport: invalid Flexicast interface address: %s\n",
              interface);
      return false;
    }
    t->flexicast_interface_set = true;
  }

  if (!group && port == 0)
    return true;
  if (!t->is_server || !group || port == 0 || !interface) {
    fprintf(stderr,
            "transport: native Flexicast sources require group, port, and "
            "interface\n");
    return false;
  }

  int family;
  if (strchr(group, ':')) {
    struct sockaddr_in6 *destination =
        (struct sockaddr_in6 *)&t->flexicast_group_addr;
    destination->sin6_family = AF_INET6;
    destination->sin6_port = htons(port);
    if (inet_pton(AF_INET6, group, &destination->sin6_addr) != 1 ||
        !ipv6_is_ssm(destination->sin6_addr.s6_addr)) {
      fprintf(stderr, "transport: invalid IPv6 SSM group: %s\n", group);
      return false;
    }
    destination->sin6_scope_id = t->flexicast_interface_index;
    t->flexicast_group_addr_len = sizeof(*destination);
    family = AF_INET6;
  } else {
    struct sockaddr_in *destination =
        (struct sockaddr_in *)&t->flexicast_group_addr;
    destination->sin_family = AF_INET;
    destination->sin_port = htons(port);
    if (inet_pton(AF_INET, group, &destination->sin_addr) != 1 ||
        (ntohl(destination->sin_addr.s_addr) & 0xff000000U) != 0xe8000000U) {
      fprintf(stderr, "transport: invalid IPv4 SSM group: %s\n", group);
      return false;
    }
    t->flexicast_group_addr_len = sizeof(*destination);
    family = AF_INET;
  }
  if (family != t->flexicast_interface_family ||
      (family == AF_INET &&
       t->flexicast_interface_v4.s_addr == htonl(INADDR_ANY)) ||
      (family == AF_INET6 &&
       (IN6_IS_ADDR_UNSPECIFIED(&t->flexicast_interface_v6) ||
        IN6_IS_ADDR_MULTICAST(&t->flexicast_interface_v6) ||
        t->flexicast_interface_index == 0))) {
    fprintf(stderr,
            "transport: a native Flexicast source needs a concrete local "
            "interface address matching the group family\n");
    return false;
  }
  bool usable_socket = false;
  for (size_t i = 0; i < t->num_fds; i++) {
    if (t->local_addrs[i].ss_family != family)
      continue;
    bool matches;
    if (family == AF_INET) {
      const struct sockaddr_in *local =
          (const struct sockaddr_in *)&t->local_addrs[i];
      matches = local->sin_addr.s_addr == htonl(INADDR_ANY) ||
                local->sin_addr.s_addr == t->flexicast_interface_v4.s_addr;
    } else {
      const struct sockaddr_in6 *local =
          (const struct sockaddr_in6 *)&t->local_addrs[i];
      matches = IN6_IS_ADDR_UNSPECIFIED(&local->sin6_addr) ||
                memcmp(&local->sin6_addr, &t->flexicast_interface_v6,
                       sizeof(local->sin6_addr)) == 0;
    }
    if (matches) {
      usable_socket = true;
      /* A concrete bind matching the configured multicast interface proves
       * that the ordinary QUIC path and Flexicast share one local physical
       * resource. Wildcard binds remain unknown rather than assuming this. */
      bool concrete =
          family == AF_INET
              ? ((const struct sockaddr_in *)&t->local_addrs[i])
                        ->sin_addr.s_addr != htonl(INADDR_ANY)
              : !IN6_IS_ADDR_UNSPECIFIED(
                    &((const struct sockaddr_in6 *)&t->local_addrs[i])
                         ->sin6_addr);
      if (concrete && t->flexicast_interface_index != 0)
        t->local_ifindices[i] = t->flexicast_interface_index;
      break;
    }
  }
  if (!usable_socket) {
    fprintf(stderr,
            "transport: no UDP socket matching the Flexicast address family "
            "can use the configured interface\n");
    return false;
  }
  t->flexicast_native_source = true;
  return true;
}

static transport_flexicast_membership_t *
find_membership(transport_t *t, uint8_t ip_version, const uint8_t *source,
                const uint8_t *group, uint16_t port, uint32_t interface_index) {
  size_t address_len = ip_address_size(ip_version);
  if (address_len == 0)
    return NULL;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_membership_t *membership = &t->flexicast.memberships[i];
    if (membership->active && membership->ip_version == ip_version &&
        membership->udp_port == port &&
        membership->interface_index == interface_index &&
        memcmp(membership->source_ip, source, address_len) == 0 &&
        memcmp(membership->group_ip, group, address_len) == 0)
      return membership;
  }
  return NULL;
}

static transport_flexicast_membership_t *
allocate_membership(transport_t *t, const uint8_t *source, const uint8_t *group,
                    uint8_t ip_version, uint16_t port,
                    uint32_t interface_index) {
  size_t address_len = ip_address_size(ip_version);
  if (address_len == 0)
    return NULL;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_membership_t *membership = &t->flexicast.memberships[i];
    if (!membership->active) {
      membership->active = true;
      membership->ip_version = ip_version;
      memcpy(membership->source_ip, source, address_len);
      memcpy(membership->group_ip, group, address_len);
      membership->udp_port = port;
      membership->interface_index = interface_index;
      membership->references = 1;
      return membership;
    }
  }
  return NULL;
}

static bool any_memberships(const transport_t *t, uint8_t ip_version) {
  for (size_t i = 0; i < t->flexicast.capacity; i++)
    if (t->flexicast.memberships[i].active &&
        t->flexicast.memberships[i].ip_version == ip_version)
      return true;
  return false;
}

static int change_source_group(transport_t *t, int fd, uint8_t ip_version,
                               const uint8_t *source_ip,
                               const uint8_t *group_ip,
                               uint32_t interface_index, bool join) {
  if (ip_version == 4) {
    struct ip_mreq_source request = {0};
    memcpy(&request.imr_multiaddr, group_ip, 4);
    memcpy(&request.imr_sourceaddr, source_ip, 4);
    request.imr_interface.s_addr =
        t->flexicast_interface_set && t->flexicast_interface_family == AF_INET
            ? t->flexicast_interface_v4.s_addr
            : htonl(INADDR_ANY);
    return setsockopt(fd, IPPROTO_IP,
                      join ? IP_ADD_SOURCE_MEMBERSHIP
                           : IP_DROP_SOURCE_MEMBERSHIP,
                      &request, sizeof(request));
  }
  if (ip_version != 6)
    return -1;
#if defined(MCAST_JOIN_SOURCE_GROUP) || defined(MCAST_LEAVE_SOURCE_GROUP)
  int option;
  if (join) {
#if defined(MCAST_JOIN_SOURCE_GROUP)
    option = MCAST_JOIN_SOURCE_GROUP;
#else
    return -1;
#endif
  } else {
#if defined(MCAST_LEAVE_SOURCE_GROUP)
    option = MCAST_LEAVE_SOURCE_GROUP;
#else
    return -1;
#endif
  }
  struct group_source_req request = {0};
  request.gsr_interface = interface_index;
  struct sockaddr_in6 *group = (struct sockaddr_in6 *)&request.gsr_group;
  struct sockaddr_in6 *source = (struct sockaddr_in6 *)&request.gsr_source;
  group->sin6_family = AF_INET6;
  source->sin6_family = AF_INET6;
  memcpy(&group->sin6_addr, group_ip, 16);
  memcpy(&source->sin6_addr, source_ip, 16);
  return setsockopt(fd, IPPROTO_IPV6, option, &request, sizeof(request));
#else
  (void)t;
  (void)fd;
  (void)source_ip;
  (void)group_ip;
  (void)interface_index;
  (void)join;
  return -1;
#endif
}

static void release_membership(transport_t *t,
                               transport_flexicast_flow_t *flow) {
  if (!t || !flow || !flow->membership_acquired)
    return;
  transport_flexicast_membership_t *membership =
      find_membership(t, flow->ip_version, flow->source_ip, flow->group_ip,
                      flow->udp_port, flow->interface_index);
  flow->membership_acquired = false;
  if (!membership || membership->references == 0)
    return;
  if (--membership->references != 0)
    return;

  size_t slot = ip_version_slot(membership->ip_version);
  int fd = slot != SIZE_MAX ? t->flexicast_fds[slot] : -1;
  int result = fd >= 0 ? change_source_group(
                             t, fd, membership->ip_version,
                             membership->source_ip, membership->group_ip,
                             membership->interface_index, false)
                       : -1;
  if (fd >= 0) {
    if (result != 0)
      fprintf(stderr, "transport: unable to leave Flexicast group: %s\n",
              strerror(SOCKET_ERROR_CODE));
    else
      t->stats.flexicast_membership_leaves++;
  }
  uint8_t ip_version = membership->ip_version;
  memset(membership, 0, sizeof(*membership));
  if (slot != SIZE_MAX && t->flexicast_fds[slot] >= 0 &&
      !any_memberships(t, ip_version)) {
    CLOSE_SOCKET(t->flexicast_fds[slot]);
    t->flexicast_fds[slot] = -1;
    t->flexicast_receive_ports[slot] = 0;
  }
}

static void release_flow(transport_t *t, transport_flexicast_flow_t *flow) {
  release_membership(t, flow);
  dispose_flow(flow);
}

void transport_flexicast_dispose(transport_t *t) {
  if (!t)
    return;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (flow->active)
      release_flow(t, flow);
  }
  transport_flexicast_registry_destroy(&t->flexicast);
}

static int open_receive_socket(uint8_t ip_version, uint16_t port) {
  int family = ip_version == 4 ? AF_INET : AF_INET6;
  int fd = socket(family, SOCK_DGRAM, 0);
  if (fd < 0)
    return -1;
  int reuse = 1;
  int receive_buffer = 2 * 1024 * 1024;
  int v6_only = 1;
  bool configured =
      setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == 0 &&
      setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer,
                 sizeof(receive_buffer)) == 0;
  if (configured && family == AF_INET6)
    configured = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only,
                            sizeof(v6_only)) == 0;
  if (configured && family == AF_INET) {
    struct sockaddr_in bind_address = {.sin_family = AF_INET,
                                       .sin_port = htons(port),
                                       .sin_addr.s_addr = htonl(INADDR_ANY)};
    configured =
        bind(fd, (struct sockaddr *)&bind_address, sizeof(bind_address)) == 0;
  } else if (configured) {
    struct sockaddr_in6 bind_address = {.sin6_family = AF_INET6,
                                        .sin6_port = htons(port),
                                        .sin6_addr = IN6ADDR_ANY_INIT};
    configured =
        bind(fd, (struct sockaddr *)&bind_address, sizeof(bind_address)) == 0;
  }
  if (!configured || !set_multicast_fd_nonblocking(fd)) {
    fprintf(stderr, "transport: unable to open Flexicast receive socket: %s\n",
            strerror(SOCKET_ERROR_CODE));
    CLOSE_SOCKET(fd);
    return -1;
  }
  return fd;
}

static bool
join_announced_group(transport_t *t, transport_flexicast_flow_t *flow,
                     const quicly_flexicast_announce_frame_t *announce) {
  size_t address_len = ip_address_size(announce->ip_version);
  if (address_len == 0 || announce->udp_port == 0)
    return false;
  uint32_t interface_index =
      t->flexicast_interface_set &&
              ((announce->ip_version == 4 &&
                t->flexicast_interface_family == AF_INET) ||
               (announce->ip_version == 6 &&
                t->flexicast_interface_family == AF_INET6))
          ? t->flexicast_interface_index
          : 0;
  if (flow->membership_acquired && flow->ip_version == announce->ip_version &&
      flow->udp_port == announce->udp_port &&
      flow->interface_index == interface_index &&
      memcmp(flow->source_ip, announce->source_ip, address_len) == 0 &&
      memcmp(flow->group_ip, announce->group_ip, address_len) == 0)
    return true;
  release_membership(t, flow);
  flow->ip_version = announce->ip_version;
  flow->interface_index = interface_index;
  memcpy(flow->source_ip, announce->source_ip, address_len);
  memcpy(flow->group_ip, announce->group_ip, address_len);
  flow->udp_port = announce->udp_port;

  bool multicast = announce->ip_version == 4
                       ? ipv4_is_multicast(announce->group_ip)
                       : ipv6_is_multicast(announce->group_ip);
  if (!multicast)
    return true; /* replicated-unicast profile */
  if ((announce->ip_version == 4 && (announce->source_ip[0] == 0 ||
                                     ipv4_is_multicast(announce->source_ip))) ||
      (announce->ip_version == 6 &&
       !ipv6_is_unicast_source(announce->source_ip))) {
    fprintf(stderr, "transport: announced Flexicast source is not unicast\n");
    return false;
  }
  if ((announce->ip_version == 4 && announce->group_ip[0] != 232U) ||
      (announce->ip_version == 6 && !ipv6_is_ssm(announce->group_ip))) {
    fprintf(stderr, "transport: announced group is outside the SSM range\n");
    return false;
  }

  size_t slot = ip_version_slot(announce->ip_version);
  bool created = false;
  if (t->flexicast_fds[slot] < 0) {
    int fd = open_receive_socket(announce->ip_version, announce->udp_port);
    if (fd < 0)
      return false;
    t->flexicast_fds[slot] = fd;
    t->flexicast_receive_ports[slot] = announce->udp_port;
    created = true;
  } else if (t->flexicast_receive_ports[slot] != announce->udp_port) {
    fprintf(stderr,
            "transport: one address family cannot join Flexicast groups on "
            "different UDP ports\n");
    return false;
  }

  transport_flexicast_membership_t *existing =
      find_membership(t, announce->ip_version, announce->source_ip,
                      announce->group_ip, announce->udp_port, interface_index);
  if (!existing) {
    if (change_source_group(t, t->flexicast_fds[slot], announce->ip_version,
                            announce->source_ip, announce->group_ip,
                            interface_index, true) != 0) {
      fprintf(stderr, "transport: unable to join Flexicast group: %s\n",
              strerror(SOCKET_ERROR_CODE));
      if (created) {
        CLOSE_SOCKET(t->flexicast_fds[slot]);
        t->flexicast_fds[slot] = -1;
        t->flexicast_receive_ports[slot] = 0;
      }
      return false;
    }
    t->stats.flexicast_membership_joins++;
    if (!allocate_membership(t, announce->source_ip, announce->group_ip,
                             announce->ip_version, announce->udp_port,
                             interface_index)) {
      (void)change_source_group(t, t->flexicast_fds[slot],
                                announce->ip_version, announce->source_ip,
                                announce->group_ip, interface_index, false);
      return false;
    }
  } else {
    existing->references++;
  }
  flow->membership_acquired = true;
  flow->native_multicast = true;
  return true;
}

#define FLEXICAST_MEMBER_MAP_EMPTY 0U
#define FLEXICAST_MEMBER_MAP_OCCUPIED 1U
#define FLEXICAST_MEMBER_MAP_TOMBSTONE 2U

static uintptr_t member_pointer_hash(const transport_conn_t *conn) {
  uintptr_t value = (uintptr_t)conn;
  value ^= value >> 17;
  value *= (uintptr_t)UINT64_C(0xed5ad4bb);
  return value ^ (value >> 11);
}

static bool member_table_init(transport_flexicast_flow_t *flow) {
  if (flow->members)
    return true;
  size_t map_capacity = 2;
  while (map_capacity < flow->member_capacity * 2U)
    map_capacity *= 2U;
  flow->members = calloc(flow->member_capacity, sizeof(*flow->members));
  flow->member_map = calloc(map_capacity, sizeof(*flow->member_map));
  if (!flow->members || !flow->member_map) {
    free(flow->members);
    free(flow->member_map);
    flow->members = NULL;
    flow->member_map = NULL;
    return false;
  }
  flow->member_map_capacity = map_capacity;
  return true;
}

static bool member_map_find(const transport_flexicast_flow_t *flow,
                            const transport_conn_t *conn, size_t *slot) {
  if (!flow->member_map)
    return false;
  size_t index = member_pointer_hash(conn) & (flow->member_map_capacity - 1U);
  for (size_t probe = 0; probe < flow->member_map_capacity; probe++) {
    const transport_flexicast_member_map_entry_t *entry =
        &flow->member_map[index];
    if (entry->state == FLEXICAST_MEMBER_MAP_EMPTY)
      return false;
    if (entry->state == FLEXICAST_MEMBER_MAP_OCCUPIED && entry->conn == conn) {
      *slot = entry->slot;
      return true;
    }
    index = (index + 1U) & (flow->member_map_capacity - 1U);
  }
  return false;
}

static bool member_map_insert(transport_flexicast_flow_t *flow,
                              const transport_conn_t *conn, size_t slot) {
  size_t index = member_pointer_hash(conn) & (flow->member_map_capacity - 1U);
  size_t tombstone = SIZE_MAX;
  for (size_t probe = 0; probe < flow->member_map_capacity; probe++) {
    transport_flexicast_member_map_entry_t *entry = &flow->member_map[index];
    if (entry->state == FLEXICAST_MEMBER_MAP_OCCUPIED) {
      if (entry->conn == conn)
        return false;
    } else if (entry->state == FLEXICAST_MEMBER_MAP_TOMBSTONE) {
      if (tombstone == SIZE_MAX)
        tombstone = index;
    } else {
      if (tombstone != SIZE_MAX)
        entry = &flow->member_map[tombstone];
      entry->conn = conn;
      entry->slot = slot;
      entry->state = FLEXICAST_MEMBER_MAP_OCCUPIED;
      return true;
    }
    index = (index + 1U) & (flow->member_map_capacity - 1U);
  }
  return false;
}

static void member_map_remove(transport_flexicast_flow_t *flow,
                              const transport_conn_t *conn) {
  size_t index = member_pointer_hash(conn) & (flow->member_map_capacity - 1U);
  while (flow->member_map[index].state != FLEXICAST_MEMBER_MAP_EMPTY) {
    transport_flexicast_member_map_entry_t *entry = &flow->member_map[index];
    if (entry->state == FLEXICAST_MEMBER_MAP_OCCUPIED && entry->conn == conn) {
      memset(entry, 0, sizeof(*entry));
      entry->state = FLEXICAST_MEMBER_MAP_TOMBSTONE;
      return;
    }
    index = (index + 1U) & (flow->member_map_capacity - 1U);
  }
}

static void member_map_update(transport_flexicast_flow_t *flow,
                              const transport_conn_t *conn, size_t slot) {
  size_t existing;
  if (member_map_find(flow, conn, &existing)) {
    size_t index = member_pointer_hash(conn) & (flow->member_map_capacity - 1U);
    while (flow->member_map[index].state != FLEXICAST_MEMBER_MAP_EMPTY) {
      transport_flexicast_member_map_entry_t *entry = &flow->member_map[index];
      if (entry->state == FLEXICAST_MEMBER_MAP_OCCUPIED &&
          entry->conn == conn) {
        entry->slot = slot;
        return;
      }
      index = (index + 1U) & (flow->member_map_capacity - 1U);
    }
  }
}

static transport_flexicast_member_t *
find_member(transport_flexicast_flow_t *flow, const transport_conn_t *conn) {
  size_t slot;
  return flow && conn && member_map_find(flow, conn, &slot)
             ? &flow->members[slot]
             : NULL;
}

static transport_flexicast_member_t *
add_member(transport_flexicast_flow_t *flow, transport_conn_t *conn) {
  transport_flexicast_member_t *member = find_member(flow, conn);
  if (member)
    return member;
  if (!flow || !conn || flow->member_count == flow->member_capacity ||
      !member_table_init(flow) ||
      !member_map_insert(flow, conn, flow->member_count))
    return NULL;
  member = &flow->members[flow->member_count++];
  member->conn = conn;
  return member;
}

static void set_member_listening(transport_flexicast_flow_t *flow,
                                 transport_flexicast_member_t *member,
                                 bool listening, int64_t now) {
  if (member->listening == listening)
    return;
  if (listening) {
    flow->listening_count++;
    member->acknowledged_delivery_epoch = flow->delivery_epoch;
    member->last_ack_time_ms = now;
  } else {
    assert(flow->listening_count != 0);
    if (member->acknowledged_delivery_epoch < flow->delivery_epoch) {
      assert(flow->feedback_outstanding_count != 0);
      flow->feedback_outstanding_count--;
    }
    flow->listening_count--;
    member->acknowledged_delivery_epoch = flow->delivery_epoch;
    member->last_ack_time_ms = 0;
  }
  member->listening = listening;
}

static void advance_delivery_epoch(transport_flexicast_flow_t *flow) {
  if (flow->delivery_epoch != UINT64_MAX) {
    flow->delivery_epoch++;
    flow->feedback_outstanding_count = flow->listening_count;
    return;
  }
  /* This is unreachable at practical packet rates, but preserves comparison
   * semantics without relying on unsigned wraparound. */
  flow->delivery_epoch = 1;
  flow->feedback_outstanding_count = flow->listening_count;
  for (size_t i = 0; i < flow->member_count; i++)
    if (flow->members[i].listening)
      flow->members[i].acknowledged_delivery_epoch = 0;
}

static uint64_t
member_delivery_debt(const transport_flexicast_flow_t *flow,
                     const transport_flexicast_member_t *member) {
  return member->listening &&
                 member->acknowledged_delivery_epoch <= flow->delivery_epoch
             ? flow->delivery_epoch - member->acknowledged_delivery_epoch
             : 0;
}

static uint64_t
feedback_demotion_timeout_ms(const transport_flexicast_flow_t *flow) {
  uint64_t feedback_interval = flow->cc_config.feedback_timeout_msec != 0
                                   ? flow->cc_config.feedback_timeout_msec
                                   : 1000U;
  uint64_t ack_interval = flow->ack_delay_msec != 0
                              ? flow->ack_delay_msec
                              : QUICLY_DEFAULT_MAX_ACK_DELAY;
  uint64_t interval =
      feedback_interval > ack_interval ? feedback_interval : ack_interval;
  uint64_t timeout = interval * TRANSPORT_FLEXICAST_MISSED_FEEDBACK_WINDOWS;

  /* Delivery debt is counted in packets, while the controller paces bytes.
   * At a low rate, producing ACK_PACKET_THRESHOLD packets can itself take
   * longer than the fixed missed-feedback window.  Give the member that
   * serialization interval before declaring its feedback path unhealthy;
   * otherwise a controller reduction can trigger false demotion, rekeying,
   * and a self-sustaining unicast-repair storm. */
  /* Base the health deadline on the slowest rate the controller is allowed
   * to reach. Missing feedback can drive the controller down while this timer
   * is running; using the instantaneous rate would make a fast controller
   * demote members before it has had the same recovery opportunity as one
   * that has already reached its floor. */
  uint64_t rate = flow->cc_config.minimum_rate_bytes_per_second != 0
                      ? flow->cc_config.minimum_rate_bytes_per_second
                      : flow->pacing_rate_bytes_per_second;
  if (rate != 0) {
    uint64_t threshold_bytes =
        (uint64_t)TRANSPORT_FLEXICAST_ACK_PACKET_THRESHOLD *
        flow->cc_config.maximum_datagram_size;
    uint64_t serialization_ms = (threshold_bytes * 1000U + rate - 1U) / rate;
    if (serialization_ms > UINT64_MAX - timeout)
      return UINT64_MAX;
    timeout += serialization_ms;
  }
  return timeout;
}

static void erase_member(transport_flexicast_flow_t *flow,
                         transport_flexicast_member_t *member) {
  size_t slot = (size_t)(member - flow->members);
  size_t last = flow->member_count - 1U;
  if (member->listening) {
    assert(flow->listening_count != 0);
    if (member->acknowledged_delivery_epoch < flow->delivery_epoch) {
      assert(flow->feedback_outstanding_count != 0);
      flow->feedback_outstanding_count--;
    }
    flow->listening_count--;
  }
  member_map_remove(flow, member->conn);
  if (slot != last) {
    flow->members[slot] = flow->members[last];
    member_map_update(flow, flow->members[slot].conn, slot);
  }
  memset(&flow->members[last], 0, sizeof(flow->members[last]));
  flow->member_count--;
}

static bool flow_has_members(const transport_flexicast_flow_t *flow) {
  return flow && flow->member_count != 0;
}

static bool send_control(transport_conn_t *conn, uint8_t type,
                         const uint8_t *payload, size_t payload_len) {
  return conn && conn->stream &&
         quicly_sendstate_is_open(&conn->stream->sendstate) &&
         transport_stream_write_frame(conn->stream, type, payload, payload_len);
}

static quicly_flexicast_flow_id_t flexicast_wire_id(uint64_t flow_id) {
  quicly_flexicast_flow_id_t wire = {.len = QUICLY_FLEXICAST_FLOW_ID_SIZE};
  quicly_encode64(wire.bytes, flow_id);
  return wire;
}

static bool flexicast_host_id(const quicly_flexicast_flow_id_t *wire,
                              uint64_t *flow_id) {
  if (!wire || !flow_id || wire->len != QUICLY_FLEXICAST_FLOW_ID_SIZE)
    return false;
  const uint8_t *src = wire->bytes;
  *flow_id = quicly_decode64(&src);
  return *flow_id > TRANSPORT_MAX_PATHS && *flow_id <= PTLS_QUICINT_MAX;
}

static bool send_state(transport_conn_t *conn, uint64_t flow_id,
                       uint64_t sequence, uint64_t action) {
  quicly_flexicast_state_frame_t frame = {
      .flow_id = flexicast_wire_id(flow_id),
      .sequence = sequence,
      .action = action,
  };
  return quicly_flexicast_send_state(conn->quic, &frame) == QUICLY_FLEXICAST_OK;
}

static bool send_current_key(transport_flexicast_flow_t *flow,
                             transport_flexicast_member_t *member) {
  if (!flow || !member || !member->conn || !member->conn->quic)
    return false;
  quicly_flexicast_key_frame_t key = {
      .flow_id = flexicast_wire_id(flow->flow_id),
      .sequence = flow->key_epoch,
      .first_packet_number =
          quicly_flexicast_get_next_packet_number(flow->crypto),
      .key = ptls_iovec_init(flow->secret, sizeof(flow->secret)),
      .algorithm = PTLS_CIPHER_SUITE_AES_128_GCM_SHA256,
  };
  return quicly_flexicast_send_key(member->conn->quic, &key) ==
         QUICLY_FLEXICAST_OK;
}

static bool send_pending_offer(transport_flexicast_flow_t *flow,
                               transport_flexicast_member_t *member) {
  if (!flow || !member || !member->conn || !member->offer_pending)
    return flow && member && !member->offer_pending;
  if (!member->offer_bind_sent) {
    qlinq_wire_flexicast_bind_t bind = {.alias = flow->alias,
                                        .flow_id = flow->flow_id,
                                        .key_epoch = member->offer_epoch};
    uint8_t bind_buf[QLINQ_WIRE_FLEXICAST_BIND_SIZE];
    if (qlinq_wire_encode_flexicast_bind(bind_buf, sizeof(bind_buf), &bind) !=
            QLINQ_WIRE_OK ||
        !send_control(member->conn, QLINQ_WIRE_FLEXICAST_BIND, bind_buf,
                      sizeof(bind_buf)))
      return false;
    member->offer_bind_sent = true;
  }
  if (quicly_flexicast_send_announce(
          member->conn->quic, &member->offer_announce) != QUICLY_FLEXICAST_OK)
    return false;
  member->offer_pending = false;
  return true;
}

static bool rekey_source_flow(transport_t *t,
                              transport_flexicast_flow_t *flow) {
  if (!t || !flow || !flow->source || !flow->crypto ||
      flow->key_epoch == UINT32_MAX)
    return false;

  uint8_t next_secret[TRANSPORT_FLEXICAST_SECRET_SIZE];
  ptls_openssl_random_bytes(next_secret, sizeof(next_secret));
  uint64_t first_packet_number =
      quicly_flexicast_get_next_packet_number(flow->crypto);
  if (quicly_flexicast_flow_rekey(
          flow->crypto, ptls_iovec_init(next_secret, sizeof(next_secret)),
          first_packet_number,
          transport_get_time_ms()) != QUICLY_FLEXICAST_OK) {
    ptls_clear_memory(next_secret, sizeof(next_secret));
    return false;
  }

  memcpy(flow->secret, next_secret, sizeof(flow->secret));
  ptls_clear_memory(next_secret, sizeof(next_secret));
  flow->key_epoch++;

  for (size_t i = 0; i < flow->member_count; i++) {
    transport_flexicast_member_t *member = &flow->members[i];
    if (!member->conn || !member->joined)
      continue;
    set_member_listening(flow, member, false, 0);
    member->key_pending = !send_current_key(flow, member);
  }
  t->stats.flexicast_rekeys++;
  return true;
}

static void fallback_source_flow(transport_t *t,
                                 transport_flexicast_flow_t *flow) {
  if (!t || !flow || !flow->source)
    return;
  t->stats.flexicast_pacing_dropped += clear_flow_queue(flow);
  for (size_t i = 0; i < flow->member_count; i++) {
    transport_flexicast_member_t *member = &flow->members[i];
    if (!member->conn || (!member->joined && !member->listening))
      continue;
    (void)send_state(member->conn, flow->flow_id, flow->key_epoch,
                     QUICLY_FLEXICAST_STATE_LEAVE);
    (void)quicly_flexicast_detach_at(flow->crypto, member->conn->id,
                                     transport_get_time_ms());
    member->joined = false;
    member->key_pending = false;
    set_member_listening(flow, member, false, 0);
    t->stats.flexicast_fallbacks++;
  }
}

static void schedule_source_rekey(transport_t *t,
                                  transport_flexicast_flow_t *flow,
                                  int64_t now) {
  if (!t || !flow || !flow->active || !flow->source)
    return;
  /* Payloads are queued as plaintext and can safely be protected under the
   * next epoch. Repair intent is cohort-specific, so cancel only repair work;
   * surviving members can re-request it after the batched rekey. */
  t->stats.flexicast_pacing_dropped += clear_flow_repair_queue(flow);
  flow->rekey_pending = true;
  flow->rekey_pending_changes++;
  flow->rekey_ready_at_ms =
      now > INT64_MAX - TRANSPORT_FLEXICAST_REKEY_HOLDOFF_MS
          ? INT64_MAX
          : now + TRANSPORT_FLEXICAST_REKEY_HOLDOFF_MS;
}

static bool maybe_send_join(transport_flexicast_flow_t *flow) {
  if (!flow)
    return false;
  /* A local group-join failure is not a protocol failure. By withholding JOIN,
   * this subscriber stays on qlinq's ordinary per-connection data path. */
  if (flow->multicast_unavailable)
    return true;
  if (flow->source || flow->join_sent || !flow->binding_received ||
      !flow->announcement_received || !flow->control_conn)
    return flow->join_sent;
  if (!send_state(flow->control_conn, flow->flow_id, flow->key_epoch,
                  QUICLY_FLEXICAST_STATE_JOIN))
    return false;
  flow->join_sent = true;
  return true;
}

static transport_flexicast_flow_t *
find_source_cohort(transport_t *t, const moq_track_id_t *track, uint8_t alias) {
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (flow->active && flow->source && flow->alias == alias &&
        transport_track_id_equal(&flow->track_id, track))
      return flow;
  }
  return NULL;
}

bool transport_flexicast_offer(transport_t *t, transport_conn_t *conn,
                               const moq_track_id_t *track, uint8_t alias) {
  if (!t || !conn || !track || !t->flexicast_enabled || !t->is_server ||
      (conn->peer_capabilities & QLINQ_WIRE_CAP_FLEXICAST_DATAGRAM) == 0 ||
      !quicly_flexicast_is_negotiated(conn->quic) ||
      (track->flags & MOQ_TRACK_FLAG_RELIABLE) != 0)
    return false;

  transport_flexicast_flow_t *flow = find_source_cohort(t, track, alias);
  if (!flow) {
    flow = alloc_flow(t);
    if (!flow)
      return false;
    flow->source = true;
    flow->alias = alias;
    flow->key_epoch = 1;
    flow->track_id = *track;
    flow->cc_type = t->flexicast_cc_mode == TRANSPORT_FLEXICAST_CC_ADAPTIVE
                        ? &quicly_flexicast_cc_type_adaptive
                        : &quicly_flexicast_cc_type_multicast;
    flow->cc_config.startup_rate_bytes_per_second =
        t->flexicast_cc_startup_rate != 0
            ? t->flexicast_cc_startup_rate
            : (t->flexicast_cc_mode == TRANSPORT_FLEXICAST_CC_ADAPTIVE
                   ? 1250U
                   : 64U * 1024U);
    flow->cc_config.minimum_rate_bytes_per_second =
        t->flexicast_cc_minimum_rate != 0
            ? t->flexicast_cc_minimum_rate
            : (t->flexicast_cc_mode == TRANSPORT_FLEXICAST_CC_ADAPTIVE
                   ? 250U
                   : 2U * 1024U);
    flow->cc_config.maximum_rate_bytes_per_second =
        t->flexicast_cc_maximum_rate != 0 ? t->flexicast_cc_maximum_rate
                                          : 1024U * 1024U * 1024U;
    flow->cc_config.maximum_datagram_size =
        (uint32_t)t->limits.max_udp_payload_size;
    flow->cc_config.feedback_timeout_msec =
        t->flexicast_cc_feedback_timeout_ms != 0
            ? t->flexicast_cc_feedback_timeout_ms
            : 1000U;
    flow->cc_config.packet_reordering_threshold = 3;
    do {
      ptls_openssl_random_bytes(&flow->flow_id, sizeof(flow->flow_id));
      flow->flow_id &= PTLS_QUICINT_MAX;
    } while (flow->flow_id <= TRANSPORT_MAX_PATHS ||
             find_flow(t, flow->flow_id) != flow);
    ptls_openssl_random_bytes(flow->secret, sizeof(flow->secret));
    if (!create_crypto(flow, 0)) {
      release_flow(t, flow);
      return false;
    }
  }
  if (!add_member(flow, conn))
    return false;
  transport_flexicast_member_t *member = find_member(flow, conn);
  if (!member)
    return false;
  if (member->offer_epoch != 0)
    return true;

  struct sockaddr *peer = quicly_get_peername(conn->quic);
  struct sockaddr *local = quicly_get_sockname(conn->quic);
  if (!peer || !local ||
      (!t->flexicast_native_source && peer->sa_family != local->sa_family)) {
    transport_flexicast_remove_member(t, conn, track);
    return false;
  }
  quicly_flexicast_announce_frame_t fc_announce = {
      .flow_id = flexicast_wire_id(flow->flow_id),
      .sequence = flow->key_epoch,
      .ack_delay_msec = QUICLY_DEFAULT_MAX_ACK_DELAY,
  };
  if (t->flexicast_native_source) {
    if (t->flexicast_group_addr.ss_family == AF_INET) {
      const struct sockaddr_in *group =
          (const struct sockaddr_in *)&t->flexicast_group_addr;
      fc_announce.ip_version = 4;
      memcpy(fc_announce.source_ip, &t->flexicast_interface_v4, 4);
      memcpy(fc_announce.group_ip, &group->sin_addr, 4);
      fc_announce.udp_port = ntohs(group->sin_port);
    } else {
      const struct sockaddr_in6 *group =
          (const struct sockaddr_in6 *)&t->flexicast_group_addr;
      fc_announce.ip_version = 6;
      memcpy(fc_announce.source_ip, &t->flexicast_interface_v6, 16);
      memcpy(fc_announce.group_ip, &group->sin6_addr, 16);
      fc_announce.udp_port = ntohs(group->sin6_port);
    }
    flow->native_multicast = true;
    flow->ip_version = fc_announce.ip_version;
    flow->interface_index = t->flexicast_interface_index;
    size_t address_len = ip_address_size(fc_announce.ip_version);
    memcpy(flow->source_ip, fc_announce.source_ip, address_len);
    memcpy(flow->group_ip, fc_announce.group_ip, address_len);
    flow->udp_port = fc_announce.udp_port;
  } else if (peer->sa_family == AF_INET) {
    const struct sockaddr_in *source = (const struct sockaddr_in *)local;
    const struct sockaddr_in *group = (const struct sockaddr_in *)peer;
    fc_announce.ip_version = 4;
    memcpy(fc_announce.source_ip, &source->sin_addr, 4);
    memcpy(fc_announce.group_ip, &group->sin_addr, 4);
    fc_announce.udp_port = ntohs(group->sin_port);
  } else {
    const struct sockaddr_in6 *source = (const struct sockaddr_in6 *)local;
    const struct sockaddr_in6 *group = (const struct sockaddr_in6 *)peer;
    fc_announce.ip_version = 6;
    memcpy(fc_announce.source_ip, &source->sin6_addr, 16);
    memcpy(fc_announce.group_ip, &group->sin6_addr, 16);
    fc_announce.udp_port = ntohs(group->sin6_port);
  }
  member->offer_pending = true;
  member->offer_epoch = flow->key_epoch;
  member->offer_announce = fc_announce;
  (void)send_pending_offer(flow, member);
  return true;
}

static void remove_source_member(transport_t *t,
                                 transport_flexicast_flow_t *flow,
                                 transport_conn_t *conn) {
  transport_flexicast_member_t *member = find_member(flow, conn);
  if (!member)
    return;
  bool needs_rekey = member->joined || member->listening;
  (void)quicly_flexicast_detach_at(flow->crypto, conn->id,
                                   transport_get_time_ms());
  erase_member(flow, member);
  if (!flow_has_members(flow))
    release_flow(t, flow);
  else if (needs_rekey)
    schedule_source_rekey(t, flow, transport_get_time_ms());
}

void transport_flexicast_remove_member(transport_t *t, transport_conn_t *conn,
                                       const moq_track_id_t *track) {
  if (!t || !conn)
    return;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (!flow->active || !flow->source ||
        (track && !transport_track_id_equal(&flow->track_id, track)))
      continue;
    remove_source_member(t, flow, conn);
  }
}

void transport_flexicast_unsubscribe(transport_t *t, transport_conn_t *conn,
                                     const moq_track_id_t *track) {
  if (!t || !conn || !track)
    return;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (!flow->active || flow->source || flow->control_conn != conn ||
        !transport_track_id_equal(&flow->track_id, track))
      continue;
    if (flow->join_sent)
      (void)send_state(conn, flow->flow_id, flow->key_epoch,
                       QUICLY_FLEXICAST_STATE_LEAVE);
    retire_flow_id(t, flow->flow_id, flow->key_epoch);
    release_flow(t, flow);
  }
}

void transport_flexicast_remove_connection(transport_t *t,
                                           transport_conn_t *conn) {
  if (!t || !conn)
    return;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (!flow->active)
      continue;
    if (flow->source) {
      remove_source_member(t, flow, conn);
    } else if (flow->control_conn == conn) {
      release_flow(t, flow);
    }
  }
}

bool transport_flexicast_receive_bind(transport_t *t, transport_conn_t *conn,
                                      const qlinq_wire_flexicast_bind_t *bind) {
  if (!t || !conn || !bind || !t->flexicast_enabled || t->is_server)
    return false;
  moq_track_id_t track;
  if (transport_subscriptions_find_by_alias(&conn->subscriptions, bind->alias,
                                            &track) != 0 ||
      (track.flags & MOQ_TRACK_FLAG_RELIABLE) != 0)
    return false;
  transport_flexicast_flow_t *flow = find_flow(t, bind->flow_id);
  if (!flow) {
    flow = alloc_flow(t);
    if (!flow)
      return false;
    flow->source = false;
    flow->flow_id = bind->flow_id;
    flow->control_conn = conn;
  } else if (flow->source || flow->control_conn != conn) {
    return false;
  }
  if (flow->binding_received &&
      (flow->key_epoch != bind->key_epoch || flow->alias != bind->alias))
    return false;
  flow->alias = bind->alias;
  flow->key_epoch = bind->key_epoch;
  flow->track_id = track;
  flow->binding_received = true;
  return !flow->announcement_received || maybe_send_join(flow);
}

bool transport_flexicast_receive_path_ack(transport_t *t,
                                          transport_conn_t *conn,
                                          uint64_t flow_id,
                                          const quicly_ack_frame_t *ack) {
  if (!t || !conn || !ack || !t->is_server)
    return false;
  transport_flexicast_flow_t *flow = find_flow(t, flow_id);
  /* Feedback can already be queued on the receiver's unicast path when the
   * source demotes it. The -02 abandoned-flow rule requires that stale state
   * to be ignored rather than turning fallback into a connection failure. */
  if (!flow)
    return true;
  if (!flow->source)
    return false;
  transport_flexicast_member_t *member = find_member(flow, conn);
  if (!member || !member->listening)
    return true;
  size_t num_acked = 0, num_completed = 0;
  size_t num_lost = 0;
  int ret = quicly_flexicast_ack_frame_at(flow->crypto, conn->id, ack,
                                          &num_acked, &num_lost, &num_completed,
                                          transport_get_time_ms());
  (void)num_lost;
  (void)num_completed;
  if (ret != QUICLY_FLEXICAST_OK)
    return false;
  t->stats.flexicast_acks_received += num_acked;
  if (num_acked > 0 && member) {
    if (member_delivery_debt(flow, member) != 0) {
      assert(flow->feedback_outstanding_count != 0);
      flow->feedback_outstanding_count--;
    }
    member->acknowledged_delivery_epoch = flow->delivery_epoch;
    member->last_ack_time_ms = transport_get_time_ms();
  }
  return true;
}

static bool
receive_quic_announce(transport_t *t, transport_conn_t *conn,
                      const quicly_flexicast_announce_frame_t *announce) {
  uint64_t flow_id;
  if (!t || !conn || !announce || t->is_server ||
      !flexicast_host_id(&announce->flow_id, &flow_id) ||
      announce->sequence > UINT32_MAX)
    return false;
  transport_flexicast_flow_t *flow = find_flow(t, flow_id);
  if (!flow) {
    uint32_t retired_epoch = 0;
    if (retired_flow_epoch(t, flow_id, &retired_epoch) &&
        announce->sequence <= retired_epoch)
      return true;
    flow = alloc_flow(t);
    if (!flow)
      return false;
    flow->source = false;
    flow->flow_id = flow_id;
    flow->key_epoch = (uint32_t)announce->sequence;
    flow->control_conn = conn;
  } else if (flow->source || flow->control_conn != conn) {
    return false;
  }
  if (flow->announcement_received && announce->sequence <= flow->key_epoch)
    return true;
  if (flow->binding_received && flow->key_epoch != announce->sequence)
    return false;
  if (!join_announced_group(t, flow, announce)) {
    flow->multicast_unavailable = true;
    t->stats.flexicast_fallbacks++;
  }
  flow->key_epoch = (uint32_t)announce->sequence;
  flow->ack_delay_msec = announce->ack_delay_msec > UINT32_MAX
                             ? UINT32_MAX
                             : (uint32_t)announce->ack_delay_msec;
  flow->announcement_received = true;
  return !flow->binding_received || maybe_send_join(flow);
}

static bool receive_quic_state(transport_t *t, transport_conn_t *conn,
                               const quicly_flexicast_state_frame_t *state) {
  uint64_t flow_id;
  if (!t || !conn || !state || !flexicast_host_id(&state->flow_id, &flow_id) ||
      state->sequence > UINT32_MAX)
    return false;
  transport_flexicast_flow_t *flow = find_flow(t, flow_id);
  if (!flow) {
    /* A qlinq UNSUBSCRIBE can retire the source cohort before its redundant
     * FC_STATE(LEAVE) arrives. Treat that late LEAVE as acknowledgement of an
     * already-abandoned flow, while keeping unknown JOIN/READY strict. */
    return retired_flow_contains(t, flow_id) ||
           (t->is_server && state->action == QUICLY_FLEXICAST_STATE_LEAVE);
  }
  if (state->sequence < flow->key_epoch) {
    /* JOINs and LEAVEs from several subscribers can cross the rekey caused by
     * the first membership change. Silently discarding an authenticated JOIN
     * strands that subscriber, while discarding a concurrent LEAVE retains a
     * departed member. Let source-side membership handling below resolve both;
     * per-member join_sequence rejects a LEAVE that predates a later rejoin.
     * READY still has to name the current key epoch. */
    if (!t->is_server || !flow->source ||
        (state->action != QUICLY_FLEXICAST_STATE_JOIN &&
         state->action != QUICLY_FLEXICAST_STATE_LEAVE))
      return true;
  }
  if (state->sequence > flow->key_epoch)
    return false;
  if (!t->is_server) {
    if (state->action != QUICLY_FLEXICAST_STATE_LEAVE || flow->source ||
        flow->control_conn != conn)
      return false;
    release_flow(t, flow);
    return true;
  }
  if (!flow->source)
    return false;
  transport_flexicast_member_t *member = find_member(flow, conn);
  if (!member)
    return false;
  if (state->action == QUICLY_FLEXICAST_STATE_JOIN) {
    if (member->joined) {
      if (state->sequence > member->join_sequence)
        member->join_sequence = (uint32_t)state->sequence;
      return true;
    }
    member->joined = true;
    member->key_pending = false;
    member->join_sequence = (uint32_t)state->sequence;
    member->recovery_baseline_pending = true;
    /* Debounce concurrent membership changes. No protected payload is drained
     * until one new epoch has been distributed to the complete batch. */
    schedule_source_rekey(t, flow, transport_get_time_ms());
  } else if (state->action == QUICLY_FLEXICAST_STATE_READY) {
    uint8_t alias = 0;
    if (!member->joined)
      return false;
    member->key_pending = false;
    if (!member->listening &&
        quicly_flexicast_attach_at(flow->crypto, conn->id,
                                   transport_get_time_ms()) !=
            QUICLY_FLEXICAST_OK)
      return false;
    set_member_listening(flow, member, true, transport_get_time_ms());
    if (member->recovery_baseline_pending) {
      if (transport_subscriptions_find_alias(&conn->subscriptions,
                                             &flow->track_id, &alias) != 0)
        return false;
      transport_publish_checkpoint_member_added(t, conn, &flow->track_id,
                                                alias);
      member->recovery_baseline_pending = false;
    }
  } else if (state->action == QUICLY_FLEXICAST_STATE_LEAVE) {
    uint8_t alias = 0;
    if (state->sequence < member->join_sequence)
      return true;
    bool needs_rekey = member->joined || member->listening;
    (void)quicly_flexicast_detach_at(flow->crypto, conn->id,
                                     transport_get_time_ms());
    member->joined = false;
    member->key_pending = false;
    member->recovery_baseline_pending = false;
    set_member_listening(flow, member, false, 0);
    if (transport_subscriptions_find_alias(&conn->subscriptions,
                                           &flow->track_id, &alias) == 0)
      transport_publish_checkpoint_member_removed(t, conn, &flow->track_id,
                                                  alias);
    if (needs_rekey)
      schedule_source_rekey(t, flow, transport_get_time_ms());
  } else {
    return false;
  }
  return true;
}

static bool receive_quic_key(transport_t *t, transport_conn_t *conn,
                             const quicly_flexicast_key_frame_t *key) {
  uint64_t flow_id;
  if (!t || !conn || !key || t->is_server ||
      !flexicast_host_id(&key->flow_id, &flow_id) ||
      key->sequence > UINT32_MAX ||
      key->algorithm != PTLS_CIPHER_SUITE_AES_128_GCM_SHA256 ||
      key->key.len != TRANSPORT_FLEXICAST_SECRET_SIZE)
    return false;
  transport_flexicast_flow_t *flow = find_flow(t, flow_id);
  if (!flow)
    return retired_flow_contains(t, flow_id);
  if (flow->source || flow->control_conn != conn || !flow->join_sent)
    return false;
  if (key->sequence < flow->key_epoch)
    return true;
  if (key->sequence == flow->key_epoch && flow->crypto) {
    if (memcmp(flow->secret, key->key.base, sizeof(flow->secret)) != 0)
      return false;
  } else {
    if (flow->crypto)
      (void)quicly_flexicast_send_pending_ack(flow->crypto,
                                              flow->control_conn->quic,
                                              transport_get_time_ms(), true);
    if (flow->crypto) {
      if (quicly_flexicast_flow_rekey(
              flow->crypto, key->key, key->first_packet_number,
              transport_get_time_ms()) != QUICLY_FLEXICAST_OK)
        return false;
    } else if (!create_crypto_with_secret(flow, key->key.base,
                                          key->first_packet_number,
                                          &flow->crypto)) {
      return false;
    }
    memcpy(flow->secret, key->key.base, sizeof(flow->secret));
    flow->key_epoch = (uint32_t)key->sequence;
  }
  return send_state(conn, flow->flow_id, flow->key_epoch,
                    QUICLY_FLEXICAST_STATE_READY);
}

bool transport_flexicast_receive_quic_frame(
    transport_t *t, transport_conn_t *conn,
    const quicly_flexicast_frame_t *frame) {
  if (!t || !conn || !frame || !t->flexicast_enabled ||
      !quicly_flexicast_is_negotiated(conn->quic))
    return false;
  switch (frame->type) {
  case QUICLY_FRAME_TYPE_FC_ANNOUNCE:
    return receive_quic_announce(t, conn, &frame->data.announce);
  case QUICLY_FRAME_TYPE_FC_STATE:
    return receive_quic_state(t, conn, &frame->data.state);
  case QUICLY_FRAME_TYPE_FC_KEY:
    return receive_quic_key(t, conn, &frame->data.key);
  default:
    return false;
  }
}

bool transport_flexicast_receive_packet(transport_t *t, uint8_t *packet,
                                        size_t packet_size,
                                        transport_conn_t **source_conn,
                                        ptls_iovec_t *payload) {
  if (!t || !packet || !source_conn || !payload || packet_size < 9 ||
      !t->flexicast_enabled)
    return false;
  const uint8_t *flow_at = packet + 1;
  uint64_t flow_id = quicly_decode64(&flow_at);
  transport_flexicast_flow_t *flow = find_flow(t, flow_id);
  if (!flow || flow->source || !flow->crypto)
    return false;
  *source_conn = flow->control_conn;
  *payload = ptls_iovec_init(NULL, 0);
  uint64_t packet_number = 0;
  int64_t now = transport_get_time_ms();
  if (quicly_flexicast_receive_datagram_at(flow->crypto, packet, packet_size,
                                           payload, &packet_number,
                                           now) == QUICLY_FLEXICAST_OK) {
    t->stats.flexicast_packets_received++;
    if (quicly_flexicast_ack_is_due(flow->crypto, now) &&
        !(t->simulated_flexicast_feedback_loss_rate > 0 &&
          (rand() % 100) < t->simulated_flexicast_feedback_loss_rate))
      (void)quicly_flexicast_send_pending_ack(
          flow->crypto, flow->control_conn->quic, now, false);
  }
  return true;
}

bool transport_flexicast_send_ack(transport_flexicast_flow_t *flow,
                                  uint64_t packet_number) {
  if (!flow || flow->source || !flow->control_conn)
    return false;
  return quicly_flexicast_send_path_ack(flow->control_conn->quic, flow->flow_id,
                                        packet_number) == QUICLY_FLEXICAST_OK;
}

transport_flexicast_flow_t *
transport_flexicast_find_source(transport_t *t, const moq_track_id_t *track) {
  if (!t || !track)
    return NULL;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (flow->active && flow->source &&
        transport_track_id_equal(&flow->track_id, track) &&
        transport_flexicast_listening_members(flow) != 0)
      return flow;
  }
  return NULL;
}

transport_flexicast_flow_t *transport_flexicast_find_source_member(
    transport_t *t, const moq_track_id_t *track, const transport_conn_t *conn) {
  if (!t || !track || !conn)
    return NULL;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    transport_flexicast_member_t *member;
    if (!flow->active || !flow->source ||
        !transport_track_id_equal(&flow->track_id, track) ||
        !(member = find_member(flow, conn)) || !member->listening)
      continue;
    return flow;
  }
  return NULL;
}

size_t
transport_flexicast_listening_members(const transport_flexicast_flow_t *flow) {
  return flow ? flow->listening_count : 0;
}

bool transport_flexicast_member_is_listening(
    const transport_flexicast_flow_t *flow, const transport_conn_t *conn) {
  if (!flow || !conn)
    return false;
  size_t slot;
  return member_map_find(flow, conn, &slot) && flow->members[slot].listening;
}

static size_t socket_for_peer(const transport_t *t,
                              const struct sockaddr *peer) {
  for (size_t i = 0; i < t->num_fds; i++)
    if (t->local_addrs[i].ss_family == peer->sa_family)
      return i;
  return SIZE_MAX;
}

static uint64_t member_delivery_rate(const transport_flexicast_member_t *member,
                                     size_t packet_size) {
  if (!member || !member->conn || !member->conn->quic)
    return 0;
  quicly_stats_t stats;
  if (quicly_get_stats(member->conn->quic, &stats) != 0)
    return 0;
  uint64_t rate = stats.delivery_rate.smoothed != 0
                      ? stats.delivery_rate.smoothed
                      : stats.delivery_rate.latest;
  if (rate == 0) {
    uint64_t rtt = stats.rtt.smoothed != 0 ? stats.rtt.smoothed : 100;
    uint64_t cwnd = stats.cc.cwnd >= packet_size ? stats.cc.cwnd : packet_size;
    rate = cwnd > UINT64_MAX / 1000U ? UINT64_MAX : cwnd * 1000U / rtt;
  }
  return rate;
}

static size_t repair_symbol_count(const uint64_t *symbols);

static size_t pending_repair_symbol_count(
    const transport_flexicast_pending_repair_t *pending) {
  return pending->mode == TRANSPORT_REPAIR_MODE_RATELESS
             ? pending->requested_dof
             : repair_symbol_count(pending->requested_symbols);
}

static uint64_t saturating_add_u64(uint64_t left, uint64_t right) {
  return right > UINT64_MAX - left ? UINT64_MAX : left + right;
}

static void account_controller_airtime(transport_flexicast_flow_t *flow,
                                       uint64_t bytes, bool repair) {
  flow->cc_interval_physical_bytes =
      saturating_add_u64(flow->cc_interval_physical_bytes, bytes);
  if (repair)
    flow->cc_interval_repair_bytes =
        saturating_add_u64(flow->cc_interval_repair_bytes, bytes);
}

static void update_external_load_hint(const transport_t *t,
                                      transport_flexicast_flow_t *flow,
                                      quicly_flexicast_cc_hints_t *hints,
                                      int64_t now) {
  uint64_t interval = t->flexicast_cc_feedback_timeout_ms != 0
                          ? t->flexicast_cc_feedback_timeout_ms
                          : 1000U;
  if (flow->cc_external_load_interval_started_ms == 0) {
    flow->cc_external_load_interval_started_ms = now;
    if (flow->cc_external_load_epoch == 0)
      flow->cc_external_load_epoch = 1;
  } else if (now > flow->cc_external_load_interval_started_ms &&
             (uint64_t)(now - flow->cc_external_load_interval_started_ms) >=
                 interval) {
    flow->cc_external_load_fraction_ppm =
        flow->cc_interval_physical_bytes == 0
            ? 0
            : (uint32_t)((flow->cc_interval_repair_bytes >
                                  UINT64_MAX / FLEXICAST_EXTERNAL_LOAD_SCALE
                              ? UINT64_MAX
                              : flow->cc_interval_repair_bytes *
                                    FLEXICAST_EXTERNAL_LOAD_SCALE) /
                         flow->cc_interval_physical_bytes);
    flow->cc_interval_physical_bytes = 0;
    flow->cc_interval_repair_bytes = 0;
    flow->cc_external_load_interval_started_ms = now;
    if (flow->cc_external_load_epoch != UINT64_MAX)
      flow->cc_external_load_epoch++;
  }

  uint64_t queued = flow->repair_queue.bytes;
  uint64_t oldest = 0;
  size_t packet_size = t->limits.max_udp_payload_size;
  for (size_t i = 0; i < TRANSPORT_FLEXICAST_PENDING_REPAIRS; i++) {
    const transport_flexicast_pending_repair_t *pending =
        &flow->pending_repairs[i];
    if (!pending->active)
      continue;
    size_t symbols = pending_repair_symbol_count(pending);
    uint64_t bytes = symbols > UINT64_MAX / packet_size
                         ? UINT64_MAX
                         : (uint64_t)symbols * packet_size;
    queued = saturating_add_u64(queued, bytes);
    if (pending->first_request_ms > 0 && now > pending->first_request_ms &&
        (uint64_t)(now - pending->first_request_ms) > oldest)
      oldest = (uint64_t)(now - pending->first_request_ms);
  }
  for (size_t i = 0; i < flow->repair_queue.count; i++) {
    const transport_flexicast_queued_payload_t *queued =
        queue_at_const(&flow->repair_queue, i);
    int64_t enqueued = queued->enqueued_at_ms;
    if (enqueued > 0 && now > enqueued && (uint64_t)(now - enqueued) > oldest)
      oldest = (uint64_t)(now - enqueued);
  }
  hints->external_load_epoch = flow->cc_external_load_epoch;
  hints->external_load_queued_bytes = queued;
  hints->external_load_oldest_age_msec = oldest;
  hints->external_load_fraction_ppm = flow->cc_external_load_fraction_ppm;
}

static void update_controller_hints(transport_t *t,
                                    transport_flexicast_flow_t *flow,
                                    int64_t now) {
  quicly_flexicast_cc_hints_t hints = {0};
  uint64_t rates[TRANSPORT_FLEXICAST_MAX_FLOWS];
  size_t count = 0;
  int64_t active_window =
      2 * (int64_t)(t->flexicast_cc_feedback_timeout_ms != 0
                        ? t->flexicast_cc_feedback_timeout_ms
                        : 1000U);
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *candidate = &t->flexicast.flows[i];
    if (!candidate->active || !candidate->source || !candidate->crypto ||
        transport_flexicast_listening_members(candidate) == 0 ||
        (candidate != flow && candidate->data_queue.count == 0 &&
         candidate->repair_queue.count == 0 &&
         candidate->pending_repair_count == 0 &&
         (candidate->last_payload_sent_ms == 0 ||
          now - candidate->last_payload_sent_ms > active_window)))
      continue;
    quicly_flexicast_cc_output_t output;
    quicly_flexicast_cc_get_flow_output(candidate->crypto, &output);
    rates[count++] = output.rate_bytes_per_second;
  }
  if (count == 0) {
    quicly_flexicast_cc_output_t output;
    quicly_flexicast_cc_get_flow_output(flow->crypto, &output);
    rates[0] = output.rate_bytes_per_second;
    count = 1;
  }
  for (size_t i = 1; i < count; i++) {
    uint64_t value = rates[i];
    size_t j = i;
    while (j > 0 && rates[j - 1] > value) {
      rates[j] = rates[j - 1];
      j--;
    }
    rates[j] = value;
  }
  hints.active_senders = (uint32_t)count;
  hints.median_sender_rate_bytes_per_second = rates[count / 2];
  if (t->flexicast_cc_aggregate_rate_limit != 0)
    hints.aggregate_rate_limit_bytes_per_second =
        t->flexicast_cc_aggregate_rate_limit / count;
  update_external_load_hint(t, flow, &hints, now);
  quicly_flexicast_cc_set_flow_hints(flow->crypto, &hints, now);
}

static void refresh_pacer(transport_t *t, transport_flexicast_flow_t *flow,
                          int64_t now) {
  update_controller_hints(t, flow, now);
  quicly_flexicast_cc_output_t cc_output;
  quicly_flexicast_cc_get_flow_output(flow->crypto, &cc_output);
  if (flow->listening_count == 0)
    return;
  uint64_t rate = cc_output.rate_bytes_per_second;
  uint64_t burst = cc_output.burst_bytes;
  if (rate == 0) {
    uint64_t slowest = UINT64_MAX;
    for (size_t i = 0; i < flow->member_count; i++) {
      transport_flexicast_member_t *member = &flow->members[i];
      if (!member->conn || !member->listening)
        continue;
      uint64_t member_rate =
          member_delivery_rate(member, t->limits.max_udp_payload_size);
      if (member_rate != 0 && member_rate < slowest)
        slowest = member_rate;
    }
    if (slowest == UINT64_MAX)
      slowest = 64U * 1024U;
    /* Compatibility fallback for flows created without a controller. */
    rate = slowest * 4U / 5U;
  }
  if (burst == 0)
    burst = rate / 20U;
  uint64_t minimum_burst = t->limits.max_udp_payload_size * 4U;
  if (burst < minimum_burst)
    burst = minimum_burst;
  uint64_t maximum_burst = t->limits.max_udp_payload_size * 10U;
  if (burst > maximum_burst)
    burst = maximum_burst;

  if (flow->pacing_last_refill_ms == 0) {
    flow->pacing_tokens = burst;
    flow->pacing_last_refill_ms = now;
  } else if (now > flow->pacing_last_refill_ms) {
    uint64_t elapsed = (uint64_t)(now - flow->pacing_last_refill_ms);
    if (elapsed > 60000U)
      elapsed = 60000U;
    uint64_t numerator = elapsed * rate + flow->pacing_remainder;
    uint64_t added = numerator / 1000U;
    flow->pacing_remainder = numerator % 1000U;
    flow->pacing_tokens =
        added >= burst -
                     (flow->pacing_tokens < burst ? flow->pacing_tokens : burst)
            ? burst
            : flow->pacing_tokens + added;
    flow->pacing_last_refill_ms = now;
  }
  flow->pacing_rate_bytes_per_second = rate;
  flow->pacing_burst_bytes = burst;
  if (flow->pacing_tokens > burst)
    flow->pacing_tokens = burst;
}

static size_t pacing_cost(const transport_flexicast_flow_t *flow,
                          size_t packet_size) {
  if (flow->native_multicast)
    return packet_size;
  size_t members = transport_flexicast_listening_members(flow);
  return members != 0 && packet_size <= SIZE_MAX / members
             ? packet_size * members
             : SIZE_MAX;
}

typedef enum {
  FLEXICAST_DISPATCH_OK,
  FLEXICAST_DISPATCH_BLOCKED,
  FLEXICAST_DISPATCH_FAILED,
} flexicast_dispatch_result_t;

static flexicast_dispatch_result_t
dispatch_payload(transport_t *t, transport_flexicast_flow_t *flow,
                 ptls_iovec_t payload) {
  size_t capacity = payload.len + 128U;
  uint8_t *packet = malloc(capacity);
  if (!packet)
    return FLEXICAST_DISPATCH_FAILED;
  size_t packet_size = 0;
  uint64_t packet_number = 0;
  int send_result = quicly_flexicast_send_datagram_at(
      flow->crypto, payload, packet, capacity, &packet_size, &packet_number,
      transport_get_time_ms());
  if (send_result != QUICLY_FLEXICAST_OK) {
    free(packet);
    return send_result == QUICLY_FLEXICAST_ERROR_SEND_WINDOW
               ? FLEXICAST_DISPATCH_BLOCKED
               : FLEXICAST_DISPATCH_FAILED;
  }

  bool sent_any = false;
  struct iovec vec = {.iov_base = packet, .iov_len = packet_size};
  if (flow->native_multicast && t->flexicast_native_source) {
    struct sockaddr *group = (struct sockaddr *)&t->flexicast_group_addr;
    size_t fd_index = socket_for_peer(t, group);
    int interface_result = -1;
    if (fd_index != SIZE_MAX && group->sa_family == AF_INET)
      interface_result = setsockopt(t->fds[fd_index], IPPROTO_IP,
                                    IP_MULTICAST_IF, &t->flexicast_interface_v4,
                                    sizeof(t->flexicast_interface_v4));
    else if (fd_index != SIZE_MAX && group->sa_family == AF_INET6) {
      int loopback = 1;
      interface_result = setsockopt(
          t->fds[fd_index], IPPROTO_IPV6, IPV6_MULTICAST_IF,
          &t->flexicast_interface_index, sizeof(t->flexicast_interface_index));
      if (interface_result == 0)
        interface_result =
            setsockopt(t->fds[fd_index], IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                       &loopback, sizeof(loopback));
    }
    if (fd_index != SIZE_MAX && interface_result == 0 &&
        transport_egress_submit(&t->egress[fd_index], t->fds[fd_index], group,
                                t->flexicast_group_addr_len, &vec, 1)) {
      advance_delivery_epoch(flow);
      t->stats.flexicast_packets_sent++;
      t->stats.flexicast_native_packets_sent++;
      flow->last_payload_sent_ms = transport_get_time_ms();
      free(packet);
      return FLEXICAST_DISPATCH_OK;
    }
    /* Queueing or interface selection failed locally. The exact same protected
     * packet can still be sent to every member's unicast endpoint. */
    t->stats.flexicast_fallbacks++;
  }
  for (size_t i = 0; i < flow->member_count; i++) {
    transport_flexicast_member_t *member = &flow->members[i];
    if (!member->conn || !member->listening || !member->conn->quic)
      continue;
    struct sockaddr *peer = quicly_get_peername(member->conn->quic);
    size_t fd_index = peer ? socket_for_peer(t, peer) : SIZE_MAX;
    if (fd_index != SIZE_MAX &&
        transport_egress_submit(&t->egress[fd_index], t->fds[fd_index], peer,
                                quicly_get_socklen(peer), &vec, 1)) {
      sent_any = true;
      continue;
    }
    int complete = 0;
    (void)quicly_flexicast_abandon_datagram(flow->crypto, member->conn->id,
                                            packet_number, &complete);
    (void)quicly_flexicast_detach_at(flow->crypto, member->conn->id,
                                     transport_get_time_ms());
    set_member_listening(flow, member, false, 0);
    t->stats.flexicast_fallbacks++;
  }
  if (sent_any) {
    advance_delivery_epoch(flow);
    t->stats.flexicast_packets_sent++;
    flow->last_payload_sent_ms = transport_get_time_ms();
  }
  free(packet);
  return sent_any ? FLEXICAST_DISPATCH_OK : FLEXICAST_DISPATCH_FAILED;
}

bool transport_flexicast_can_queue(const transport_t *t,
                                   const transport_flexicast_flow_t *flow,
                                   size_t packets, size_t bytes) {
  if (!t || !flow || packets > TRANSPORT_FLEXICAST_QUEUE_CAPACITY ||
      packets > TRANSPORT_FLEXICAST_QUEUE_CAPACITY - flow->data_queue.count ||
      bytes > t->limits.max_egress_bytes_per_socket ||
      flow->repair_queue.bytes >
          t->limits.max_egress_bytes_per_socket - flow->data_queue.bytes ||
      bytes > t->limits.max_egress_bytes_per_socket - flow->data_queue.bytes -
                  flow->repair_queue.bytes)
    return false;
  return true;
}

static bool queue_payload(transport_t *t, transport_flexicast_flow_t *flow,
                          ptls_iovec_t payload) {
  if (!transport_flexicast_can_queue(t, flow, 1, payload.len)) {
    t->stats.flexicast_pacing_backpressure++;
    return false;
  }
  uint8_t *copy = malloc(payload.len);
  if (!copy)
    return false;
  memcpy(copy, payload.base, payload.len);
  transport_flexicast_queued_payload_t queued = {.data = copy,
                                                 .size = payload.len,
                                                 .enqueued_at_ms =
                                                     transport_get_time_ms()};
  if (!queue_push(&flow->data_queue, &queued)) {
    free(copy);
    return false;
  }
  t->stats.flexicast_pacing_delays++;
  return true;
}

static bool repair_queue_can_accept(const transport_t *t,
                                    const transport_flexicast_flow_t *flow,
                                    size_t packets, size_t bytes) {
  if (!t || !flow || packets > TRANSPORT_FLEXICAST_REPAIR_QUEUE_CAPACITY ||
      packets > TRANSPORT_FLEXICAST_REPAIR_QUEUE_CAPACITY -
                    flow->repair_queue.count ||
      bytes > t->limits.max_egress_bytes_per_socket ||
      flow->data_queue.bytes >
          t->limits.max_egress_bytes_per_socket - flow->repair_queue.bytes ||
      bytes > t->limits.max_egress_bytes_per_socket - flow->data_queue.bytes -
                  flow->repair_queue.bytes)
    return false;
  return true;
}

static bool queue_repair_payload(transport_t *t,
                                 transport_flexicast_flow_t *flow,
                                 ptls_iovec_t payload, uint64_t group_id,
                                 uint64_t object_id, uint16_t symbol_index,
                                 transport_repair_mode_t mode, int64_t now) {
  if (!repair_queue_can_accept(t, flow, 1, payload.len))
    return false;
  uint8_t *copy = malloc(payload.len);
  if (!copy)
    return false;
  memcpy(copy, payload.base, payload.len);
  bool was_empty = flow->repair_queue.count == 0;
  transport_flexicast_queued_payload_t queued = {.data = copy,
                                                 .size = payload.len,
                                                 .enqueued_at_ms = now,
                                                 .group_id = group_id,
                                                 .object_id = object_id,
                                                 .symbol_index = symbol_index,
                                                 .repair_mode = mode};
  if (!queue_push(&flow->repair_queue, &queued)) {
    free(copy);
    return false;
  }
  if (was_empty && (flow->last_repair_sent_ms == 0 ||
                    now - flow->last_repair_sent_ms >=
                        TRANSPORT_FLEXICAST_REPAIR_PRIORITY_IDLE_MS))
    flow->repair_priority_available = true;
  t->stats.flexicast_pacing_delays++;
  return true;
}

static transport_flexicast_pending_repair_t *
find_pending_repair(transport_flexicast_flow_t *flow, uint64_t group_id,
                    uint64_t object_id, transport_repair_mode_t mode) {
  for (size_t i = 0; i < TRANSPORT_FLEXICAST_PENDING_REPAIRS; i++) {
    transport_flexicast_pending_repair_t *pending = &flow->pending_repairs[i];
    if (pending->active && pending->group_id == group_id &&
        pending->object_id == object_id && pending->mode == mode)
      return pending;
  }
  return NULL;
}

static transport_flexicast_repair_requester_t *
requester_store_find(transport_flexicast_requester_store_t *store,
                     uint64_t request_id, uint64_t member_id) {
  for (size_t i = 0; i < store->count; i++) {
    transport_flexicast_repair_requester_t *requester = &store->entries[i];
    if (requester->request_id == request_id &&
        requester->member_id == member_id)
      return requester;
  }
  return NULL;
}

static transport_flexicast_repair_requester_t *
requester_store_append(transport_flexicast_requester_store_t *store) {
  if (store->count < store->capacity)
    return &store->entries[store->count++];
  if (store->capacity >= TRANSPORT_FLEXICAST_REPAIR_REQUESTERS)
    return NULL;
  size_t capacity = store->capacity == 0 ? 16U : store->capacity * 2U;
  if (capacity > TRANSPORT_FLEXICAST_REPAIR_REQUESTERS)
    capacity = TRANSPORT_FLEXICAST_REPAIR_REQUESTERS;
  transport_flexicast_repair_requester_t *requesters =
      realloc(store->entries, capacity * sizeof(*requesters));
  if (!requesters)
    return NULL;
  store->entries = requesters;
  store->capacity = capacity;
  return &store->entries[store->count++];
}

static void get_requester_delivery_stats(
    const transport_flexicast_flow_t *flow, uint64_t member_id,
    uint64_t *delivery_rate, int64_t *last_feedback) {
  *delivery_rate = 0;
  *last_feedback = 0;
  if (!flow->crypto)
    return;
  quicly_flexicast_member_stats_t stats;
  if (quicly_flexicast_get_member_stats(flow->crypto, member_id, &stats) ==
      QUICLY_FLEXICAST_OK) {
    *delivery_rate = stats.delivery_rate_bytes_per_second;
    *last_feedback = stats.last_feedback_at;
  }
}

static void record_requested_symbols(
    transport_flexicast_repair_requester_t *requester,
    transport_repair_mode_t mode, bool whole_object, size_t deficit,
    const uint16_t *missing, size_t missing_count) {
  if (!requester || mode != TRANSPORT_REPAIR_MODE_INDEXED)
    return;
  if (whole_object) {
    if (deficit > QLINQ_WIRE_MAX_NACK_SYMBOLS)
      deficit = QLINQ_WIRE_MAX_NACK_SYMBOLS;
    for (size_t i = 0; i < deficit; i++)
      requester->requested_symbols[i / 64U] |= UINT64_C(1) << (i % 64U);
  } else {
    for (size_t i = 0; missing && i < missing_count; i++)
      if (missing[i] < QLINQ_WIRE_MAX_NACK_SYMBOLS)
        requester->requested_symbols[missing[i] / 64U] |=
            UINT64_C(1) << (missing[i] % 64U);
  }
}

static size_t
requester_store_remove(transport_flexicast_requester_store_t *store,
                       uint64_t request_id) {
  size_t removed = 0;
  for (size_t i = 0; i < store->count;) {
    if (store->entries[i].request_id != request_id) {
      i++;
      continue;
    }
    store->entries[i] = store->entries[--store->count];
    removed++;
  }
  if (store->count == 0) {
    free(store->entries);
    memset(store, 0, sizeof(*store));
  }
  return removed;
}

static void observe_repair_requester(
    transport_t *t, transport_flexicast_flow_t *flow,
    transport_flexicast_pending_repair_t *pending, uint64_t member_id,
    size_t deficit, transport_repair_mode_t mode, bool whole_object,
    const uint16_t *missing, size_t missing_count, int64_t now_ms) {
  if (deficit == 0)
    return;
  if (deficit > UINT16_MAX)
    deficit = UINT16_MAX;

  uint64_t delivery_rate;
  int64_t last_feedback;
  get_requester_delivery_stats(flow, member_id, &delivery_rate, &last_feedback);
  uint64_t feedback_age = last_feedback > 0 && now_ms > last_feedback
                              ? (uint64_t)(now_ms - last_feedback)
                              : 0;

  transport_flexicast_repair_requester_t *requester = requester_store_find(
      &flow->repair_requesters, pending->intent_id, member_id);
  if (requester) {
    if (pending->retained_deficit_sum >= requester->deficit)
      pending->retained_deficit_sum -= requester->deficit;
    if (deficit < requester->deficit && !requester->shared_repair_useful) {
      requester->shared_repair_useful = true;
      pending->shared_useful_requesters++;
    }
    requester->deficit = (uint16_t)deficit;
    requester->delivery_rate_bytes_per_second = delivery_rate;
    requester->last_feedback_ms = last_feedback;
    requester->last_request_ms = now_ms;
    memset(requester->requested_symbols, 0,
           sizeof(requester->requested_symbols));
    pending->retained_deficit_sum =
        saturating_add_u64(pending->retained_deficit_sum, (uint64_t)deficit);
    t->stats.repair_requester_updates++;
  } else if (!(requester = requester_store_append(&flow->repair_requesters))) {
    pending->overflow_requests++;
    pending->overflow_deficit_sum =
        saturating_add_u64(pending->overflow_deficit_sum, (uint64_t)deficit);
    t->stats.repair_requester_overflow++;
  } else {
    *requester = (transport_flexicast_repair_requester_t){
        .request_id = pending->intent_id,
        .member_id = member_id,
        .deficit = (uint16_t)deficit,
        .delivery_rate_bytes_per_second = delivery_rate,
        .first_request_ms = now_ms,
        .last_request_ms = now_ms,
        .last_feedback_ms = last_feedback,
        .shared_repair_useful = true};
    pending->retained_requesters++;
    pending->shared_useful_requesters++;
    pending->retained_deficit_sum =
        saturating_add_u64(pending->retained_deficit_sum, (uint64_t)deficit);
    if (flow->repair_requesters.count > t->stats.repair_requester_records_peak)
      t->stats.repair_requester_records_peak = flow->repair_requesters.count;
  }
  if (deficit > pending->maximum_requester_deficit)
    pending->maximum_requester_deficit = (uint16_t)deficit;
  if (feedback_age > pending->oldest_feedback_age_ms)
    pending->oldest_feedback_age_ms = feedback_age;
  if (delivery_rate != 0 &&
      (pending->minimum_delivery_rate_bytes_per_second == 0 ||
       delivery_rate < pending->minimum_delivery_rate_bytes_per_second))
    pending->minimum_delivery_rate_bytes_per_second = delivery_rate;

  record_requested_symbols(requester, mode, whole_object, deficit, missing,
                           missing_count);
}

static void expire_repair_requesters(transport_t *t,
                                     transport_flexicast_flow_t *flow,
                                     uint64_t intent_id) {
  size_t expired = requester_store_remove(&flow->repair_requesters, intent_id);
  t->stats.repair_requester_records_expired =
      saturating_add_u64(t->stats.repair_requester_records_expired, expired);
}

static transport_flexicast_shadow_observation_t *
find_shadow_observation(transport_flexicast_flow_t *flow, uint64_t group_id,
                        uint64_t object_id, transport_repair_mode_t mode) {
  for (size_t i = 0; i < TRANSPORT_FLEXICAST_SHADOW_OBSERVATIONS; i++) {
    transport_flexicast_shadow_observation_t *observation =
        &flow->shadow_observations[i];
    if (observation->active && observation->group_id == group_id &&
        observation->object_id == object_id && observation->mode == mode)
      return observation;
  }
  return NULL;
}

static void clear_shadow_observation(
    transport_flexicast_flow_t *flow,
    transport_flexicast_shadow_observation_t *observation) {
  if (!flow || !observation || !observation->active)
    return;
  uint64_t observation_id = observation->observation_id;
  (void)requester_store_remove(&flow->shadow_requesters, observation_id);
  memset(observation, 0, sizeof(*observation));
  if (flow->shadow_observation_count != 0)
    flow->shadow_observation_count--;
}

void transport_flexicast_observe_repair_request(
    transport_t *t, transport_flexicast_flow_t *flow,
    const sent_object_cache_t *object, uint64_t requester_id,
    transport_repair_mode_t mode, bool whole_object, const uint16_t *missing,
    size_t missing_count,
    transport_flexicast_observation_disposition_t disposition, int64_t now_ms) {
  if (!t || !t->repair_shadow_log || !flow || !object || requester_id == 0 ||
      (mode != TRANSPORT_REPAIR_MODE_INDEXED &&
       mode != TRANSPORT_REPAIR_MODE_RATELESS))
    return;
  size_t deficit = whole_object ? object->data_symbols : missing_count;
  if (deficit == 0)
    return;
  if (deficit > UINT16_MAX)
    deficit = UINT16_MAX;

  transport_flexicast_shadow_observation_t *observation =
      find_shadow_observation(flow, object->group_id, object->object_id, mode);
  if (!observation) {
    for (size_t i = 0; i < TRANSPORT_FLEXICAST_SHADOW_OBSERVATIONS; i++) {
      if (!flow->shadow_observations[i].active) {
        observation = &flow->shadow_observations[i];
        break;
      }
    }
    if (!observation) {
      t->stats.repair_shadow_observation_overflow++;
      return;
    }
    if (++flow->next_shadow_observation_id == 0)
      flow->next_shadow_observation_id = 1;
    *observation = (transport_flexicast_shadow_observation_t){
        .active = true,
        .observation_id = flow->next_shadow_observation_id,
        .group_id = object->group_id,
        .object_id = object->object_id,
        .mode = mode,
        .first_request_ms = now_ms,
        .ready_at_ms = now_ms + TRANSPORT_FLEXICAST_SHADOW_OBSERVATION_MS,
        .cohort_member_count = transport_flexicast_listening_members(flow)};
    flow->shadow_observation_count++;
  }
  size_t cohort_members = transport_flexicast_listening_members(flow);
  if (cohort_members > observation->cohort_member_count)
    observation->cohort_member_count = cohort_members;
  switch (disposition) {
  case TRANSPORT_FLEXICAST_OBS_ACCEPTED:
    observation->accepted_requests++;
    break;
  case TRANSPORT_FLEXICAST_OBS_SUPPRESSED:
    observation->suppressed_requests++;
    break;
  case TRANSPORT_FLEXICAST_OBS_THROTTLED:
    observation->throttled_requests++;
    break;
  }

  transport_flexicast_repair_requester_t *requester = requester_store_find(
      &flow->shadow_requesters, observation->observation_id, requester_id);
  if (!requester) {
    requester = requester_store_append(&flow->shadow_requesters);
    if (!requester) {
      observation->overflow_requests++;
      t->stats.repair_shadow_observation_overflow++;
      return;
    }
    *requester = (transport_flexicast_repair_requester_t){
        .request_id = observation->observation_id,
        .member_id = requester_id,
        .deficit = (uint16_t)deficit,
        .first_request_ms = now_ms,
        .last_request_ms = now_ms};
  } else {
    if (deficit > requester->deficit)
      requester->deficit = (uint16_t)deficit;
    requester->last_request_ms = now_ms;
  }

  get_requester_delivery_stats(flow, requester_id,
                               &requester->delivery_rate_bytes_per_second,
                               &requester->last_feedback_ms);
  record_requested_symbols(requester, mode, whole_object, deficit, missing,
                           missing_count);
}

static bool repair_symbol_is_covered(const transport_flexicast_flow_t *flow,
                                     uint64_t group_id, uint64_t object_id,
                                     uint16_t symbol_index, int64_t now_ms) {
  for (size_t i = 0; i < flow->repair_queue.count; i++) {
    const transport_flexicast_queued_payload_t *queued =
        queue_at_const(&flow->repair_queue, i);
    if (queued->group_id == group_id && queued->object_id == object_id &&
        queued->symbol_index == symbol_index)
      return true;
  }
  for (size_t i = 0; i < TRANSPORT_FLEXICAST_RECENT_REPAIRS; i++) {
    const transport_flexicast_recent_repair_t *recent =
        &flow->recent_repairs[i];
    if (recent->active && recent->expires_at_ms > now_ms &&
        recent->group_id == group_id && recent->object_id == object_id &&
        recent->symbol_index == symbol_index)
      return true;
  }
  return false;
}

static size_t repair_symbol_count(const uint64_t *symbols) {
  size_t count = 0;
  for (size_t i = 0; i < QLINQ_WIRE_MAX_NACK_SYMBOLS / 64U; i++) {
    uint64_t word = symbols[i];
    while (word != 0) {
      word &= word - 1U;
      count++;
    }
  }
  return count;
}

static size_t
rateless_repair_count_covered(const transport_flexicast_flow_t *flow,
                              uint64_t group_id, uint64_t object_id,
                              int64_t now_ms) {
  size_t count = 0;
  for (size_t i = 0; i < flow->repair_queue.count; i++) {
    const transport_flexicast_queued_payload_t *queued =
        queue_at_const(&flow->repair_queue, i);
    if (queued->group_id == group_id && queued->object_id == object_id &&
        queued->repair_mode == TRANSPORT_REPAIR_MODE_RATELESS)
      count++;
  }
  for (size_t i = 0; i < TRANSPORT_FLEXICAST_RECENT_REPAIRS; i++) {
    const transport_flexicast_recent_repair_t *recent =
        &flow->recent_repairs[i];
    if (recent->active && recent->expires_at_ms > now_ms &&
        recent->group_id == group_id && recent->object_id == object_id &&
        recent->mode == TRANSPORT_REPAIR_MODE_RATELESS)
      count++;
  }
  return count;
}

static transport_conn_t *find_connection_by_id(transport_t *t,
                                               uint64_t member_id) {
  if (!t || member_id > UINT32_MAX)
    return NULL;
  size_t count = t->is_server ? t->conn_count : (t->client_conn ? 1U : 0U);
  for (size_t i = 0; i < count; i++) {
    transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
    if (conn && conn->id == (uint32_t)member_id)
      return conn;
  }
  return NULL;
}

static uint32_t shared_delivery_ppm(const transport_flexicast_flow_t *flow,
                                    uint64_t delivery_rate) {
  if (!flow || flow->pacing_rate_bytes_per_second == 0 || delivery_rate == 0)
    return 0;
  __extension__ typedef unsigned __int128 wide_t;
  wide_t scaled = (wide_t)delivery_rate * 1000000U;
  scaled /= flow->pacing_rate_bytes_per_second;
  return scaled >= 1000000U ? 1000000U : (uint32_t)scaled;
}

static bool build_shadow_observation_snapshot(
    transport_t *t, transport_flexicast_flow_t *flow,
    const transport_flexicast_shadow_observation_t *observation,
    const sent_object_cache_t *object, int64_t now,
    transport_repair_planner_snapshot_t *snapshot,
    transport_repair_planner_requester_t **allocated) {
  if (!t || !flow || !observation || !object || !snapshot || !allocated)
    return false;
  size_t count = 0;
  for (size_t i = 0; i < flow->shadow_requesters.count; i++)
    if (flow->shadow_requesters.entries[i].request_id ==
        observation->observation_id)
      count++;
  if (count == 0)
    return false;
  transport_repair_planner_requester_t *requesters =
      calloc(count, sizeof(*requesters));
  if (!requesters)
    return false;

  size_t output = 0;
  size_t cohort_members = observation->cohort_member_count;
  size_t current_members = transport_flexicast_listening_members(flow);
  if (current_members > cohort_members)
    cohort_members = current_members;
  bool incomplete = observation->overflow_requests != 0 ||
                    observation->throttled_requests != 0;
  for (size_t i = 0; i < flow->shadow_requesters.count; i++) {
    const transport_flexicast_repair_requester_t *source =
        &flow->shadow_requesters.entries[i];
    if (source->request_id != observation->observation_id)
      continue;
    transport_repair_planner_requester_t *requester = &requesters[output++];
    requester->member_id = source->member_id;
    requester->deficit = source->deficit;
    requester->feedback_age_ms =
        source->last_feedback_ms > 0 && now > source->last_feedback_ms
            ? (uint64_t)(now - source->last_feedback_ms)
            : 0;
    requester->shared_delivery_probability_ppm =
        shared_delivery_ppm(flow, source->delivery_rate_bytes_per_second);
    memcpy(requester->requested_symbols, source->requested_symbols,
           sizeof(requester->requested_symbols));

    transport_conn_t *conn = find_connection_by_id(t, source->member_id);
    if (!conn) {
      incomplete = true;
      continue;
    }
    requester->path_count = t->num_fds;
    for (size_t path = 0; path < requester->path_count; path++) {
      const path_state_t *state = &conn->path_states[path];
      transport_repair_planner_path_t *entry = &requester->paths[path];
      entry->resource_id = t->local_ifindices[path];
      entry->measurement_known = state->initialized && state->b_ewma > 0;
      entry->estimate.b = state->b_ewma > 0 ? state->b_ewma : FP_FROM_INT(100);
      entry->estimate.l = state->l_ewma;
      entry->estimate.p = state->p_ewma;
      entry->estimate.q = state->q_ewma;
    }
  }

  *snapshot = (transport_repair_planner_snapshot_t){
      .version = TRANSPORT_REPAIR_PLANNER_VERSION,
      .intent_id = observation->observation_id,
      .group_id = observation->group_id,
      .object_id = observation->object_id,
      .mode = observation->mode,
      .symbol_size = object->symbol_size,
      .packet_overhead = QLINQ_WIRE_FEC_HEADER_SIZE + 128U,
      .deadline_ms = t->repair_shadow_deadline_ms,
      .shared_rate_bytes_per_second = flow->pacing_rate_bytes_per_second,
      .shared_resource_id = flow->interface_index,
      .shared_physical_copies = flow->native_multicast ? 1U : cohort_members,
      .cohort_member_count = cohort_members,
      .observation_window_ms = TRANSPORT_FLEXICAST_SHADOW_OBSERVATION_MS,
      .observation_age_ms =
          now > observation->first_request_ms
              ? (uint64_t)(now - observation->first_request_ms)
              : 0,
      .accepted_request_count = observation->accepted_requests,
      .suppressed_request_count = observation->suppressed_requests,
      .throttled_request_count = observation->throttled_requests,
      .observation_overflow_count = observation->overflow_requests,
      .incomplete_requester_state = incomplete,
      .requesters = requesters,
      .requester_count = count};
  *allocated = requesters;
  return true;
}

static void emit_ready_shadow_observations(transport_t *t,
                                           transport_flexicast_flow_t *flow,
                                           int64_t now) {
  if (!t || !flow || !t->repair_shadow_log)
    return;
  for (size_t index = 0; index < TRANSPORT_FLEXICAST_SHADOW_OBSERVATIONS;
       index++) {
    transport_flexicast_shadow_observation_t *observation =
        &flow->shadow_observations[index];
    if (!observation->active || now < observation->ready_at_ms)
      continue;
    sent_object_cache_t *object = transport_sent_cache_find(
        &t->sent_cache, &flow->track_id, observation->group_id,
        observation->object_id);
    if (!object) {
      clear_shadow_observation(flow, observation);
      continue;
    }
    transport_repair_planner_snapshot_t snapshot;
    transport_repair_planner_requester_t *requesters = NULL;
    transport_repair_planner_evaluation_t evaluation;
    if (!build_shadow_observation_snapshot(t, flow, observation, object, now,
                                           &snapshot, &requesters) ||
        !transport_repair_planner_evaluate(&snapshot, &evaluation)) {
      t->stats.repair_shadow_log_errors++;
      free(requesters);
      clear_shadow_observation(flow, observation);
      continue;
    }
    t->stats.repair_shadow_plans_evaluated++;
    switch (evaluation.chosen.action) {
    case TRANSPORT_REPAIR_PLAN_ALL_SHARED:
      t->stats.repair_shadow_all_shared++;
      break;
    case TRANSPORT_REPAIR_PLAN_ALL_UNICAST:
      t->stats.repair_shadow_all_unicast++;
      break;
    case TRANSPORT_REPAIR_PLAN_MIXED:
      t->stats.repair_shadow_mixed++;
      break;
    }
    if (evaluation.chosen.uncertain || evaluation.chosen.approximate)
      t->stats.repair_shadow_uncertain++;
    if (!evaluation.chosen.feasible)
      t->stats.repair_shadow_infeasible++;
    t->stats.repair_shadow_last_airtime_us =
        evaluation.chosen.aggregate_airtime_us;
    t->stats.repair_shadow_last_physical_bytes =
        evaluation.chosen.physical_bytes;
    t->stats.repair_shadow_last_savings_ppm =
        evaluation.chosen_savings_vs_shared_ppm;
    if (t->repair_shadow_log &&
        (!transport_repair_planner_record_write(t->repair_shadow_log, &snapshot,
                                                &evaluation) ||
         fflush(t->repair_shadow_log) != 0))
      t->stats.repair_shadow_log_errors++;
    free(requesters);
    clear_shadow_observation(flow, observation);
  }
}

static void clear_pending_repair(transport_t *t,
                                 transport_flexicast_flow_t *flow,
                                 transport_flexicast_pending_repair_t *pending);

bool transport_flexicast_schedule_repair(
    transport_t *t, transport_flexicast_flow_t *flow,
    const sent_object_cache_t *object, uint64_t requester_id,
    transport_repair_mode_t mode, bool whole_object, const uint16_t *missing,
    size_t missing_count, int64_t now_ms) {
  if (!t || !flow || !flow->source || !object ||
      !transport_track_id_equal(&flow->track_id, &object->track_id) ||
      (mode != TRANSPORT_REPAIR_MODE_INDEXED &&
       mode != TRANSPORT_REPAIR_MODE_RATELESS) ||
      (mode == TRANSPORT_REPAIR_MODE_INDEXED && !whole_object &&
       (!missing || missing_count == 0)) ||
      (mode == TRANSPORT_REPAIR_MODE_RATELESS && !whole_object &&
       missing_count == 0))
    return false;
  if (mode == TRANSPORT_REPAIR_MODE_INDEXED && !whole_object)
    for (size_t i = 0; i < missing_count; i++)
      if (missing[i] >= QLINQ_WIRE_MAX_NACK_SYMBOLS)
        return false;

  size_t requester_deficit =
      whole_object ? object->data_symbols : missing_count;
  if (requester_deficit > TRANSPORT_REPAIR_MAX_SYMBOLS)
    requester_deficit = TRANSPORT_REPAIR_MAX_SYMBOLS;
  transport_flexicast_pending_repair_t *pending =
      find_pending_repair(flow, object->group_id, object->object_id, mode);
  bool merging = pending != NULL;
  if (mode == TRANSPORT_REPAIR_MODE_RATELESS) {
    size_t covered =
        t->flexicast_repair_route == TRANSPORT_FLEXICAST_REPAIR_SHARED
            ? rateless_repair_count_covered(flow, object->group_id,
                                            object->object_id, now_ms)
            : 0;
    if (requester_deficit <= covered) {
      t->stats.repair_requests_merged++;
      return true;
    }
    missing_count = requester_deficit - covered;
  }
  if (!pending) {
    bool fully_queued =
        t->flexicast_repair_route == TRANSPORT_FLEXICAST_REPAIR_SHARED;
    if (mode == TRANSPORT_REPAIR_MODE_RATELESS) {
      fully_queued = false;
    } else if (whole_object) {
      size_t count = object->data_symbols;
      if (count > TRANSPORT_REPAIR_MAX_SYMBOLS)
        count = TRANSPORT_REPAIR_MAX_SYMBOLS;
      for (size_t i = 0; i < count; i++)
        fully_queued &= repair_symbol_is_covered(
            flow, object->group_id, object->object_id, (uint16_t)i, now_ms);
    } else {
      for (size_t i = 0; i < missing_count; i++)
        fully_queued &= repair_symbol_is_covered(
            flow, object->group_id, object->object_id, missing[i], now_ms);
    }
    if (fully_queued) {
      t->stats.repair_requests_merged++;
      return true;
    }
  }
  if (!pending) {
    for (size_t i = 0; i < TRANSPORT_FLEXICAST_PENDING_REPAIRS; i++) {
      if (!flow->pending_repairs[i].active) {
        pending = &flow->pending_repairs[i];
        break;
      }
    }
    if (!pending) {
      t->stats.repair_queue_backpressure++;
      return false;
    }
    memset(pending, 0, sizeof(*pending));
    pending->active = true;
    if (++flow->next_repair_intent_id == 0)
      flow->next_repair_intent_id = 1;
    pending->intent_id = flow->next_repair_intent_id;
    pending->group_id = object->group_id;
    pending->object_id = object->object_id;
    pending->mode = mode;
    pending->first_request_ms = now_ms;
    pending->ready_at_ms = now_ms + TRANSPORT_FLEXICAST_REPAIR_HOLDOFF_MS;
    flow->pending_repair_count++;
  }

  size_t before = pending_repair_symbol_count(pending);
  if (mode == TRANSPORT_REPAIR_MODE_RATELESS) {
    if (missing_count > pending->requested_dof)
      pending->requested_dof = (uint16_t)missing_count;
  } else if (whole_object) {
    size_t count = object->data_symbols;
    if (count > TRANSPORT_REPAIR_MAX_SYMBOLS)
      count = TRANSPORT_REPAIR_MAX_SYMBOLS;
    for (size_t i = 0; i < count; i++)
      if (!repair_symbol_is_covered(flow, object->group_id, object->object_id,
                                    (uint16_t)i, now_ms))
        pending->requested_symbols[i / 64U] |= UINT64_C(1) << (i % 64U);
  } else {
    for (size_t i = 0; i < missing_count; i++) {
      if (!repair_symbol_is_covered(flow, object->group_id, object->object_id,
                                    missing[i], now_ms))
        pending->requested_symbols[missing[i] / 64U] |= UINT64_C(1)
                                                        << (missing[i] % 64U);
    }
  }
  size_t after = pending_repair_symbol_count(pending);
  if (merging || after == before)
    t->stats.repair_requests_merged++;
  observe_repair_requester(t, flow, pending, requester_id, requester_deficit,
                           mode, whole_object, missing, missing_count, now_ms);
  if (after == 0)
    clear_pending_repair(t, flow, pending);
  return true;
}

static void
clear_pending_repair(transport_t *t, transport_flexicast_flow_t *flow,
                     transport_flexicast_pending_repair_t *pending) {
  if (!pending->active)
    return;
  expire_repair_requesters(t, flow, pending->intent_id);
  memset(pending, 0, sizeof(*pending));
  if (flow->pending_repair_count != 0)
    flow->pending_repair_count--;
}

static size_t cancel_flow_repairs(transport_t *t,
                                  transport_flexicast_flow_t *flow,
                                  bool entire_track, uint64_t group_id,
                                  uint64_t object_id) {
  size_t pending_symbols = 0;
  for (size_t i = 0; i < TRANSPORT_FLEXICAST_PENDING_REPAIRS; i++) {
    transport_flexicast_pending_repair_t *pending = &flow->pending_repairs[i];
    if (!pending->active || (!entire_track && (pending->group_id != group_id ||
                                               pending->object_id > object_id)))
      continue;
    pending_symbols += pending_repair_symbol_count(pending);
    clear_pending_repair(t, flow, pending);
  }
  for (size_t i = 0; i < TRANSPORT_FLEXICAST_RECENT_REPAIRS; i++) {
    transport_flexicast_recent_repair_t *recent = &flow->recent_repairs[i];
    if (recent->active && (entire_track || (recent->group_id == group_id &&
                                            recent->object_id <= object_id)))
      memset(recent, 0, sizeof(*recent));
  }
  for (size_t i = 0; i < TRANSPORT_FLEXICAST_SHADOW_OBSERVATIONS; i++) {
    transport_flexicast_shadow_observation_t *observation =
        &flow->shadow_observations[i];
    if (observation->active &&
        (entire_track || (observation->group_id == group_id &&
                          observation->object_id <= object_id)))
      clear_shadow_observation(flow, observation);
  }

  transport_flexicast_queued_payload_t
      retained[TRANSPORT_FLEXICAST_REPAIR_QUEUE_CAPACITY] = {0};
  size_t retained_count = 0;
  size_t retained_bytes = 0;
  size_t cancelled = 0;
  for (size_t i = 0; i < flow->repair_queue.count; i++) {
    transport_flexicast_queued_payload_t *queued =
        queue_at(&flow->repair_queue, i);
    if (entire_track ||
        (queued->group_id == group_id && queued->object_id <= object_id)) {
      free(queued->data);
      cancelled++;
    } else {
      retained[retained_count++] = *queued;
      retained_bytes += queued->size;
    }
    memset(queued, 0, sizeof(*queued));
  }
  if (retained_count != 0)
    memcpy(flow->repair_queue.entries, retained,
           retained_count * sizeof(*retained));
  flow->repair_queue.head = 0;
  flow->repair_queue.count = retained_count;
  flow->repair_queue.bytes = retained_bytes;
  if (retained_count == 0) {
    flow->repair_priority_available = false;
    flow->data_airtime_since_repair = 0;
  }
  t->stats.repair_packets_cancelled += cancelled;
  t->stats.repair_pending_symbols_cancelled += pending_symbols;
  return cancelled + pending_symbols;
}

size_t transport_flexicast_cancel_repairs_through(transport_t *t,
                                                  const moq_track_id_t *track,
                                                  uint64_t group_id,
                                                  uint64_t object_id) {
  if (!t || !track)
    return 0;
  size_t cancelled = 0;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (flow->active && flow->source &&
        transport_track_id_equal(&flow->track_id, track))
      cancelled += cancel_flow_repairs(t, flow, false, group_id, object_id);
  }
  return cancelled;
}

size_t transport_flexicast_cancel_track_repairs(transport_t *t,
                                                const moq_track_id_t *track) {
  if (!t || !track)
    return 0;
  size_t cancelled = 0;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (flow->active && flow->source &&
        transport_track_id_equal(&flow->track_id, track))
      cancelled += cancel_flow_repairs(t, flow, true, 0, 0);
  }
  return cancelled;
}

static bool requester_needs_repair_symbol(
    const transport_flexicast_repair_requester_t *requester,
    transport_repair_mode_t mode, uint16_t symbol_index,
    size_t rateless_ordinal) {
  if (mode == TRANSPORT_REPAIR_MODE_RATELESS)
    return rateless_ordinal < requester->deficit;
  return symbol_index < QLINQ_WIRE_MAX_NACK_SYMBOLS &&
         (requester->requested_symbols[symbol_index / 64U] &
          (UINT64_C(1) << (symbol_index % 64U))) != 0;
}

static bool
unicast_repair_can_accept(transport_t *t, transport_flexicast_flow_t *flow,
                          const transport_flexicast_pending_repair_t *pending,
                          const uint16_t *indices, size_t count) {
  size_t matched = 0;
  for (size_t r = 0; r < flow->repair_requesters.count; r++) {
    const transport_flexicast_repair_requester_t *requester =
        &flow->repair_requesters.entries[r];
    if (requester->request_id != pending->intent_id)
      continue;
    transport_conn_t *conn = find_connection_by_id(t, requester->member_id);
    if (!conn || !conn->quic)
      return false;
    size_t needed = 0;
    for (size_t i = 0; i < count; i++) {
      uint16_t symbol_index =
          pending->mode == TRANSPORT_REPAIR_MODE_RATELESS ? 0 : indices[i];
      if (requester_needs_repair_symbol(requester, pending->mode, symbol_index,
                                        i))
        needed++;
    }
    if (needed > QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY ||
        conn->queued_datagrams[0] > QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY - needed)
      return false;
    matched++;
  }
  return matched != 0;
}

static bool
queue_unicast_repair_symbol(transport_t *t, transport_flexicast_flow_t *flow,
                            const transport_flexicast_pending_repair_t *pending,
                            ptls_iovec_t packet, uint16_t symbol_index,
                            size_t rateless_ordinal, size_t *transmissions) {
  bool matched = false;
  for (size_t r = 0; r < flow->repair_requesters.count; r++) {
    const transport_flexicast_repair_requester_t *requester =
        &flow->repair_requesters.entries[r];
    if (requester->request_id != pending->intent_id ||
        !requester_needs_repair_symbol(requester, pending->mode, symbol_index,
                                       rateless_ordinal))
      continue;
    transport_conn_t *conn = find_connection_by_id(t, requester->member_id);
    if (!conn || !transport_queue_datagram(conn, 0, packet))
      return false;
    (*transmissions)++;
    matched = true;
  }
  return matched;
}

static void materialize_pending_repairs(transport_t *t,
                                        transport_flexicast_flow_t *flow,
                                        int64_t now) {
  for (size_t pending_index = 0;
       pending_index < TRANSPORT_FLEXICAST_PENDING_REPAIRS; pending_index++) {
    transport_flexicast_pending_repair_t *pending =
        &flow->pending_repairs[pending_index];
    if (!pending->active || now < pending->ready_at_ms)
      continue;
    sent_object_cache_t *object = transport_sent_cache_find(
        &t->sent_cache, &flow->track_id, pending->group_id, pending->object_id);
    if (!object) {
      clear_pending_repair(t, flow, pending);
      continue;
    }
    uint16_t indices[TRANSPORT_REPAIR_MAX_SYMBOLS];
    size_t count = 0;
    if (pending->mode == TRANSPORT_REPAIR_MODE_RATELESS) {
      count = pending->requested_dof;
    } else {
      for (size_t word_index = 0;
           word_index < QLINQ_WIRE_MAX_NACK_SYMBOLS / 64U &&
           count < TRANSPORT_REPAIR_MAX_SYMBOLS;
           word_index++) {
        uint64_t word = pending->requested_symbols[word_index];
        for (uint16_t bit = 0;
             bit < 64U && count < TRANSPORT_REPAIR_MAX_SYMBOLS; bit++)
          if ((word & (UINT64_C(1) << bit)) != 0)
            indices[count++] = (uint16_t)(word_index * 64U + bit);
      }
    }
    if (count == 0) {
      clear_pending_repair(t, flow, pending);
      continue;
    }
    size_t packet_size = QLINQ_WIRE_FEC_HEADER_SIZE + object->symbol_size;
    bool forced_unicast =
        t->flexicast_repair_route == TRANSPORT_FLEXICAST_REPAIR_UNICAST;
    bool capacity_available =
        forced_unicast
            ? unicast_repair_can_accept(t, flow, pending, indices, count)
            : repair_queue_can_accept(t, flow, count, packet_size * count);
    if (packet_size > SIZE_MAX / count || !capacity_available) {
      if (!pending->backpressure_reported) {
        t->stats.repair_queue_backpressure++;
        pending->backpressure_reported = true;
      }
      continue;
    }

    transport_repair_batch_t repair;
    bool systematic_fallback = false;
    bool built = pending->mode == TRANSPORT_REPAIR_MODE_RATELESS
                     ? transport_repair_build_rateless(&t->fec_cache, object,
                                                       count, &repair)
                     : transport_repair_build(&t->fec_cache, object, false,
                                              indices, count, &repair);
    if (!built && pending->mode == TRANSPORT_REPAIR_MODE_RATELESS &&
        object->next_repair_symbol >= QLINQ_FEC_MAX_TOTAL_SYMBOLS) {
      t->stats.repair_rateless_exhausted++;
      built = transport_repair_build_systematic_fallback(&t->fec_cache, object,
                                                         count, &repair);
      systematic_fallback = built;
    }
    if (!built) {
      clear_pending_repair(t, flow, pending);
      continue;
    }
    size_t queued = 0, unicast_transmissions = 0;
    for (size_t i = 0; i < repair.count; i++) {
      uint8_t packet[QLINQ_WIRE_FEC_HEADER_SIZE + QLINQ_FEC_MAX_SYMBOL_SIZE];
      size_t encoded_size = QLINQ_WIRE_FEC_HEADER_SIZE + repair.symbol_size;
      qlinq_wire_fec_header_t header = {.alias = flow->alias,
                                        .is_keyframe = object->is_keyframe,
                                        .priority = object->priority,
                                        .path_id = 0,
                                        .group_id = object->group_id,
                                        .object_id = object->object_id,
                                        .symbol_index = repair.indices[i],
                                        .total_symbols = repair.total_symbols,
                                        .data_symbols = object->data_symbols,
                                        .symbol_size = repair.symbol_size,
                                        .original_size = (uint32_t)object->size,
                                        .send_time_ns =
                                            transport_get_time_ns()};
      if (qlinq_wire_encode_fec_header(packet, sizeof(packet), &header) !=
              QLINQ_WIRE_OK ||
          encoded_size > sizeof(packet))
        break;
      memcpy(packet + QLINQ_WIRE_FEC_HEADER_SIZE,
             repair.symbols + i * repair.symbol_size, repair.symbol_size);
      bool sent =
          forced_unicast
              ? queue_unicast_repair_symbol(
                    t, flow, pending, ptls_iovec_init(packet, encoded_size),
                    repair.indices[i], i, &unicast_transmissions)
              : queue_repair_payload(t, flow,
                                     ptls_iovec_init(packet, encoded_size),
                                     object->group_id, object->object_id,
                                     repair.indices[i], pending->mode, now);
      if (!sent)
        break;
      if (pending->mode == TRANSPORT_REPAIR_MODE_RATELESS) {
        if (pending->requested_dof != 0)
          pending->requested_dof--;
      } else {
        pending->requested_symbols[repair.indices[i] / 64U] &=
            ~(UINT64_C(1) << (repair.indices[i] % 64U));
      }
      queued++;
    }
    if (queued != 0 && pending->mode == TRANSPORT_REPAIR_MODE_RATELESS) {
      bool committed =
          systematic_fallback
              ? transport_repair_commit_systematic_fallback(object, &repair,
                                                            queued)
              : transport_repair_commit_rateless(object, &repair, queued);
      /* Repair allocation is transactional: only symbols admitted to an
       * egress queue consume an ESI (or advance the systematic fallback). */
      assert(committed);
    }
    transport_repair_batch_destroy(&repair);
    if (queued != 0) {
      size_t physical_symbols = forced_unicast ? unicast_transmissions : queued;
      t->stats.repair_symbols_sent += physical_symbols;
      if (forced_unicast) {
        t->stats.repair_unicast_symbols_sent += unicast_transmissions;
        uint64_t unicast_bytes =
            unicast_transmissions > UINT64_MAX / packet_size
                ? UINT64_MAX
                : (uint64_t)unicast_transmissions * packet_size;
        t->stats.repair_unicast_payload_bytes_queued = saturating_add_u64(
            t->stats.repair_unicast_payload_bytes_queued, unicast_bytes);
      } else {
        t->stats.repair_multicast_symbols_sent += queued;
      }
      if (pending->mode == TRANSPORT_REPAIR_MODE_RATELESS)
        t->stats.repair_rateless_symbols_sent += physical_symbols;
      t->stats.repair_batches_emitted++;
      pending->backpressure_reported = false;
    }
    if (pending_repair_symbol_count(pending) == 0)
      clear_pending_repair(t, flow, pending);
    else
      pending->ready_at_ms = now;
  }
}

bool transport_flexicast_send_payload(transport_t *t,
                                      transport_flexicast_flow_t *flow,
                                      ptls_iovec_t payload) {
  if (!t || !flow || !flow->source || !flow->crypto || !payload.base ||
      transport_flexicast_listening_members(flow) == 0)
    return false;
  refresh_pacer(t, flow, transport_get_time_ms());
  size_t cost = pacing_cost(flow, payload.len + 128U);
  if (flow->data_queue.count != 0 || flow->repair_queue.count != 0 ||
      cost > flow->pacing_tokens)
    return queue_payload(t, flow, payload);
  flexicast_dispatch_result_t result = dispatch_payload(t, flow, payload);
  if (result == FLEXICAST_DISPATCH_BLOCKED)
    return queue_payload(t, flow, payload);
  if (result != FLEXICAST_DISPATCH_OK)
    return false;
  flow->pacing_tokens -= cost;
  t->stats.flexicast_paced_packets++;
  t->stats.flexicast_physical_bytes_sent += cost;
  account_controller_airtime(flow, cost, false);
  return true;
}

static bool repair_has_priority(const transport_flexicast_flow_t *flow,
                                size_t repair_cost) {
  if (flow->repair_queue.count == 0)
    return false;
  if (flow->data_queue.count == 0 || flow->repair_priority_available)
    return true;
  return repair_cost <= UINT64_MAX / 3U &&
         flow->data_airtime_since_repair >= repair_cost * 3U;
}

typedef struct {
  transport_flexicast_queued_payload_t *payload;
  size_t cost;
  bool repair;
} flexicast_queue_selection_t;

static flexicast_queue_selection_t
select_queued_payload(transport_flexicast_flow_t *flow) {
  transport_flexicast_queued_payload_t *repair =
      queue_front(&flow->repair_queue);
  size_t repair_cost =
      repair ? pacing_cost(flow, repair->size + 128U) : SIZE_MAX;
  bool use_repair = repair_has_priority(flow, repair_cost);
  transport_flexicast_queued_payload_t *payload =
      use_repair ? repair : queue_front(&flow->data_queue);
  if (!payload)
    payload = repair;
  if (!payload)
    return (flexicast_queue_selection_t){0};

  size_t cost = pacing_cost(flow, payload->size + 128U);
  if (use_repair && cost > flow->pacing_tokens && flow->data_queue.count != 0) {
    transport_flexicast_queued_payload_t *data = queue_front(&flow->data_queue);
    size_t data_cost = pacing_cost(flow, data->size + 128U);
    if (data_cost < cost) {
      payload = data;
      cost = data_cost;
      use_repair = false;
    }
  }
  return (flexicast_queue_selection_t){
      .payload = payload, .cost = cost, .repair = use_repair};
}

static void account_data_airtime(transport_flexicast_flow_t *flow,
                                 size_t cost) {
  uint64_t maximum = flow->pacing_burst_bytes;
  if (maximum <= UINT64_MAX / 4U)
    maximum *= 4U;
  else
    maximum = UINT64_MAX;
  uint64_t current = flow->data_airtime_since_repair < maximum
                         ? flow->data_airtime_since_repair
                         : maximum;
  flow->data_airtime_since_repair =
      cost >= maximum - current ? maximum : current + cost;
}

static void
record_sent_repair(transport_flexicast_flow_t *flow,
                   const transport_flexicast_queued_payload_t *queued,
                   int64_t now_ms) {
  transport_flexicast_recent_repair_t *recent =
      &flow->recent_repairs[flow->next_recent_repair];
  *recent = (transport_flexicast_recent_repair_t){
      .active = true,
      .group_id = queued->group_id,
      .object_id = queued->object_id,
      .symbol_index = queued->symbol_index,
      .mode = queued->repair_mode,
      .expires_at_ms =
          now_ms <= INT64_MAX - TRANSPORT_FLEXICAST_REPAIR_REISSUE_MS
              ? now_ms + TRANSPORT_FLEXICAST_REPAIR_REISSUE_MS
              : INT64_MAX};
  flow->next_recent_repair =
      (flow->next_recent_repair + 1U) % TRANSPORT_FLEXICAST_RECENT_REPAIRS;
}

static void drain_paced_payloads(transport_t *t,
                                 transport_flexicast_flow_t *flow) {
  if (flow->data_queue.count == 0 && flow->repair_queue.count == 0)
    return;
  if (flow->rekey_pending)
    return;
  if (transport_flexicast_listening_members(flow) == 0) {
    bool awaiting_rekey_ready = false;
    for (size_t i = 0; i < flow->member_count; i++)
      awaiting_rekey_ready |= flow->members[i].conn && flow->members[i].joined;
    if (!awaiting_rekey_ready)
      t->stats.flexicast_pacing_dropped += clear_flow_queue(flow);
    return;
  }
  refresh_pacer(t, flow, transport_get_time_ms());
  while (flow->data_queue.count != 0 || flow->repair_queue.count != 0) {
    flexicast_queue_selection_t selection = select_queued_payload(flow);
    transport_flexicast_queued_payload_t *queued = selection.payload;
    if (!queued || !queued->data)
      break;
    size_t cost = selection.cost;
    bool is_repair = selection.repair;
    if (cost > flow->pacing_tokens)
      break;
    flexicast_dispatch_result_t result =
        dispatch_payload(t, flow, ptls_iovec_init(queued->data, queued->size));
    if (result == FLEXICAST_DISPATCH_BLOCKED)
      break;
    if (result == FLEXICAST_DISPATCH_OK) {
      flow->pacing_tokens -= cost;
      t->stats.flexicast_paced_packets++;
      t->stats.flexicast_physical_bytes_sent += cost;
      account_controller_airtime(flow, cost, is_repair);
      if (is_repair) {
        t->stats.repair_physical_bytes_sent += cost;
        flow->last_repair_sent_ms = transport_get_time_ms();
        record_sent_repair(flow, queued, flow->last_repair_sent_ms);
        flow->repair_priority_available = false;
        flow->data_airtime_since_repair = 0;
      } else {
        account_data_airtime(flow, cost);
      }
    } else {
      t->stats.flexicast_pacing_dropped++;
    }
    queue_pop(is_repair ? &flow->repair_queue : &flow->data_queue);
    if (result != FLEXICAST_DISPATCH_OK)
      break;
  }
}

bool transport_flexicast_track_ready(transport_t *t,
                                     const moq_track_id_t *track) {
  if (!t || !track)
    return false;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (!flow->active || !flow->source ||
        !transport_track_id_equal(&flow->track_id, track) ||
        transport_flexicast_listening_members(flow) == 0)
      continue;
    refresh_pacer(t, flow, transport_get_time_ms());
    if (flow->data_queue.count >=
            TRANSPORT_FLEXICAST_QUEUE_CAPACITY * 3U / 4U ||
        flow->data_queue.bytes + flow->repair_queue.bytes >=
            t->limits.max_egress_bytes_per_socket * 3U / 4U ||
        (flow->data_queue.count != 0 &&
         flow->pacing_tokens < t->limits.max_udp_payload_size))
      return false;
  }
  return true;
}

int64_t transport_flexicast_get_first_timeout(transport_t *t) {
  if (!t || !t->flexicast_enabled)
    return INT64_MAX;
  int64_t now = transport_get_time_ms();
  int64_t first_timeout = INT64_MAX;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (!flow->active || flow->source || !flow->crypto)
      continue;
    int64_t deadline = quicly_flexicast_get_ack_deadline(flow->crypto);
    if (deadline < first_timeout)
      first_timeout = deadline;
  }
  if (!t->is_server)
    return first_timeout;
  for (size_t i = 0; i < t->flexicast.capacity; i++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[i];
    if (!flow->active || !flow->source || !flow->crypto)
      continue;
    if (flow->rekey_pending && flow->rekey_ready_at_ms < first_timeout)
      first_timeout = flow->rekey_ready_at_ms;
    if (flow->feedback_outstanding_count != 0) {
      quicly_flexicast_cc_output_t output;
      quicly_flexicast_cc_get_flow_output(flow->crypto, &output);
      if (output.next_timeout < first_timeout)
        first_timeout = output.next_timeout;
    }
    for (size_t pending_index = 0;
         pending_index < TRANSPORT_FLEXICAST_PENDING_REPAIRS; pending_index++) {
      const transport_flexicast_pending_repair_t *pending =
          &flow->pending_repairs[pending_index];
      if (pending->active && pending->ready_at_ms < first_timeout)
        first_timeout = pending->ready_at_ms;
    }
    for (size_t observation_index = 0;
         observation_index < TRANSPORT_FLEXICAST_SHADOW_OBSERVATIONS;
         observation_index++) {
      const transport_flexicast_shadow_observation_t *observation =
          &flow->shadow_observations[observation_index];
      if (observation->active && observation->ready_at_ms < first_timeout)
        first_timeout = observation->ready_at_ms;
    }
    if ((flow->data_queue.count == 0 && flow->repair_queue.count == 0) ||
        transport_flexicast_listening_members(flow) == 0)
      continue;
    refresh_pacer(t, flow, now);
    flexicast_queue_selection_t selection = select_queued_payload(flow);
    if (!selection.payload)
      continue;
    size_t cost = selection.cost;
    if (cost <= flow->pacing_tokens)
      return now;
    if (flow->pacing_rate_bytes_per_second == 0)
      continue;
    uint64_t deficit = cost - flow->pacing_tokens;
    uint64_t delay =
        (deficit * 1000U + flow->pacing_rate_bytes_per_second - 1U) /
        flow->pacing_rate_bytes_per_second;
    if (delay == 0)
      delay = 1;
    int64_t timeout =
        delay > (uint64_t)(INT64_MAX - now) ? INT64_MAX : now + (int64_t)delay;
    if (timeout < first_timeout)
      first_timeout = timeout;
  }
  return first_timeout;
}

void transport_flexicast_tick(transport_t *t) {
  if (!t || !t->flexicast_enabled)
    return;
  int64_t now = transport_get_time_ms();
  for (size_t f = 0; f < t->flexicast.capacity; f++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[f];
    if (!flow->active || flow->source || !flow->crypto || !flow->control_conn ||
        !flow->control_conn->quic ||
        !quicly_flexicast_ack_is_due(flow->crypto, now) ||
        (t->simulated_flexicast_feedback_loss_rate > 0 &&
         (rand() % 100) < t->simulated_flexicast_feedback_loss_rate))
      continue;
    (void)quicly_flexicast_send_pending_ack(
        flow->crypto, flow->control_conn->quic, now, false);
  }
  if (!t->is_server)
    return;
  for (size_t f = 0; f < t->flexicast.capacity; f++) {
    transport_flexicast_flow_t *flow = &t->flexicast.flows[f];
    if (!flow->active || !flow->source || !flow->crypto)
      continue;
    for (size_t i = 0; i < flow->member_count; i++) {
      transport_flexicast_member_t *member = &flow->members[i];
      if (member->offer_pending)
        (void)send_pending_offer(flow, member);
    }
    if (flow->rekey_pending) {
      if (now < flow->rekey_ready_at_ms)
        continue;
      size_t changes = flow->rekey_pending_changes;
      flow->rekey_pending = false;
      flow->rekey_ready_at_ms = 0;
      flow->rekey_pending_changes = 0;
      t->stats.flexicast_rekey_members += flow->member_count;
      if (changes > 1)
        t->stats.flexicast_rekey_batched_changes += changes;
      if (!rekey_source_flow(t, flow))
        fallback_source_flow(t, flow);
      continue;
    }
    for (size_t i = 0; i < flow->member_count; i++) {
      transport_flexicast_member_t *member = &flow->members[i];
      if (member->conn && member->joined && member->key_pending &&
          send_current_key(flow, member))
        member->key_pending = false;
    }
    if (flow->feedback_outstanding_count != 0) {
      quicly_flexicast_cc_output_t output;
      quicly_flexicast_cc_get_flow_output(flow->crypto, &output);
      if (output.next_timeout != INT64_MAX && now >= output.next_timeout)
        quicly_flexicast_cc_on_flow_timeout(flow->crypto, now);
    }
    bool removed = false;
    for (size_t i = 0; i < flow->member_count; i++) {
      transport_flexicast_member_t *member = &flow->members[i];
      if (!member->conn || !member->listening ||
          member_delivery_debt(flow, member) <
              TRANSPORT_FLEXICAST_ACK_PACKET_THRESHOLD ||
          member->last_ack_time_ms <= 0 ||
          (uint64_t)(now - member->last_ack_time_ms) <
              feedback_demotion_timeout_ms(flow))
        continue;
      (void)send_state(member->conn, flow->flow_id, flow->key_epoch,
                       QUICLY_FLEXICAST_STATE_LEAVE);
      (void)quicly_flexicast_detach_at(flow->crypto, member->conn->id, now);
      member->joined = false;
      member->key_pending = false;
      set_member_listening(flow, member, false, 0);
      t->stats.flexicast_fallbacks++;
      t->stats.flexicast_feedback_fallbacks++;
      removed = true;
    }
    if (removed) {
      /* Shared repair work may have been requested by a member that has just
       * been demoted. Drop it at the cohort boundary; members that remain on
       * the flow will re-request any symbol they still need, while the demoted
       * member's subsequent NACKs take the ordinary unicast repair path. */
      (void)cancel_flow_repairs(t, flow, true, 0, 0);
      schedule_source_rekey(t, flow, now);
    }
    materialize_pending_repairs(t, flow, now);
    emit_ready_shadow_observations(t, flow, now);
    drain_paced_payloads(t, flow);
  }
}
