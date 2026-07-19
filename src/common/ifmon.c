/* ifmon.c - network interface monitor C library */

#ifndef _WIN32
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
#include <net/if_dl.h>
#include <net/route.h>
#include <sys/sysctl.h>
#endif

#else
#include <iphlpapi.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "ifmon.h"

static void format_mac(const uint8_t *bytes, size_t len, char *out) {
  if (len > 6) {
    len = 6;
  }
  if (len == 0) {
    strncpy(out, "00:00:00:00:00:00", 18);
    return;
  }
  char *p = out;
  for (size_t i = 0; i < len; i++) {
    p += sprintf(p, i == 0 ? "%02X" : ":%02X", bytes[i]);
  }
  for (size_t i = len; i < 6; i++) {
    p += sprintf(p, ":00");
  }
}

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||      \
    defined(__NetBSD__)
static uint8_t count_bits_v4(struct in_addr addr) {
  uint32_t val = ntohl(addr.s_addr);
  uint8_t count = 0;
  while (val & 0x80000000) {
    count++;
    val <<= 1;
  }
  return count;
}

static uint8_t count_bits_v6(struct in6_addr addr) {
  uint8_t count = 0;
  for (int i = 0; i < 16; i++) {
    uint8_t byte = addr.s6_addr[i];
    while (byte & 0x80) {
      count++;
      byte <<= 1;
    }
    if (byte != 0) {
      break;
    }
  }
  return count;
}
#endif

static int is_iface_allowed(const char *name) {
  if (!name || name[0] == '\0')
    return 0;

  /* Linux / Generic */
  if (strncmp(name, "lo", 2) == 0)
    return 0;
  if (strncmp(name, "tun", 3) == 0)
    return 0;
  if (strncmp(name, "tap", 3) == 0)
    return 0;
  if (strncmp(name, "docker", 6) == 0)
    return 0;
  if (strncmp(name, "br-", 3) == 0)
    return 0;

  /* macOS specific */
  if (strncmp(name, "utun", 4) == 0)
    return 0;
  if (strncmp(name, "llw", 3) == 0)
    return 0; /* Apple low latency wifi */
  if (strncmp(name, "awdl", 4) == 0)
    return 0; /* Apple Wireless Direct Link */

  /* Windows specific */
  if (strstr(name, "Loopback") != NULL)
    return 0;
  if (strstr(name, "vEthernet") != NULL)
    return 0;
  if (strstr(name, "Wintun") != NULL)
    return 0;

  return 1;
}

static void generate_update(const ifmon_list_t *prev, const ifmon_list_t *curr,
                            int is_initial, ifmon_update_t *up) {
  memset(up, 0, sizeof(ifmon_update_t));
  up->is_initial = is_initial;
  up->interfaces = curr;

  if (is_initial) {
    return;
  }

  for (int i = 0; i < curr->count; i++) {
    const ifmon_iface_t *curr_if = &curr->ifaces[i];
    const ifmon_iface_t *prev_if = NULL;
    for (int j = 0; j < prev->count; j++) {
      if (prev->ifaces[j].index == curr_if->index) {
        prev_if = &prev->ifaces[j];
        break;
      }
    }

    if (!prev_if) {
      if (up->added_count < IFMON_MAX_INTERFACES) {
        up->added[up->added_count++] = curr_if->index;
      }
    } else {
      int hw_changed = (strcmp(prev_if->hw_addr, curr_if->hw_addr) != 0);

      ifmon_iface_diff_t diff;
      memset(&diff, 0, sizeof(diff));
      diff.index = curr_if->index;
      diff.hw_addr_changed = hw_changed;

      for (int c = 0; c < curr_if->addr_count; c++) {
        const ifmon_addr_t *ca = &curr_if->addrs[c];
        int found = 0;
        for (int p = 0; p < prev_if->addr_count; p++) {
          const ifmon_addr_t *pa = &prev_if->addrs[p];
          if (ca->family == pa->family && ca->prefix_len == pa->prefix_len) {
            if (ca->family == AF_INET && ca->ip.v4.s_addr == pa->ip.v4.s_addr) {
              found = 1;
            } else if (ca->family == AF_INET6 &&
                       memcmp(ca->ip.v6.s6_addr, pa->ip.v6.s6_addr, 16) == 0) {
              found = 1;
            }
          }
          if (found)
            break;
        }
        if (!found) {
          if (diff.addrs_added_count < IFMON_MAX_IPS_PER_IFACE) {
            diff.addrs_added[diff.addrs_added_count++] = *ca;
          }
        }
      }

      for (int p = 0; p < prev_if->addr_count; p++) {
        const ifmon_addr_t *pa = &prev_if->addrs[p];
        int found = 0;
        for (int c = 0; c < curr_if->addr_count; c++) {
          const ifmon_addr_t *ca = &curr_if->addrs[c];
          if (ca->family == pa->family && ca->prefix_len == pa->prefix_len) {
            if (ca->family == AF_INET && ca->ip.v4.s_addr == pa->ip.v4.s_addr) {
              found = 1;
            } else if (ca->family == AF_INET6 &&
                       memcmp(ca->ip.v6.s6_addr, pa->ip.v6.s6_addr, 16) == 0) {
              found = 1;
            }
          }
          if (found)
            break;
        }
        if (!found) {
          if (diff.addrs_removed_count < IFMON_MAX_IPS_PER_IFACE) {
            diff.addrs_removed[diff.addrs_removed_count++] = *pa;
          }
        }
      }

      if (hw_changed || diff.addrs_added_count > 0 ||
          diff.addrs_removed_count > 0) {
        if (up->modified_count < IFMON_MAX_INTERFACES) {
          up->modified[up->modified_count++] = diff;
        }
      }
    }
  }

  for (int p = 0; p < prev->count; p++) {
    const ifmon_iface_t *prev_if = &prev->ifaces[p];
    int found = 0;
    for (int c = 0; c < curr->count; c++) {
      if (curr->ifaces[c].index == prev_if->index) {
        found = 1;
        break;
      }
    }
    if (!found) {
      if (up->removed_count < IFMON_MAX_INTERFACES) {
        up->removed[up->removed_count++] = prev_if->index;
      }
    }
  }
}

#if defined(__linux__)
int ifmon_list_get(ifmon_list_t *list, uint8_t *scratchpad,
                   size_t scratchpad_size) {
  list->count = 0;
  int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (fd < 0)
    return -1;

  struct {
    struct nlmsghdr nlh;
    struct ifinfomsg ifi;
  } req_link;
  memset(&req_link, 0, sizeof(req_link));
  req_link.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
  req_link.nlh.nlmsg_type = RTM_GETLINK;
  req_link.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req_link.nlh.nlmsg_seq = 1;
  req_link.ifi.ifi_family = AF_UNSPEC;
  if (send(fd, &req_link, req_link.nlh.nlmsg_len, 0) < 0) {
    close(fd);
    return -1;
  }

  int done1 = 0;
  for (int iter = 0; iter < 1000; iter++) {
    ssize_t len;
    do {
      len = recv(fd, scratchpad, scratchpad_size, 0);
    } while (len < 0 && errno == EINTR);
    if (len < 0)
      break;
    struct nlmsghdr *nlh;
    for (nlh = (struct nlmsghdr *)scratchpad; NLMSG_OK(nlh, (size_t)len);
         nlh = NLMSG_NEXT(nlh, len)) {
      if (nlh->nlmsg_type == NLMSG_DONE) {
        done1 = 1;
        break;
      }
      if (nlh->nlmsg_type == NLMSG_ERROR) {
        done1 = 1;
        break;
      }
      if (nlh->nlmsg_type == RTM_NEWLINK) {
        struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
        if (!(ifi->ifi_flags & IFF_UP))
          continue;

        if (list->count < IFMON_MAX_INTERFACES) {
          ifmon_iface_t *iface = &list->ifaces[list->count];
          memset(iface, 0, sizeof(ifmon_iface_t));
          iface->index = ifi->ifi_index;
          strncpy(iface->hw_addr, "00:00:00:00:00:00", sizeof(iface->hw_addr));

          struct rtattr *rta = IFLA_RTA(ifi);
          int rta_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
          for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
            if (rta->rta_type == IFLA_IFNAME) {
              strncpy(iface->name, (char *)RTA_DATA(rta),
                      sizeof(iface->name) - 1);
            } else if (rta->rta_type == IFLA_ADDRESS) {
              format_mac((uint8_t *)RTA_DATA(rta), RTA_PAYLOAD(rta),
                         iface->hw_addr);
            }
          }
          if (!is_iface_allowed(iface->name))
            continue;
          list->count++;
        }
      }
    }
    if (done1)
      break;
  }

  struct {
    struct nlmsghdr nlh;
    struct ifaddrmsg ifa;
  } req_addr;
  memset(&req_addr, 0, sizeof(req_addr));
  req_addr.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  req_addr.nlh.nlmsg_type = RTM_GETADDR;
  req_addr.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req_addr.nlh.nlmsg_seq = 2;
  req_addr.ifa.ifa_family = AF_UNSPEC;
  if (send(fd, &req_addr, req_addr.nlh.nlmsg_len, 0) < 0) {
    close(fd);
    return -1;
  }

  int done2 = 0;
  for (int iter = 0; iter < 1000; iter++) {
    ssize_t len;
    do {
      len = recv(fd, scratchpad, scratchpad_size, 0);
    } while (len < 0 && errno == EINTR);
    if (len < 0)
      break;
    struct nlmsghdr *nlh;
    for (nlh = (struct nlmsghdr *)scratchpad; NLMSG_OK(nlh, (size_t)len);
         nlh = NLMSG_NEXT(nlh, len)) {
      if (nlh->nlmsg_type == NLMSG_DONE) {
        done2 = 1;
        break;
      }
      if (nlh->nlmsg_type == NLMSG_ERROR) {
        done2 = 1;
        break;
      }
      if (nlh->nlmsg_type == RTM_NEWADDR) {
        struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);

        ifmon_iface_t *iface = NULL;
        for (int i = 0; i < list->count; i++) {
          if (list->ifaces[i].index == (uint32_t)ifa->ifa_index) {
            iface = &list->ifaces[i];
            break;
          }
        }
        if (!iface)
          continue;

        if (ifa->ifa_family == AF_INET || ifa->ifa_family == AF_INET6) {
          if (iface->addr_count < IFMON_MAX_IPS_PER_IFACE) {
            ifmon_addr_t *addr = &iface->addrs[iface->addr_count];
            addr->family = ifa->ifa_family;
            addr->prefix_len = ifa->ifa_prefixlen;

            struct rtattr *rta = IFA_RTA(ifa);
            int rta_len =
                nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifaddrmsg));
            for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
              if (rta->rta_type == IFA_ADDRESS) {
                if (ifa->ifa_family == AF_INET) {
                  memcpy(&addr->ip.v4, RTA_DATA(rta), sizeof(struct in_addr));
                } else if (ifa->ifa_family == AF_INET6) {
                  memcpy(&addr->ip.v6, RTA_DATA(rta), sizeof(struct in6_addr));
                }
              }
            }
            iface->addr_count++;
          }
        }
      }
    }
    if (done2)
      break;
  }

  for (int i = 0; i < list->count; i++) {
    ifmon_iface_t *iface = &list->ifaces[i];
    uint8_t first_v4_prefix = 0;
    uint8_t first_v6_prefix = 0;
    for (int j = 0; j < iface->addr_count; j++) {
      if (iface->addrs[j].family == AF_INET && iface->addrs[j].prefix_len > 0) {
        first_v4_prefix = iface->addrs[j].prefix_len;
        break;
      }
    }
    for (int j = 0; j < iface->addr_count; j++) {
      if (iface->addrs[j].family == AF_INET6 &&
          iface->addrs[j].prefix_len > 0) {
        first_v6_prefix = iface->addrs[j].prefix_len;
        break;
      }
    }
    for (int j = 0; j < iface->addr_count; j++) {
      if (iface->addrs[j].prefix_len == 0) {
        if (iface->addrs[j].family == AF_INET) {
          iface->addrs[j].prefix_len = first_v4_prefix ? first_v4_prefix : 24;
        } else if (iface->addrs[j].family == AF_INET6) {
          iface->addrs[j].prefix_len = first_v6_prefix ? first_v6_prefix : 64;
        }
      }
    }
  }

  close(fd);
  return 0;
}

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)

#define ROUNDUP(a)                                                             \
  ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

int ifmon_list_get(ifmon_list_t *list, uint8_t *scratchpad,
                   size_t scratchpad_size) {
  list->count = 0;
  int mib[6];
  mib[0] = CTL_NET;
  mib[1] = AF_ROUTE;
  mib[2] = 0;
  mib[3] = 0;
  mib[4] = NET_RT_IFLIST;
  mib[5] = 0;

  size_t len = 0;
  if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
    return -1;

  if (len > scratchpad_size)
    len = scratchpad_size;
  if (sysctl(mib, 6, scratchpad, &len, NULL, 0) < 0)
    return -1;

  uint8_t *next = scratchpad;
  uint8_t *end = scratchpad + len;

  while (next < end) {
    struct rt_msghdr *rtm = (struct rt_msghdr *)next;
    if (rtm->rtm_msglen == 0)
      break;

    if (rtm->rtm_type == RTM_IFINFO) {
      struct if_msghdr *ifm = (struct if_msghdr *)rtm;
      if (!(ifm->ifm_flags & IFF_UP)) {
        next += rtm->rtm_msglen;
        continue;
      }
      if (list->count < IFMON_MAX_INTERFACES) {
        ifmon_iface_t *iface = &list->ifaces[list->count];
        memset(iface, 0, sizeof(*iface));
        iface->index = ifm->ifm_index;
        strncpy(iface->hw_addr, "00:00:00:00:00:00", sizeof(iface->hw_addr));

        struct sockaddr_dl *sdl = (struct sockaddr_dl *)(ifm + 1);
        if (sdl->sdl_family == AF_LINK) {
          int nlen = sdl->sdl_nlen;
          if (nlen >= (int)sizeof(iface->name))
            nlen = sizeof(iface->name) - 1;
          memcpy(iface->name, sdl->sdl_data, nlen);
          iface->name[nlen] = '\0';
          format_mac((uint8_t *)LLADDR(sdl), sdl->sdl_alen, iface->hw_addr);
        }
        if (!is_iface_allowed(iface->name))
          continue;
        list->count++;
      }
    } else if (rtm->rtm_type == RTM_NEWADDR) {
      struct ifa_msghdr *ifam = (struct ifa_msghdr *)rtm;
      ifmon_iface_t *iface = NULL;
      for (int i = 0; i < list->count; i++) {
        if (list->ifaces[i].index == ifam->ifam_index) {
          iface = &list->ifaces[i];
          break;
        }
      }

      if (iface && iface->addr_count < IFMON_MAX_IPS_PER_IFACE) {
        struct sockaddr *sa = (struct sockaddr *)(ifam + 1);
        struct sockaddr *addrs[RTAX_MAX];
        int addrs_present = ifam->ifam_addrs;
        for (int i = 0; i < RTAX_MAX; i++) {
          if (addrs_present & (1 << i)) {
            addrs[i] = sa;
            sa = (struct sockaddr *)((uint8_t *)sa + ROUNDUP(sa->sa_len));
          } else {
            addrs[i] = NULL;
          }
        }

        struct sockaddr *addr = addrs[RTAX_IFA];
        struct sockaddr *netmask = addrs[RTAX_NETMASK];
        if (addr &&
            (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)) {
          ifmon_addr_t *a = &iface->addrs[iface->addr_count];
          a->family = addr->sa_family;

          if (addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)addr;
            a->ip.v4 = sin->sin_addr;
            if (netmask) {
              struct sockaddr_in *msin = (struct sockaddr_in *)netmask;
              a->prefix_len = count_bits_v4(msin->sin_addr);
            }
          } else {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
            a->ip.v6 = sin6->sin6_addr;
            if (netmask) {
              struct sockaddr_in6 *msin6 = (struct sockaddr_in6 *)netmask;
              a->prefix_len = count_bits_v6(msin6->sin6_addr);
            }
          }
          iface->addr_count++;
        }
      }
    }
    next += rtm->rtm_msglen;
  }

  for (int i = 0; i < list->count; i++) {
    ifmon_iface_t *iface = &list->ifaces[i];
    uint8_t first_v4_prefix = 0;
    uint8_t first_v6_prefix = 0;
    for (int j = 0; j < iface->addr_count; j++) {
      if (iface->addrs[j].family == AF_INET && iface->addrs[j].prefix_len > 0) {
        first_v4_prefix = iface->addrs[j].prefix_len;
        break;
      }
    }
    for (int j = 0; j < iface->addr_count; j++) {
      if (iface->addrs[j].family == AF_INET6 &&
          iface->addrs[j].prefix_len > 0) {
        first_v6_prefix = iface->addrs[j].prefix_len;
        break;
      }
    }
    for (int j = 0; j < iface->addr_count; j++) {
      if (iface->addrs[j].prefix_len == 0) {
        if (iface->addrs[j].family == AF_INET) {
          iface->addrs[j].prefix_len = first_v4_prefix ? first_v4_prefix : 24;
        } else if (iface->addrs[j].family == AF_INET6) {
          iface->addrs[j].prefix_len = first_v6_prefix ? first_v6_prefix : 64;
        }
      }
    }
  }

  return 0;
}

#else
int ifmon_list_get(ifmon_list_t *list, uint8_t *scratchpad,
                   size_t scratchpad_size) {
  list->count = 0;
  ULONG size = (ULONG)scratchpad_size;

  IP_ADAPTER_ADDRESSES *addrs = (IP_ADAPTER_ADDRESSES *)scratchpad;

  ULONG res = GetAdaptersAddresses(
      AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, NULL, addrs,
      &size);
  if (res != ERROR_SUCCESS)
    return -1;

  for (IP_ADAPTER_ADDRESSES *curr = addrs; curr != NULL; curr = curr->Next) {
    if (curr->OperStatus != IfOperStatusUp)
      continue;

    uint32_t index = curr->IfIndex;
    if (index == 0)
      index = curr->Ipv6IfIndex;
    if (index == 0)
      continue;

    if (list->count < IFMON_MAX_INTERFACES) {
      ifmon_iface_t *iface = &list->ifaces[list->count];
      memset(iface, 0, sizeof(*iface));
      iface->index = index;

      int name_len =
          WideCharToMultiByte(CP_UTF8, 0, curr->FriendlyName, -1, iface->name,
                              sizeof(iface->name) - 1, NULL, NULL);
      if (name_len > 0) {
        iface->name[name_len] = '\0';
      } else {
        strncpy(iface->name, "", sizeof(iface->name));
      }

      format_mac(curr->PhysicalAddress, curr->PhysicalAddressLength,
                 iface->hw_addr);

      if (!is_iface_allowed(iface->name))
        continue;

      for (IP_ADAPTER_UNICAST_ADDRESS *unicast = curr->FirstUnicastAddress;
           unicast != NULL; unicast = unicast->Next) {
        if (!unicast->Address.lpSockaddr)
          continue;
        int family = unicast->Address.lpSockaddr->sa_family;
        if (family != AF_INET && family != AF_INET6)
          continue;

        if (iface->addr_count < IFMON_MAX_IPS_PER_IFACE) {
          ifmon_addr_t *addr = &iface->addrs[iface->addr_count];
          addr->family = family;
          addr->prefix_len = unicast->OnLinkPrefixLength;
          if (family == AF_INET) {
            struct sockaddr_in *sin =
                (struct sockaddr_in *)unicast->Address.lpSockaddr;
            addr->ip.v4 = sin->sin_addr;
          } else {
            struct sockaddr_in6 *sin6 =
                (struct sockaddr_in6 *)unicast->Address.lpSockaddr;
            addr->ip.v6 = sin6->sin6_addr;
          }
          iface->addr_count++;
        }
      }
      list->count++;
    }
  }
  return 0;
}
#endif

#ifndef _WIN32
static int open_event_socket(void) {
  int fd = -1;
#if defined(__linux__)
  fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (fd >= 0) {
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
      close(fd);
      return -1;
    }
  }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
  fd = socket(AF_ROUTE, SOCK_RAW, 0);
#endif

  if (fd >= 0) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) {
      fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
  }
  return fd;
}

static void drain_socket(int fd) {
  char buf[4096];
  for (int iter = 0; iter < 1000; iter++) {
    ssize_t r;
    do {
      r = recv(fd, buf, sizeof(buf), 0);
    } while (r < 0 && errno == EINTR);
    if (r <= 0)
      break;
  }
}

static void *watcher_thread_func(void *arg) {
  ifmon_watcher_t *w = (ifmon_watcher_t *)arg;
  struct pollfd fds[2];
  fds[0].fd = w->event_fd;
  fds[0].events = POLLIN;
  fds[1].fd = w->stop_pipe[0];
  fds[1].events = POLLIN;

  while (w->running) {
    int ret;
    do {
      ret = poll(fds, 2, -1);
    } while (ret < 0 && errno == EINTR);
    if (ret < 0)
      continue;
    if (fds[1].revents & POLLIN)
      break;
    if (fds[0].revents & POLLIN) {
      drain_socket(w->event_fd);
      if (ifmon_list_get(&w->curr_list, w->scratchpad, sizeof(w->scratchpad)) ==
          0) {
        generate_update(&w->prev_list, &w->curr_list, 0, &w->update);
        if (w->update.added_count > 0 || w->update.removed_count > 0 ||
            w->update.modified_count > 0) {
          w->cb(&w->update, w->userdata);
          w->prev_list = w->curr_list;
        }
      }
    }
  }
  return NULL;
}

int ifmon_watch_start(ifmon_watcher_t *w, ifmon_callback_t cb, void *userdata) {
  memset(w, 0, sizeof(ifmon_watcher_t));
  w->cb = cb;
  w->userdata = userdata;
  w->event_fd = -1;
  w->stop_pipe[0] = -1;
  w->stop_pipe[1] = -1;

  if (ifmon_list_get(&w->prev_list, w->scratchpad, sizeof(w->scratchpad)) ==
      0) {
    generate_update(NULL, &w->prev_list, 1, &w->update);
    cb(&w->update, userdata);
  }

  if (pipe(w->stop_pipe) < 0)
    return -1;

  w->event_fd = open_event_socket();
  if (w->event_fd < 0) {
    close(w->stop_pipe[0]);
    close(w->stop_pipe[1]);
    return -1;
  }

  w->running = 1;
  if (pthread_create(&w->thread, NULL, watcher_thread_func, w) != 0) {
    w->running = 0;
    close(w->event_fd);
    close(w->stop_pipe[0]);
    close(w->stop_pipe[1]);
    return -1;
  }
  return 0;
}

void ifmon_watch_stop(ifmon_watcher_t *w) {
  if (!w)
    return;
  w->running = 0;
  char c = 1;
  (void)write(w->stop_pipe[1], &c, 1);
  pthread_join(w->thread, NULL);
  close(w->stop_pipe[0]);
  close(w->stop_pipe[1]);
  if (w->event_fd >= 0) {
    close(w->event_fd);
  }
}

#else

static VOID
    NETIOAPI_API_ windows_callback(PVOID CallerContext,
                                   PMIB_UNICASTIPADDRESS_ROW Row,
                                   MIB_NOTIFICATION_TYPE NotificationType) {
  ifmon_watcher_t *w = (ifmon_watcher_t *)CallerContext;
  EnterCriticalSection(&w->lock);
  if (ifmon_list_get(&w->curr_list, w->scratchpad, sizeof(w->scratchpad)) ==
      0) {
    generate_update(&w->prev_list, &w->curr_list, 0, &w->update);
    if (w->update.added_count > 0 || w->update.removed_count > 0 ||
        w->update.modified_count > 0) {
      w->cb(&w->update, w->userdata);
      w->prev_list = w->curr_list;
    }
  }
  LeaveCriticalSection(&w->lock);
}

int ifmon_watch_start(ifmon_watcher_t *w, ifmon_callback_t cb, void *userdata) {
  memset(w, 0, sizeof(ifmon_watcher_t));
  w->cb = cb;
  w->userdata = userdata;
  w->notify_handle = INVALID_HANDLE_VALUE;
  InitializeCriticalSection(&w->lock);

  if (ifmon_list_get(&w->prev_list, w->scratchpad, sizeof(w->scratchpad)) ==
      0) {
    generate_update(NULL, &w->prev_list, 1, &w->update);
    cb(&w->update, userdata);
  }

  DWORD res = NotifyUnicastIpAddressChange(AF_UNSPEC, windows_callback, w,
                                           FALSE, &w->notify_handle);
  if (res != NO_ERROR) {
    DeleteCriticalSection(&w->lock);
    return -1;
  }
  return 0;
}

void ifmon_watch_stop(ifmon_watcher_t *w) {
  if (!w)
    return;
  if (w->notify_handle != INVALID_HANDLE_VALUE) {
    CancelMibChangeNotify2(w->notify_handle);
  }
  DeleteCriticalSection(&w->lock);
}
#endif