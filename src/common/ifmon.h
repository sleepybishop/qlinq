/* ifmon.h - network interface monitor C library */

#ifndef IFMON_H
#define IFMON_H

#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <pthread.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define IFMON_MAX_INTERFACES 16
#define IFMON_MAX_IPS_PER_IFACE 16

/* an IP address (v4 or v6) paired with its prefix length */
typedef struct ifmon_addr {
  int family; /* AF_INET or AF_INET6 */
  union {
    struct in_addr v4;
    struct in6_addr v6;
  } ip;
  uint8_t prefix_len;
} ifmon_addr_t;

/* one network interface at a point in time */
typedef struct ifmon_iface {
  uint32_t index;   /* platform interface index */
  char name[64];    /* interface name (null-terminated) */
  char hw_addr[18]; /* MAC as "AA:BB:CC:DD:EE:FF\0" */
  int is_up;        /* 1 if interface is UP & RUNNING, 0 if link/carrier down */
  ifmon_addr_t addrs[IFMON_MAX_IPS_PER_IFACE];
  int addr_count;
} ifmon_iface_t;

/* snapshot */
typedef struct ifmon_list {
  ifmon_iface_t ifaces[IFMON_MAX_INTERFACES];
  int count; /* number of interfaces */
} ifmon_list_t;

/* diff for a single interface */
typedef struct ifmon_iface_diff {
  uint32_t index;
  int hw_addr_changed;
  int link_state_changed; /* 1 if link state (is_up) changed */
  int is_up;              /* new link state (1=UP, 0=DOWN) */
  ifmon_addr_t addrs_added[IFMON_MAX_IPS_PER_IFACE];
  int addrs_added_count;
  ifmon_addr_t addrs_removed[IFMON_MAX_IPS_PER_IFACE];
  int addrs_removed_count;
} ifmon_iface_diff_t;

/* update delivered to the callback */
typedef struct ifmon_update {
  int is_initial;                       /* 1 on the very first callback */
  const ifmon_list_t *interfaces;       /* current snapshot */
  uint32_t added[IFMON_MAX_INTERFACES]; /* array of added ifindex values */
  int added_count;
  uint32_t removed[IFMON_MAX_INTERFACES]; /* array of removed ifindex values */
  int removed_count;
  ifmon_iface_diff_t modified[IFMON_MAX_INTERFACES]; /* per-interface diffs */
  int modified_count;
} ifmon_update_t;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||      \
    defined(__NetBSD__)
#define IFMON_SCRATCHPAD_SIZE 32768
#elif defined(_WIN32)
#define IFMON_SCRATCHPAD_SIZE 16384
#else
#define IFMON_SCRATCHPAD_SIZE 8192
#endif

/* callback invoked for each interface update */
typedef void (*ifmon_callback_t)(const ifmon_update_t *update, void *userdata);

/* all state wrapped in a single struct */
typedef struct ifmon_watcher {
  ifmon_callback_t cb;
  void *userdata;
  ifmon_list_t prev_list;
  ifmon_list_t curr_list;
  ifmon_update_t update;
  uint8_t scratchpad[IFMON_SCRATCHPAD_SIZE];
#ifndef _WIN32
  pthread_t thread;
  int stop_pipe[2];
  int event_fd;
  volatile int running;
#else
  HANDLE notify_handle;
  CRITICAL_SECTION lock;
#endif
} ifmon_watcher_t;

/* populate a snapshot into the caller's struct */
int ifmon_list_get(ifmon_list_t *list, uint8_t *scratchpad,
                   size_t scratchpad_size);

/* begin watching for interface changes. caller keeps watcher alive. */
int ifmon_watch_start(ifmon_watcher_t *w, ifmon_callback_t cb, void *userdata);

/* stop watching */
void ifmon_watch_stop(ifmon_watcher_t *w);

#ifdef __cplusplus
}
#endif

#endif /* IFMON_H */
