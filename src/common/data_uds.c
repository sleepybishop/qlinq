/* data_uds.c */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "data_uds.h"
#include "portable_sockets.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_UDS_CLIENTS 16

typedef struct {
  int fd;
  moq_track_id_t track_id;
  bool active;
} uds_client_t;

struct data_uds_t {
  int listen_fd;
  data_uds_callback_t callback;
  data_uds_is_ready_callback_t is_ready_cb;
  void *user_data;
  char socket_name[128];
  uds_client_t clients[MAX_UDS_CLIENTS];
  uint8_t *payload_buf;
  size_t payload_buf_capacity;
};

/* setup UDS address */
static void setup_uds_addr(struct sockaddr_un *addr, socklen_t *len,
                           const char *name) {
  memset(addr, 0, sizeof(*addr));
  addr->sun_family = AF_UNIX;
  snprintf(addr->sun_path, sizeof(addr->sun_path), "/tmp/%s.sock", name);
  *len = sizeof(addr->sun_family) + strlen(addr->sun_path);
}

/* read exact number of bytes, blocking briefly if socket is non-blocking */
static bool read_exact_timeout(int fd, void *buf, size_t size) {
  size_t read_bytes = 0;
  while (read_bytes < size) {
    ssize_t ret =
        socket_read(fd, (uint8_t *)buf + read_bytes, size - read_bytes);
    if (ret < 0) {
      if (SOCKET_ERROR_CODE == SOCKET_EINTR) {
        continue;
      }
      if (SOCKET_ERROR_CODE == SOCKET_EAGAIN ||
          SOCKET_ERROR_CODE == SOCKET_EWOULDBLOCK) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        int p = poll(&pfd, 1, 10); /* block briefly for 10ms */
        if (p <= 0) {
          if (p < 0 && SOCKET_ERROR_CODE == SOCKET_EINTR) {
            continue;
          }
          return false;
        }
        continue;
      }
      return false;
    }
    if (ret == 0) {
      return false;
    }
    read_bytes += ret;
  }
  return true;
}

/* write exact number of bytes, blocking briefly if socket is non-blocking */
static bool write_exact_timeout(int fd, const void *buf, size_t size) {
  size_t written = 0;
  while (written < size) {
    ssize_t ret =
        socket_write(fd, (const uint8_t *)buf + written, size - written);
    if (ret < 0) {
      if (SOCKET_ERROR_CODE == SOCKET_EINTR) {
        continue;
      }
      if (SOCKET_ERROR_CODE == SOCKET_EAGAIN ||
          SOCKET_ERROR_CODE == SOCKET_EWOULDBLOCK) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        int p = poll(&pfd, 1, 10); /* block briefly for 10ms */
        if (p <= 0) {
          if (p < 0 && SOCKET_ERROR_CODE == SOCKET_EINTR) {
            continue;
          }
          return false;
        }
        continue;
      }
      return false;
    }
    written += ret;
  }
  return true;
}

/* create UDS data socket listener */
data_uds_t *data_uds_create(const char *socket_name,
                            data_uds_callback_t callback,
                            data_uds_is_ready_callback_t is_ready_cb,
                            void *user_data) {
  data_uds_t *d = calloc(1, sizeof(data_uds_t));
  if (!d)
    return NULL;

  d->callback = callback;
  d->is_ready_cb = is_ready_cb;
  d->user_data = user_data;
  strncpy(d->socket_name, socket_name, sizeof(d->socket_name) - 1);

  d->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (d->listen_fd < 0) {
    free(d);
    return NULL;
  }

  int flags = fcntl(d->listen_fd, F_GETFL, 0);
  if (flags >= 0) {
    fcntl(d->listen_fd, F_SETFL, flags | O_NONBLOCK);
  }

  struct sockaddr_un addr;
  socklen_t addr_len;
  setup_uds_addr(&addr, &addr_len, socket_name);
#ifndef _WIN32
  unlink(addr.sun_path);
#else
  _unlink(addr.sun_path);
#endif

  if (bind(d->listen_fd, (struct sockaddr *)&addr, addr_len) != 0) {
    CLOSE_SOCKET(d->listen_fd);
    free(d);
    return NULL;
  }

  if (listen(d->listen_fd, 5) != 0) {
    CLOSE_SOCKET(d->listen_fd);
    free(d);
    return NULL;
  }

  fprintf(stderr, "generic data UDS listener initialized on /tmp/%s.sock\n",
          socket_name);
  return d;
}

/* destroy UDS data socket listener */
void data_uds_destroy(data_uds_t *d) {
  if (d) {
    for (int i = 0; i < MAX_UDS_CLIENTS; i++) {
      if (d->clients[i].active) {
        shutdown(d->clients[i].fd, SHUT_RDWR);
        CLOSE_SOCKET(d->clients[i].fd);
        d->clients[i].active = false;
      }
    }

    shutdown(d->listen_fd, SHUT_RDWR);
    CLOSE_SOCKET(d->listen_fd);

    struct sockaddr_un addr;
    socklen_t addr_len;
    setup_uds_addr(&addr, &addr_len, d->socket_name);
#ifndef _WIN32
    unlink(addr.sun_path);
#else
    _unlink(addr.sun_path);
#endif

    if (d->payload_buf) {
      free(d->payload_buf);
    }
    free(d);
  }
}

/* send length-prefixed packet to UDS client matching track_id */
bool data_uds_send(data_uds_t *d, const moq_track_id_t *track_id,
                   const uint8_t *buf, size_t size, uint8_t priority) {
  if (!d)
    return false;

  int target_fd = -1;
  for (int i = 0; i < MAX_UDS_CLIENTS; i++) {
    if (d->clients[i].active && d->clients[i].track_id.type == track_id->type &&
        strcmp(d->clients[i].track_id.name, track_id->name) == 0) {
      target_fd = d->clients[i].fd;
      break;
    }
  }

  /* Fallback: if no strict match and type is MOQ_TRACK_DATA, find any active
   * MOQ_TRACK_DATA client */
  if (target_fd == -1 && track_id->type == MOQ_TRACK_DATA) {
    for (int i = 0; i < MAX_UDS_CLIENTS; i++) {
      if (d->clients[i].active &&
          d->clients[i].track_id.type == MOQ_TRACK_DATA) {
        target_fd = d->clients[i].fd;
        break;
      }
    }
  }

  if (target_fd == -1) {
    return false;
  }

  uint32_t payload_size = (uint32_t)size;
  if (!write_exact_timeout(target_fd, &payload_size, sizeof(payload_size))) {
    return false;
  }

  if (!write_exact_timeout(target_fd, &priority, sizeof(priority))) {
    return false;
  }

  if (!write_exact_timeout(target_fd, buf, size)) {
    return false;
  }

  return true;
}

/* process listener and client fds in a non-blocking manner */
void data_uds_tick(data_uds_t *d) {
  if (!d) {
    return;
  }

  struct pollfd fds[MAX_UDS_CLIENTS + 1];
  int client_indices[MAX_UDS_CLIENTS];
  int nfds = 1;

  fds[0].fd = d->listen_fd;
  fds[0].events = POLLIN;
  fds[0].revents = 0;

  for (int i = 0; i < MAX_UDS_CLIENTS; i++) {
    if (d->clients[i].active) {
      bool is_ready = true;
      if (d->is_ready_cb) {
        is_ready = d->is_ready_cb(d->user_data, &d->clients[i].track_id);
      }
      fds[nfds].fd = d->clients[i].fd;
      fds[nfds].events = is_ready ? POLLIN : 0;
      fds[nfds].revents = 0;
      client_indices[nfds - 1] = i;
      nfds++;
    }
  }

  int ret = poll(fds, nfds, 0);
  if (ret <= 0) {
    return;
  }

  /* check listener for new connections */
  if (fds[0].revents & POLLIN) {
    int client_fd = accept(d->listen_fd, NULL, NULL);
    if (client_fd >= 0) {
      int flags = fcntl(client_fd, F_GETFL, 0);
      if (flags >= 0) {
        fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
      }
      uint8_t reg_hdr[3];
      if (read_exact_timeout(client_fd, reg_hdr, 3)) {
        uint8_t track_type = reg_hdr[0];
        uint8_t flags_val = reg_hdr[1];
        uint8_t name_len = reg_hdr[2];
        char name[64];
        size_t copy_len = (name_len < 63) ? name_len : 63;
        if (read_exact_timeout(client_fd, name, name_len)) {
          name[copy_len] = '\0';
          int slot = -1;
          for (int i = 0; i < MAX_UDS_CLIENTS; i++) {
            if (!d->clients[i].active) {
              slot = i;
              break;
            }
          }
          if (slot != -1) {
            d->clients[slot].fd = client_fd;
            d->clients[slot].track_id.type = (moq_track_type_t)track_type;
            d->clients[slot].track_id.flags = flags_val;
            strcpy(d->clients[slot].track_id.name, name);
            d->clients[slot].active = true;
            fprintf(stderr,
                    "generic data UDS helper connected: track='%s', type=%d, "
                    "flags=%d\n",
                    name, track_type, flags_val);
          } else {
            CLOSE_SOCKET(client_fd);
          }
        } else {
          CLOSE_SOCKET(client_fd);
        }
      } else {
        CLOSE_SOCKET(client_fd);
      }
    }
  }

  /* check client sockets for data */
  for (int i = 1; i < nfds; i++) {
    if (fds[i].revents & POLLIN) {
      int idx = client_indices[i - 1];
      int client_fd = d->clients[idx].active ? d->clients[idx].fd : -1;
      moq_track_id_t track_id = d->clients[idx].track_id;

      if (client_fd == -1) {
        continue;
      }

      uint32_t payload_size = 0;
      uint8_t priority = 1;
      bool closed = false;

      if (!read_exact_timeout(client_fd, &payload_size, sizeof(payload_size))) {
        closed = true;
      } else if (!read_exact_timeout(client_fd, &priority, sizeof(priority))) {
        closed = true;
      } else {
        if (payload_size > 0) {
          if (payload_size > d->payload_buf_capacity) {
            d->payload_buf_capacity = payload_size;
            d->payload_buf = realloc(d->payload_buf, payload_size);
          }
          if (!read_exact_timeout(client_fd, d->payload_buf, payload_size)) {
            closed = true;
          }
        }
      }

      if (closed) {
        fprintf(stderr, "generic data UDS helper disconnected\n");
        if (d->clients[idx].active) {
          CLOSE_SOCKET(d->clients[idx].fd);
          d->clients[idx].active = false;
        }
      } else {
        if (payload_size > 0) {
          d->callback(d->user_data, &track_id, d->payload_buf, payload_size,
                      priority);
        }
      }
    }
  }
}

size_t data_uds_get_poll_fds(data_uds_t *d, struct pollfd *fds,
                             size_t max_fds) {
  if (!d || !fds)
    return 0;

  size_t count = 0;
  if (d->listen_fd >= 0 && count < max_fds) {
    fds[count].fd = d->listen_fd;
    fds[count].events = POLLIN;
    fds[count].revents = 0;
    count++;
  }

  for (size_t i = 0; i < MAX_UDS_CLIENTS && count < max_fds; i++) {
    if (d->clients[i].active && d->clients[i].fd >= 0 && count < max_fds) {
      fds[count].fd = d->clients[i].fd;
      fds[count].events = POLLIN;
      fds[count].revents = 0;
      count++;
    }
  }

  return count;
}
