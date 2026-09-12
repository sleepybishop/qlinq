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
#ifndef _WIN32
#include <stddef.h>
#include <sys/file.h>
#include <sys/stat.h>
#endif

#define MAX_UDS_CLIENTS 16
#define UDS_FRAME_HEADER_SIZE 5
#define UDS_MAX_QUEUED_BYTES (4U * 1024U * 1024U)

typedef struct {
  int fd;
  moq_track_id_t track_id;
  bool active;
  bool registered;
  uint8_t registration[3 + 63];
  size_t registration_len;
  size_t registration_needed;
  uint8_t frame_header[UDS_FRAME_HEADER_SIZE];
  size_t frame_header_len;
  uint32_t payload_size;
  uint8_t priority;
  uint8_t *payload;
  size_t payload_capacity;
  size_t payload_len;
  bool pending_record;
  uint64_t record_id, progress;
  uint8_t *output;
  size_t output_capacity;
  size_t output_offset;
  size_t output_len;
} uds_client_t;

struct data_uds_t {
  int listen_fd;
  data_uds_callback_t callback;
  data_uds_record_callback_t record_callback;
  uint64_t next_record_id;
#ifndef _WIN32
  int lock_fd;
  struct stat socket_identity;
#endif
  bool socket_bound;
  data_uds_is_ready_callback_t is_ready_cb;
  void *user_data;
  char socket_name[128];
  uds_client_t clients[MAX_UDS_CLIENTS];
};

static bool valid_socket_name(const char *name) {
  if (!name || name[0] == '\0')
    return false;
  for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
    if (!(('a' <= *p && *p <= 'z') || ('A' <= *p && *p <= 'Z') ||
          ('0' <= *p && *p <= '9') || *p == '-' || *p == '_' || *p == '.'))
      return false;
  }
  return strlen(name) <= 80;
}

/* setup UDS address */
static bool setup_uds_addr(struct sockaddr_un *addr, socklen_t *len,
                           const char *name) {
  if (!valid_socket_name(name))
    return false;
  memset(addr, 0, sizeof(*addr));
  addr->sun_family = AF_UNIX;
  int written =
      snprintf(addr->sun_path, sizeof(addr->sun_path), "/tmp/%s.sock", name);
  if (written < 0 || (size_t)written >= sizeof(addr->sun_path))
    return false;
#ifndef _WIN32
  *len =
      (socklen_t)(offsetof(struct sockaddr_un, sun_path) + (size_t)written + 1);
#else
  *len = sizeof(*addr);
#endif
  return true;
}

static bool set_nonblocking(int fd) {
#ifdef _WIN32
  u_long enabled = 1;
  return ioctlsocket(fd, FIONBIO, &enabled) == 0;
#else
  int flags = fcntl(fd, F_GETFL, 0);
  return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

static void close_client(uds_client_t *client) {
  if (!client)
    return;
  if (client->active) {
    shutdown(client->fd, SHUT_RDWR);
    CLOSE_SOCKET(client->fd);
  }
  free(client->payload);
  free(client->output);
  memset(client, 0, sizeof(*client));
  client->fd = -1;
}

static bool flush_client_output(uds_client_t *client) {
  while (client->output_offset < client->output_len) {
    ssize_t ret =
        socket_write(client->fd, client->output + client->output_offset,
                     client->output_len - client->output_offset);
    if (ret > 0) {
      client->output_offset += (size_t)ret;
      continue;
    }
    if (ret < 0 && SOCKET_ERROR_CODE == SOCKET_EINTR)
      continue;
    if (ret < 0 && (SOCKET_ERROR_CODE == SOCKET_EAGAIN ||
                    SOCKET_ERROR_CODE == SOCKET_EWOULDBLOCK))
      return true;
    return false;
  }
  client->output_offset = 0;
  client->output_len = 0;
  return true;
}

static bool queue_client_frame(uds_client_t *client, const uint8_t *buf,
                               size_t size, uint8_t priority) {
  if (size > UINT32_MAX || size > SIZE_MAX - UDS_FRAME_HEADER_SIZE)
    return false;
  size_t pending = client->output_len - client->output_offset;
  size_t frame_size = UDS_FRAME_HEADER_SIZE + size;
  if (frame_size > UDS_MAX_QUEUED_BYTES ||
      pending > UDS_MAX_QUEUED_BYTES - frame_size)
    return false;

  if (client->output_offset > 0 && pending > 0)
    memmove(client->output, client->output + client->output_offset, pending);
  client->output_offset = 0;
  client->output_len = pending;

  size_t needed = pending + frame_size;
  if (needed > client->output_capacity) {
    size_t capacity = client->output_capacity ? client->output_capacity : 4096;
    while (capacity < needed) {
      if (capacity > UDS_MAX_QUEUED_BYTES / 2) {
        capacity = UDS_MAX_QUEUED_BYTES;
        break;
      }
      capacity *= 2;
    }
    uint8_t *output = realloc(client->output, capacity);
    if (!output)
      return false;
    client->output = output;
    client->output_capacity = capacity;
  }

  uint32_t payload_size = (uint32_t)size;
  memcpy(client->output + client->output_len, &payload_size,
         sizeof(payload_size));
  client->output[client->output_len + sizeof(payload_size)] = priority;
  if (size > 0)
    memcpy(client->output + client->output_len + UDS_FRAME_HEADER_SIZE, buf,
           size);
  client->output_len += frame_size;
  return flush_client_output(client);
}

/* A persistent lock inode serializes cooperating instances. Do not unlink the
 * lock file: a waiter could still hold that inode while a third process opens
 * a newly created one. The socket itself is removed only by its current owner.
 */
static void remove_owned_socket(data_uds_t *d) {
  if (!d->socket_bound)
    return;
  struct sockaddr_un addr;
  socklen_t len;
  if (!setup_uds_addr(&addr, &len, d->socket_name))
    return;
#ifndef _WIN32
  struct stat current;
  if (lstat(addr.sun_path, &current) == 0 &&
      current.st_dev == d->socket_identity.st_dev &&
      current.st_ino == d->socket_identity.st_ino && S_ISSOCK(current.st_mode))
    unlink(addr.sun_path);
#else
  _unlink(addr.sun_path);
#endif
}

static data_uds_t *
data_uds_create_impl(const char *socket_name, data_uds_callback_t callback,
                     data_uds_record_callback_t record_callback,
                     data_uds_is_ready_callback_t is_ready_cb,
                     void *user_data) {
  if (!valid_socket_name(socket_name) || (!callback && !record_callback))
    return NULL;
  data_uds_t *d = calloc(1, sizeof(*d));
  if (!d)
    return NULL;
  d->callback = callback;
  d->record_callback = record_callback;
  d->is_ready_cb = is_ready_cb;
  d->user_data = user_data;
  strcpy(d->socket_name, socket_name);
  d->listen_fd = -1;
#ifndef _WIN32
  d->lock_fd = -1;
#endif
  for (int i = 0; i < MAX_UDS_CLIENTS; i++)
    d->clients[i].fd = -1;
  struct sockaddr_un addr;
  socklen_t addr_len;
  if (!setup_uds_addr(&addr, &addr_len, socket_name))
    goto Fail;
#ifndef _WIN32
  char lock_path[sizeof(addr.sun_path) + 6];
  snprintf(lock_path, sizeof(lock_path), "%s.lock", addr.sun_path);
  d->lock_fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
  struct stat lock_stat;
  if (d->lock_fd < 0 || fstat(d->lock_fd, &lock_stat) != 0 ||
      !S_ISREG(lock_stat.st_mode) || lock_stat.st_uid != geteuid() ||
      lock_stat.st_nlink != 1 || flock(d->lock_fd, LOCK_EX | LOCK_NB) != 0)
    goto Fail;
  struct stat existing;
  if (lstat(addr.sun_path, &existing) == 0) {
    if (!S_ISSOCK(existing.st_mode) || existing.st_uid != geteuid())
      goto Fail;
    /* Also protect a live listener from versions predating the lock file. */
    int probe = socket(AF_UNIX, SOCK_STREAM, 0);
    if (probe < 0)
      goto Fail;
    if (!set_nonblocking(probe)) {
      CLOSE_SOCKET(probe);
      goto Fail;
    }
    int result = connect(probe, (struct sockaddr *)&addr, addr_len);
    int error = errno;
    CLOSE_SOCKET(probe);
    if (result == 0 || (error != ECONNREFUSED && error != ENOENT))
      goto Fail;
    struct stat current;
    if (lstat(addr.sun_path, &current) == 0) {
      if (current.st_dev != existing.st_dev ||
          current.st_ino != existing.st_ino || unlink(addr.sun_path) != 0)
        goto Fail;
    } else if (errno != ENOENT) {
      goto Fail;
    }
  } else if (errno != ENOENT) {
    goto Fail;
  }
#endif
  d->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (IS_INVALID_SOCKET(d->listen_fd) || !set_nonblocking(d->listen_fd) ||
      bind(d->listen_fd, (struct sockaddr *)&addr, addr_len) != 0)
    goto Fail;
#ifndef _WIN32
  if (lstat(addr.sun_path, &d->socket_identity) != 0)
    goto Fail;
#endif
  d->socket_bound = true;
#ifndef _WIN32
  if (chmod(addr.sun_path, S_IRUSR | S_IWUSR) != 0)
    goto Fail;
#endif
  if (listen(d->listen_fd, 5) != 0)
    goto Fail;
  fprintf(stderr, "generic data UDS listener initialized on /tmp/%s.sock\n",
          socket_name);
  return d;
Fail:
  data_uds_destroy(d);
  return NULL;
}

data_uds_t *data_uds_create(const char *socket_name,
                            data_uds_callback_t callback,
                            data_uds_is_ready_callback_t is_ready_cb,
                            void *user_data) {
  return data_uds_create_impl(socket_name, callback, NULL, is_ready_cb,
                              user_data);
}

data_uds_t *data_uds_create_ex(const char *socket_name,
                               data_uds_record_callback_t callback,
                               data_uds_is_ready_callback_t is_ready_cb,
                               void *user_data) {
  return data_uds_create_impl(socket_name, NULL, callback, is_ready_cb,
                              user_data);
}

void data_uds_destroy(data_uds_t *d) {
  if (!d)
    return;
  for (int i = 0; i < MAX_UDS_CLIENTS; i++)
    close_client(&d->clients[i]);
  if (d->listen_fd >= 0) {
    shutdown(d->listen_fd, SHUT_RDWR);
    CLOSE_SOCKET(d->listen_fd);
  }
  remove_owned_socket(d);
#ifndef _WIN32
  if (d->lock_fd >= 0)
    close(d->lock_fd);
#endif
  free(d);
}

/* send length-prefixed packet to UDS client matching track_id */
bool data_uds_send(data_uds_t *d, const moq_track_id_t *track_id,
                   const uint8_t *buf, size_t size, uint8_t priority) {
  if (!d)
    return false;

  if (!track_id || (size > 0 && !buf))
    return false;

  int target_idx = -1;
  for (int i = 0; i < MAX_UDS_CLIENTS; i++) {
    if (d->clients[i].active && d->clients[i].registered &&
        d->clients[i].track_id.type == track_id->type &&
        strcmp(d->clients[i].track_id.name, track_id->name) == 0) {
      target_idx = i;
      break;
    }
  }

  /* Fallback: if no strict match and type is MOQ_TRACK_DATA, find any active
   * MOQ_TRACK_DATA client */
  if (target_idx == -1 && track_id->type == MOQ_TRACK_DATA) {
    for (int i = 0; i < MAX_UDS_CLIENTS; i++) {
      if (d->clients[i].active && d->clients[i].registered &&
          d->clients[i].track_id.type == MOQ_TRACK_DATA) {
        target_idx = i;
        break;
      }
    }
  }

  if (target_idx == -1) {
    return false;
  }

  uds_client_t *client = &d->clients[target_idx];
  if (!queue_client_frame(client, buf, size, priority)) {
    close_client(client);
    return false;
  }

  return true;
}

static int read_nonblocking(int fd, uint8_t *buf, size_t *have, size_t needed) {
  while (*have < needed) {
    ssize_t ret = socket_read(fd, buf + *have, needed - *have);
    if (ret > 0) {
      *have += (size_t)ret;
      continue;
    }
    if (ret == 0)
      return -1;
    if (SOCKET_ERROR_CODE == SOCKET_EINTR)
      continue;
    if (SOCKET_ERROR_CODE == SOCKET_EAGAIN ||
        SOCKET_ERROR_CODE == SOCKET_EWOULDBLOCK)
      return 0;
    return -1;
  }
  return 1;
}

static bool valid_track_registration(uint8_t type, uint8_t flags) {
  bool valid_type = type == MOQ_TRACK_VIDEO || type == MOQ_TRACK_AUDIO ||
                    type == MOQ_TRACK_INPUT || type == MOQ_TRACK_TEXT ||
                    type == MOQ_TRACK_DATA || type == MOQ_TRACK_TELEMETRY;
  uint8_t valid_flags = MOQ_TRACK_FLAG_RELIABLE | MOQ_TRACK_FLAG_FEC_ENABLED |
                        MOQ_TRACK_FLAG_FEC_RATELESS;
  return valid_type && (flags & ~valid_flags) == 0;
}

static int process_client_input(data_uds_t *d, uds_client_t *client) {
  for (int frames = 0; frames < 64; frames++) {
    if (!client->registered) {
      if (client->registration_needed == 0)
        client->registration_needed = 3;
      int ret = read_nonblocking(client->fd, client->registration,
                                 &client->registration_len,
                                 client->registration_needed);
      if (ret <= 0)
        return ret;
      if (client->registration_needed == 3) {
        uint8_t name_len = client->registration[2];
        if (name_len > 63 || !valid_track_registration(client->registration[0],
                                                       client->registration[1]))
          return -1;
        client->registration_needed = 3 + name_len;
        if (client->registration_len < client->registration_needed)
          continue;
      }

      uint8_t name_len = client->registration[2];
      client->track_id.type = (moq_track_type_t)client->registration[0];
      client->track_id.flags = client->registration[1];
      memcpy(client->track_id.name, client->registration + 3, name_len);
      client->track_id.name[name_len] = '\0';
      client->registered = true;
      fprintf(stderr,
              "generic data UDS helper connected: track='%s', type=%d, "
              "flags=%d\n",
              client->track_id.name, client->track_id.type,
              client->track_id.flags);
      continue;
    }

    if (d->is_ready_cb && !d->is_ready_cb(d->user_data, &client->track_id))
      return 0;

    int ret =
        read_nonblocking(client->fd, client->frame_header,
                         &client->frame_header_len, UDS_FRAME_HEADER_SIZE);
    if (ret <= 0)
      return ret;

    if (client->payload_size == 0 && client->payload_len == 0) {
      memcpy(&client->payload_size, client->frame_header, sizeof(uint32_t));
      client->priority = client->frame_header[sizeof(uint32_t)];
      size_t max_payload = (client->track_id.flags & MOQ_TRACK_FLAG_RELIABLE)
                               ? TRANSPORT_MAX_RELIABLE_OBJECT_SIZE
                               : TRANSPORT_MAX_FEC_RECORD_SIZE;
      if (client->payload_size == 0 || client->payload_size > max_payload)
        return -1;
      if (client->payload_size > client->payload_capacity) {
        uint8_t *payload = realloc(client->payload, client->payload_size);
        if (!payload)
          return -1;
        client->payload = payload;
        client->payload_capacity = client->payload_size;
      }
    }

    ret = read_nonblocking(client->fd, client->payload, &client->payload_len,
                           client->payload_size);
    if (ret <= 0)
      return ret;

    if (!client->pending_record) {
      client->pending_record = true;
      client->record_id = d->next_record_id++;
      client->progress = 0;
    }
    if (d->record_callback) {
      data_uds_record_t record = {.track_id = &client->track_id,
                                  .data = client->payload,
                                  .size = client->payload_size,
                                  .priority = client->priority,
                                  .id = client->record_id,
                                  .progress = client->progress};
      data_uds_result_t result = d->record_callback(d->user_data, &record);
      client->progress = record.progress;
      if (result == DATA_UDS_RETRY)
        return 0;
      if (result != DATA_UDS_ACCEPTED)
        return -1;
    } else {
      d->callback(d->user_data, &client->track_id, client->payload,
                  client->payload_size, client->priority);
    }
    client->pending_record = false;
    client->frame_header_len = 0;
    client->payload_size = 0;
    client->payload_len = 0;
  }
  return 0;
}

/* process listener and client fds without blocking the transport event loop */
void data_uds_tick(data_uds_t *d) {
  if (!d)
    return;

  struct pollfd fds[MAX_UDS_CLIENTS + 1];
  int client_indices[MAX_UDS_CLIENTS];
  int nfds = 1;
  fds[0] = (struct pollfd){.fd = d->listen_fd, .events = POLLIN};

  for (int i = 0; i < MAX_UDS_CLIENTS; i++) {
    uds_client_t *client = &d->clients[i];
    if (!client->active)
      continue;
    if (client->pending_record && process_client_input(d, client) < 0) {
      close_client(client);
      continue;
    }
    bool is_ready = !client->pending_record &&
                    (!client->registered || !d->is_ready_cb ||
                     d->is_ready_cb(d->user_data, &client->track_id));
    short events = is_ready ? POLLIN : 0;
    if (client->output_offset < client->output_len)
      events |= POLLOUT;
    if (!events)
      continue;
    fds[nfds] = (struct pollfd){.fd = client->fd, .events = events};
    client_indices[nfds - 1] = i;
    nfds++;
  }

  if (poll(fds, nfds, 0) <= 0)
    return;

  if (fds[0].revents & POLLIN) {
    for (;;) {
      int client_fd = accept(d->listen_fd, NULL, NULL);
      if (IS_INVALID_SOCKET(client_fd))
        break;
      int slot = -1;
      for (int i = 0; i < MAX_UDS_CLIENTS; i++) {
        if (!d->clients[i].active) {
          slot = i;
          break;
        }
      }
      if (slot < 0 || !set_nonblocking(client_fd)) {
        CLOSE_SOCKET(client_fd);
        continue;
      }
      uds_client_t *client = &d->clients[slot];
      memset(client, 0, sizeof(*client));
      client->fd = client_fd;
      client->active = true;
      client->registration_needed = 3;
    }
  }

  for (int i = 1; i < nfds; i++) {
    uds_client_t *client = &d->clients[client_indices[i - 1]];
    if (!client->active)
      continue;
    bool close_now = (fds[i].revents & (POLLERR | POLLNVAL)) != 0;
    if (!close_now && (fds[i].revents & POLLOUT) &&
        !flush_client_output(client))
      close_now = true;
    if (!close_now && (fds[i].revents & POLLIN) &&
        process_client_input(d, client) < 0)
      close_now = true;
    if ((fds[i].revents & POLLHUP) && !client->pending_record &&
        !(fds[i].revents & POLLIN))
      close_now = true;
    if (close_now) {
      fprintf(stderr, "generic data UDS helper disconnected\n");
      close_client(client);
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
      bool is_ready = !d->clients[i].pending_record &&
                      (!d->clients[i].registered || !d->is_ready_cb ||
                       d->is_ready_cb(d->user_data, &d->clients[i].track_id));
      fds[count].events = is_ready ? POLLIN : 0;
      if (d->clients[i].output_offset < d->clients[i].output_len)
        fds[count].events |= POLLOUT;
      if (!fds[count].events)
        continue;
      fds[count].revents = 0;
      count++;
    }
  }

  return count;
}
