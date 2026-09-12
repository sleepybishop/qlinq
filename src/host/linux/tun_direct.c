#include "cli_parse.h"
#include "qlinq.h"
#include "tun_device.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <net/if.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TUN_MTU 1400U
#define PACKET_CAPACITY 2048U
#define RECEIVE_QUEUE_CAPACITY 64U

typedef struct {
  uint8_t bytes[PACKET_CAPACITY];
  size_t size;
} packet_t;

typedef struct {
  bool listen;
  bool mock;
  bool insecure;
  const char *bind;
  const char *interface_name;
  const char *ip;
  const char *track;
  const char *token;
  const char *cert;
  const char *key;
  const char *ca;
  const char *run_as;
  char peer[256];
  uint16_t port;
  uint64_t run_ms;
  qlinq_delivery_t delivery;
} options_t;

typedef struct {
  packet_t packets[RECEIVE_QUEUE_CAPACITY];
  size_t head;
  size_t count;
  uint64_t dropped;
} receive_queue_t;

static volatile sig_atomic_t stopping;

static void stop_on_signal(int signal_number) {
  (void)signal_number;
  stopping = 1;
}

static uint64_t monotonic_ms(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    return 0;
  return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

static void usage(FILE *out, const char *program) {
  fprintf(out,
          "Usage: %s (--listen PORT | --peer HOST[:PORT]) --auth-token TOKEN "
          "[options]\n"
          "  --bind ADDRESS          Local IP (default: 0.0.0.0 or ::)\n"
          "  --interface NAME        TUN name (default: tun0)\n"
          "  --ip CIDR               TUN address (default: 10.8.0.1/24)\n"
          "  --track NAME            Packet stream (default: tund/tun0)\n"
          "  --mode MODE             fixed-fec (default), rateless, reliable, "
          "datagram\n"
          "  --cert FILE --key FILE  TLS identity (required on listener)\n"
          "  --ca FILE               Trust store for verified peers\n"
          "  --insecure-no-verify    Disable certificate verification (tests "
          "only)\n"
          "  --run-as USER           Drop root privileges after TUN setup\n"
          "  --mock                  Generate/receive packets without a TUN\n"
          "  --run-ms N              Stop mock mode after N milliseconds\n",
          program);
}

static bool parse_options(int argc, char **argv, options_t *options) {
  *options = (options_t){.interface_name = "tun0",
                         .ip = "10.8.0.1/24",
                         .track = "tund/tun0",
                         .port = 8888,
                         .delivery = QLINQ_DELIVERY_FIXED_FEC};
  bool have_role = false;
  for (int i = 1; i < argc; i++) {
    const char *arg = argv[i];
    if (strcmp(arg, "--help") == 0) {
      usage(stdout, argv[0]);
      exit(0);
    }
    if (strcmp(arg, "--mock") == 0) {
      options->mock = true;
    } else if (strcmp(arg, "--insecure-no-verify") == 0) {
      options->insecure = true;
    } else {
      if (++i >= argc)
        return false;
      const char *value = argv[i];
      if (strcmp(arg, "--listen") == 0) {
        uint64_t port;
        if (have_role || !cli_parse_u64(value, UINT16_MAX, &port) || port == 0)
          return false;
        options->listen = have_role = true;
        options->port = (uint16_t)port;
      } else if (strcmp(arg, "--peer") == 0) {
        if (have_role ||
            !cli_parse_endpoint(value, options->peer, sizeof(options->peer),
                                &options->port, NULL))
          return false;
        have_role = true;
      } else if (strcmp(arg, "--bind") == 0) {
        options->bind = value;
      } else if (strcmp(arg, "--interface") == 0) {
        options->interface_name = value;
      } else if (strcmp(arg, "--ip") == 0) {
        options->ip = value;
      } else if (strcmp(arg, "--track") == 0) {
        options->track = value;
      } else if (strcmp(arg, "--auth-token") == 0) {
        options->token = value;
      } else if (strcmp(arg, "--cert") == 0) {
        options->cert = value;
      } else if (strcmp(arg, "--key") == 0) {
        options->key = value;
      } else if (strcmp(arg, "--ca") == 0) {
        options->ca = value;
      } else if (strcmp(arg, "--run-as") == 0) {
        options->run_as = value;
      } else if (strcmp(arg, "--run-ms") == 0) {
        if (!cli_parse_u64(value, UINT32_MAX, &options->run_ms) ||
            options->run_ms == 0)
          return false;
      } else if (strcmp(arg, "--mode") == 0) {
        if (strcmp(value, "fixed-fec") == 0)
          options->delivery = QLINQ_DELIVERY_FIXED_FEC;
        else if (strcmp(value, "rateless") == 0)
          options->delivery = QLINQ_DELIVERY_RATELESS;
        else if (strcmp(value, "reliable") == 0)
          options->delivery = QLINQ_DELIVERY_RELIABLE;
        else if (strcmp(value, "datagram") == 0)
          options->delivery = QLINQ_DELIVERY_DATAGRAM;
        else
          return false;
      } else {
        return false;
      }
    }
  }
  if (!options->token)
    options->token = getenv("QLINQ_AUTH_TOKEN");
  return have_role && options->token && options->token[0] &&
         strlen(options->token) <= UINT16_MAX &&
         strlen(options->interface_name) < IFNAMSIZ &&
         strlen(options->track) > 0 &&
         strlen(options->track) < QLINQ_STREAM_NAME_CAPACITY &&
         (options->cert != NULL) == (options->key != NULL) &&
         (!options->listen || options->cert != NULL) &&
         (options->insecure || options->cert != NULL) &&
         (!options->run_ms || options->mock);
}

static bool drop_privileges(const char *name) {
  struct passwd *account = getpwnam(name);
  if (!account) {
    fprintf(stderr, "unknown user: %s\n", name);
    return false;
  }
  if (account->pw_uid == 0) {
    fprintf(stderr, "--run-as must name an unprivileged user\n");
    return false;
  }
  if (setgroups(0, NULL) != 0 || setgid(account->pw_gid) != 0 ||
      setuid(account->pw_uid) != 0) {
    perror("dropping privileges");
    return false;
  }
  return true;
}

static bool set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL);
  return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static bool valid_packet(const void *data, size_t size) {
  if (!data || size == 0 || size > TUN_MTU)
    return false;
  const uint8_t *bytes = data;
  const uint8_t version = bytes[0] >> 4;
  if (version == 4 && size >= 20) {
    size_t header_size = (size_t)(bytes[0] & 15U) * 4U;
    size_t total_size = ((size_t)bytes[2] << 8) | bytes[3];
    return header_size >= 20 && header_size <= size && total_size == size;
  }
  if (version == 6 && size >= 40) {
    size_t payload_size = ((size_t)bytes[4] << 8) | bytes[5];
    return payload_size + 40U == size;
  }
  return false;
}

static void enqueue_packet(receive_queue_t *queue, const void *data,
                           size_t size) {
  if (!valid_packet(data, size) || queue->count == RECEIVE_QUEUE_CAPACITY) {
    queue->dropped++;
    return;
  }
  size_t tail = (queue->head + queue->count) % RECEIVE_QUEUE_CAPACITY;
  memcpy(queue->packets[tail].bytes, data, size);
  queue->packets[tail].size = size;
  queue->count++;
}

static bool flush_packets(receive_queue_t *queue, int tun_fd) {
  while (queue->count > 0) {
    packet_t *packet = &queue->packets[queue->head];
    ssize_t written = tun_write(tun_fd, packet->bytes, packet->size);
    if (written < 0 && errno == EINTR)
      continue;
    if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
      return true;
    if (written != (ssize_t)packet->size) {
      if (written < 0)
        perror("writing TUN packet");
      else
        fprintf(stderr, "short TUN packet write\n");
      return false;
    }
    queue->head = (queue->head + 1) % RECEIVE_QUEUE_CAPACITY;
    queue->count--;
  }
  return true;
}

static void make_mock_packet(packet_t *packet, uint64_t sequence) {
  packet->size = 64;
  memset(packet->bytes, 0, packet->size);
  packet->bytes[0] = 0x45;
  packet->bytes[2] = 0;
  packet->bytes[3] = (uint8_t)packet->size;
  packet->bytes[8] = 64;
  packet->bytes[9] = 17;
  memcpy(packet->bytes + 20, &sequence, sizeof(sequence));
}

static int run_tunnel(const options_t *options) {
  int tun_fd = -1;
  char interface_name[IFNAMSIZ];
  snprintf(interface_name, sizeof(interface_name), "%s",
           options->interface_name);
  if (!options->mock) {
    if (geteuid() == 0 && !options->run_as) {
      fprintf(stderr, "root execution requires --run-as USER\n");
      return 1;
    }
    if (geteuid() != 0 && options->run_as) {
      fprintf(stderr, "--run-as requires root for initial TUN setup\n");
      return 1;
    }
    tun_fd = tun_alloc(interface_name);
    if (tun_fd < 0)
      return 1;
    if (configure_ip_and_up(interface_name, options->ip) != 0 ||
        tun_set_mtu(interface_name, TUN_MTU) != 0 || !set_nonblocking(tun_fd)) {
      fprintf(stderr, "failed to configure TUN interface %s\n", interface_name);
      close(tun_fd);
      return 1;
    }
    if (geteuid() == 0 && !drop_privileges(options->run_as)) {
      close(tun_fd);
      return 1;
    }
  }

  qlinq_context_t *context = qlinq_context_create(NULL);
  if (!context) {
    fprintf(stderr, "failed to create qlinq context\n");
    if (tun_fd >= 0)
      close(tun_fd);
    return 1;
  }
  const char *bind = options->bind ? options->bind
                     : (!options->listen && strchr(options->peer, ':'))
                         ? "::"
                         : "0.0.0.0";
  qlinq_endpoint_config_t config = {
      .bind_addresses = {bind},
      .bind_address_count = 1,
      .port = options->port,
      .reconnect_enabled = !options->listen,
      .limits = {.max_connections = 1},
      .security = {.shared_secret = options->token,
                   .shared_secret_size = strlen(options->token),
                   .certificate_file = options->cert,
                   .private_key_file = options->key,
                   .trust_store_file = options->ca,
                   .verify_peer = !options->insecure,
                   .allow_insecure_peer = options->insecure}};
  if (!options->listen) {
    config.remote_addresses[0] = options->peer;
    config.remote_address_count = 1;
  }
  qlinq_endpoint_t *endpoint = options->listen
                                   ? qlinq_listen(context, &config)
                                   : qlinq_connect(context, &config);
  qlinq_stream_config_t stream_config = {.content_type = QLINQ_CONTENT_DATA,
                                         .delivery = options->delivery,
                                         .name = options->track};
  qlinq_stream_t *publisher =
      endpoint ? qlinq_publish(endpoint, &stream_config) : NULL;
  qlinq_stream_t *subscriber =
      endpoint ? qlinq_subscribe(endpoint, &stream_config) : NULL;
  if (!endpoint || !publisher || !subscriber) {
    fprintf(stderr, "failed to open direct packet stream (status=%d)\n",
            qlinq_context_last_status(context));
    qlinq_context_destroy(context);
    if (tun_fd >= 0)
      close(tun_fd);
    return 1;
  }
  printf("direct TUN %s, track=%s, mode=%d, interface=%s%s\n",
         options->listen ? "listening" : "connecting", options->track,
         options->delivery, interface_name, options->mock ? " (mock)" : "");

  receive_queue_t queue = {0};
  packet_t pending = {0};
  uint64_t sent = 0, received = 0, partial = 0;
  uint64_t started = monotonic_ms(), last_mock = 0;
  int result = 0;
  while (!stopping &&
         (!options->run_ms || monotonic_ms() - started < options->run_ms)) {
    qlinq_status_t status = qlinq_service(context, 2);
    if (status < QLINQ_STATUS_OK) {
      fprintf(stderr, "qlinq service failed: %d\n", status);
      result = 1;
      break;
    }
    qlinq_event_t event;
    while (qlinq_next_event(context, &event)) {
      if (event.type == QLINQ_EVENT_RECORD && event.stream == subscriber) {
        if (valid_packet(event.record.data, event.record.size)) {
          received++;
          if (!options->mock)
            enqueue_packet(&queue, event.record.data, event.record.size);
        } else {
          queue.dropped++;
        }
      } else if (event.type == QLINQ_EVENT_PEER_READY) {
        fprintf(stderr, "peer %u ready\n", event.peer_id);
      } else if (event.type == QLINQ_EVENT_PEER_DISCONNECTED ||
                 event.type == QLINQ_EVENT_SUBSCRIBER_LEFT) {
        /* Do not replay an old IP packet after a reconnect. */
        pending.size = 0;
      } else if (event.type == QLINQ_EVENT_PEER_REJECTED ||
                 event.type == QLINQ_EVENT_ERROR) {
        fprintf(stderr, "peer error: %s (status=%d)\n",
                event.message ? event.message : "unknown", event.status);
      }
      qlinq_event_release(&event);
    }
    if (tun_fd >= 0 && !flush_packets(&queue, tun_fd)) {
      result = 1;
      break;
    }
    if (!qlinq_stream_is_writable(publisher))
      continue;
    for (size_t batch = 0; batch < 32; batch++) {
      if (pending.size == 0) {
        if (options->mock) {
          uint64_t now = monotonic_ms();
          if (now - last_mock < 100)
            break;
          make_mock_packet(&pending, sent + 1);
          last_mock = now;
        } else {
          ssize_t count = tun_read(tun_fd, pending.bytes, TUN_MTU);
          if (count < 0 && errno == EINTR)
            continue;
          if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
          if (count <= 0) {
            perror("reading TUN packet");
            result = 1;
            stopping = 1;
            break;
          }
          pending.size = (size_t)count;
          if (!valid_packet(pending.bytes, pending.size)) {
            pending.size = 0;
            continue;
          }
        }
      }
      qlinq_record_t record = {.data = pending.bytes,
                               .size = pending.size,
                               .sequence = sent + 1,
                               .priority = 1};
      qlinq_send_result_t send_result = qlinq_stream_send(publisher, &record);
      if (send_result == QLINQ_SEND_WOULD_BLOCK)
        break;
      if (send_result == QLINQ_SEND_NO_SUBSCRIBERS)
        break;
      if (send_result == QLINQ_SEND_INVALID ||
          send_result == QLINQ_SEND_FAILED) {
        fprintf(stderr, "packet send failed: %d\n", send_result);
        result = 1;
        stopping = 1;
        break;
      }
      if (send_result == QLINQ_SEND_PARTIAL)
        partial++;
      sent++;
      pending.size = 0;
      if (options->mock)
        break;
    }
  }
  printf("direct TUN summary: sent=%llu received=%llu partial=%llu "
         "dropped=%llu\n",
         (unsigned long long)sent, (unsigned long long)received,
         (unsigned long long)partial, (unsigned long long)queue.dropped);
  if (options->mock && options->run_ms && (!sent || !received))
    result = 1;
  qlinq_context_destroy(context);
  if (tun_fd >= 0)
    close(tun_fd);
  return result;
}

int main(int argc, char **argv) {
  options_t options;
  setvbuf(stdout, NULL, _IONBF, 0);
  if (!parse_options(argc, argv, &options)) {
    fprintf(stderr, "invalid command line\n");
    usage(stderr, argv[0]);
    return 1;
  }
  signal(SIGINT, stop_on_signal);
  signal(SIGTERM, stop_on_signal);
  return run_tunnel(&options);
}
