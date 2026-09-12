#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "portable_sockets.h"
#include "transport.h"
#include "tun_device.h"
#include <stddef.h>

static bool mock_mode = false;
static char dev_name[IFNAMSIZ] = "tun0";
static char socket_name[128] = "qlinq-data";
static char ip_addr[64] = "10.8.0.1/24";
static uint8_t tund_priority = 1;
static char track_name[64] = "";
static bool use_reliable = false;

static bool setup_uds_addr(struct sockaddr_un *addr, socklen_t *len,
                           const char *name) {
  if (!name || name[0] == '\0')
    return false;
  for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
    if (!(('a' <= *p && *p <= 'z') || ('A' <= *p && *p <= 'Z') ||
          ('0' <= *p && *p <= '9') || *p == '-' || *p == '_' || *p == '.'))
      return false;
  }
  memset(addr, 0, sizeof(*addr));
  addr->sun_family = AF_UNIX;
  int written =
      snprintf(addr->sun_path, sizeof(addr->sun_path), "/tmp/%s.sock", name);
  if (written < 0 || (size_t)written >= sizeof(addr->sun_path))
    return false;
  *len =
      (socklen_t)(offsetof(struct sockaddr_un, sun_path) + (size_t)written + 1);
  return true;
}

static bool read_exact(int fd, void *buf, size_t size) {
  size_t read_bytes = 0;
  while (read_bytes < size) {
    ssize_t ret = read(fd, (uint8_t *)buf + read_bytes, size - read_bytes);
    if (ret < 0) {
      if (errno == EINTR) {
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

static bool write_exact(int fd, const void *buf, size_t size) {
  size_t written = 0;
  while (written < size) {
    ssize_t ret =
        socket_write(fd, (const uint8_t *)buf + written, size - written);
    if (ret < 0) {
      if (errno == EINTR)
        continue;
      return false;
    }
    if (ret == 0)
      return false;
    written += (size_t)ret;
  }
  return true;
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--mock") == 0 || strcmp(argv[i], "-m") == 0) {
      mock_mode = true;
    } else if ((strcmp(argv[i], "--socket") == 0 ||
                strcmp(argv[i], "-s") == 0) &&
               i + 1 < argc) {
      strncpy(socket_name, argv[++i], sizeof(socket_name) - 1);
    } else if ((strcmp(argv[i], "--interface") == 0 ||
                strcmp(argv[i], "-i") == 0) &&
               i + 1 < argc) {
      strncpy(dev_name, argv[++i], sizeof(dev_name) - 1);
    } else if ((strcmp(argv[i], "--ip") == 0 || strcmp(argv[i], "-a") == 0) &&
               i + 1 < argc) {
      strncpy(ip_addr, argv[++i], sizeof(ip_addr) - 1);
    } else if ((strcmp(argv[i], "--priority") == 0 ||
                strcmp(argv[i], "-p") == 0) &&
               i + 1 < argc) {
      char *p_str = argv[++i];
      if (strcmp(p_str, "low") == 0) {
        tund_priority = 0;
      } else if (strcmp(p_str, "high") == 0) {
        tund_priority = 2;
      } else {
        tund_priority = 1;
      }
    } else if ((strcmp(argv[i], "--track") == 0 ||
                strcmp(argv[i], "-t") == 0) &&
               i + 1 < argc) {
      strncpy(track_name, argv[++i], sizeof(track_name) - 1);
    } else if (strcmp(argv[i], "--reliable") == 0 ||
               strcmp(argv[i], "-r") == 0) {
      use_reliable = true;
    }
  }

  if (strlen(track_name) == 0) {
    snprintf(track_name, sizeof(track_name), "tund/%s", dev_name);
  }

  printf("initializing qlinq tund (socket=%s interface=%s ip=%s mock=%s)...\n",
         socket_name, dev_name, ip_addr, mock_mode ? "true" : "false");

  int tun_fd = -1;
  if (mock_mode) {
    printf("mock mode active: skipping virtual tun interface allocation\n");
    tun_fd = 1000;
  } else {
    tun_fd = tun_alloc(dev_name);
    if (tun_fd < 0) {
      fprintf(stderr,
              "failed to setup TUN device. make sure you run as root.\n");
      return 1;
    }

    /* bring up interface, set MTU and assign IP */
    if (configure_ip_and_up(dev_name, ip_addr) != 0 ||
        tun_set_mtu(dev_name, 1400) != 0) {
      fprintf(stderr, "failed to configure TUN interface %s\n", dev_name);
      close(tun_fd);
      return 1;
    }
    printf("TUN interface %s configured successfully\n", dev_name);
  }

  int uds_fd = -1;

  while (1) {
    /* self-healing connection to qlinq UDS data socket */
    if (uds_fd == -1) {
      uds_fd = socket(AF_UNIX, SOCK_STREAM, 0);
      if (uds_fd >= 0) {
        struct sockaddr_un addr;
        socklen_t addr_len;
        if (!setup_uds_addr(&addr, &addr_len, socket_name)) {
          fprintf(stderr, "invalid UDS socket name\n");
          close(uds_fd);
          if (!mock_mode && tun_fd != -1)
            close(tun_fd);
          return 1;
        }
        if (connect(uds_fd, (struct sockaddr *)&addr, addr_len) != 0) {
          close(uds_fd);
          uds_fd = -1;
          usleep(500 * 1000);
          continue;
        }
        uint8_t reg_hdr[3];
        reg_hdr[0] = MOQ_TRACK_DATA;
        reg_hdr[1] =
            use_reliable ? MOQ_TRACK_FLAG_RELIABLE : MOQ_TRACK_FLAG_FEC_ENABLED;
        reg_hdr[2] = (uint8_t)strlen(track_name);
        if (!write_exact(uds_fd, reg_hdr, 3) ||
            !write_exact(uds_fd, track_name, reg_hdr[2])) {
          close(uds_fd);
          uds_fd = -1;
          usleep(500 * 1000);
          continue;
        }
        printf("connected to qlinq data socket\n");
      }
    }

    /* asynchronous polling event loop */
    struct pollfd fds[2];
    fds[0].fd = mock_mode ? -1 : tun_fd;
    fds[0].events = POLLIN;
    fds[1].fd = uds_fd;
    fds[1].events = POLLIN;

    /* if mock mode, poll with timeout to generate periodic mock packets */
    int poll_timeout = mock_mode ? 100 : -1;
    int ret = poll(fds, 2, poll_timeout);

    if (ret < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }

    if (mock_mode && ret == 0) {
      /* mock mode timeout: generate and send mock IP packet */
      static uint8_t mock_pkt[64];
      static uint32_t seq = 0;
      memset(mock_pkt, 0, sizeof(mock_pkt));
      mock_pkt[0] = 0x45; /* IPv4 */
      mock_pkt[1] = 0x00;
      mock_pkt[2] = 0; /* size */
      mock_pkt[3] = 64;
      seq++;
      mock_pkt[4] = (uint8_t)(seq & 0xFF);
      mock_pkt[5] = (uint8_t)((seq >> 8) & 0xFF);

      uint32_t pkt_len = sizeof(mock_pkt);
      if (!write_exact(uds_fd, &pkt_len, sizeof(pkt_len))) {
        close(uds_fd);
        uds_fd = -1;
        continue;
      }
      if (!write_exact(uds_fd, &tund_priority, sizeof(tund_priority))) {
        close(uds_fd);
        uds_fd = -1;
        continue;
      }
      if (!write_exact(uds_fd, mock_pkt, pkt_len)) {
        close(uds_fd);
        uds_fd = -1;
        continue;
      }
      printf("MOCK: transmitted mock packet seq=%u to UDS with priority=%d\n",
             seq, tund_priority);
      continue;
    }

    if (fds[0].revents & POLLIN) {
      /* read packet from TUN interface, write to UDS */
      uint8_t packet[2048];
      ssize_t len = tun_read(tun_fd, packet, sizeof(packet));
      if (len > 0 && uds_fd != -1) {
        uint32_t pkt_len = (uint32_t)len;
        if (!write_exact(uds_fd, &pkt_len, sizeof(pkt_len)) ||
            !write_exact(uds_fd, &tund_priority, sizeof(tund_priority)) ||
            !write_exact(uds_fd, packet, (size_t)len)) {
          close(uds_fd);
          uds_fd = -1;
          continue;
        }
      }
    }

    if (fds[1].revents & POLLIN) {
      /* read packet from UDS, write to TUN interface */
      uint32_t pkt_len = 0;
      if (!read_exact(uds_fd, &pkt_len, sizeof(pkt_len))) {
        close(uds_fd);
        uds_fd = -1;
        continue;
      }

      uint8_t rx_priority = 1;
      if (!read_exact(uds_fd, &rx_priority, sizeof(rx_priority))) {
        close(uds_fd);
        uds_fd = -1;
        continue;
      }

      uint8_t packet[2048];
      if (pkt_len > sizeof(packet)) {
        /* drain and discard too-large packet */
        uint8_t discard[1024];
        size_t remaining = pkt_len;
        while (remaining > 0) {
          size_t chunk =
              remaining > sizeof(discard) ? sizeof(discard) : remaining;
          if (!read_exact(uds_fd, discard, chunk)) {
            break;
          }
          remaining -= chunk;
        }
        close(uds_fd);
        uds_fd = -1;
        continue;
      }

      if (!read_exact(uds_fd, packet, pkt_len)) {
        close(uds_fd);
        uds_fd = -1;
        continue;
      }

      if (mock_mode) {
        uint32_t rx_seq = ((uint32_t)packet[4]) | ((uint32_t)packet[5] << 8);
        printf("MOCK: received packet starting with 0x%02x seq=%u size=%u "
               "priority=%d\n",
               packet[0], rx_seq, pkt_len, rx_priority);
      } else {
        /* write packet to virtual TUN interface */
        while (1) {
          ssize_t wret = tun_write(tun_fd, packet, pkt_len);
          if (wret < 0) {
            if (errno == EINTR)
              continue;
            fprintf(stderr,
                    "tund: tun_write failed, len=%u, error: %s (errno=%d)\n",
                    pkt_len, strerror(errno), errno);
          }
          break;
        }
      }
    }

    if (uds_fd != -1 && (fds[1].revents & (POLLHUP | POLLERR | POLLNVAL))) {
      close(uds_fd);
      uds_fd = -1;
    }
  }

  if (uds_fd != -1) {
    close(uds_fd);
  }
  if (!mock_mode && tun_fd != -1) {
    close(tun_fd);
  }

  return 0;
}
