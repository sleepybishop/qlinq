#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/if.h>
#include <linux/if_tun.h>
#else
#include <net/if.h>
#endif
#include "transport.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/uio.h>

#ifdef __APPLE__
#include <net/if_utun.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#endif

static bool mock_mode = false;
static char dev_name[IFNAMSIZ] = "tun0";
static char socket_name[128] = "qlinq-data";
static char ip_addr[64] = "10.8.0.1/24";
static uint8_t tund_priority = 1;
static char track_name[64] = "";
static bool use_reliable = false;

#ifdef __APPLE__
static int tun_create_by_id(char if_name[IFNAMSIZ], unsigned int id) {
  struct ctl_info ci;
  struct sockaddr_ctl sc;
  int err;
  int fd;

  if ((fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)) == -1) {
    return -1;
  }
  memset(&ci, 0, sizeof(ci));
  snprintf(ci.ctl_name, sizeof(ci.ctl_name), "%s", UTUN_CONTROL_NAME);
  if (ioctl(fd, CTLIOCGINFO, &ci)) {
    err = errno;
    (void)close(fd);
    errno = err;
    return -1;
  }
  memset(&sc, 0, sizeof(sc));
  sc = (struct sockaddr_ctl){
      .sc_id = ci.ctl_id,
      .sc_len = sizeof(sc),
      .sc_family = AF_SYSTEM,
      .ss_sysaddr = AF_SYS_CONTROL,
      .sc_unit = id + 1,
  };
  if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) != 0) {
    err = errno;
    (void)close(fd);
    errno = err;
    return -1;
  }
  snprintf(if_name, IFNAMSIZ, "utun%u", id);

  return fd;
}
#endif

static int tun_create(char if_name[IFNAMSIZ], const char *wanted_name) {
#if defined(__linux__)
  struct ifreq ifr;
  int fd;
  int err;

  fd = open("/dev/net/tun", O_RDWR);
  if (fd == -1) {
    perror("opening /dev/net/tun");
    return -1;
  }
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  snprintf(ifr.ifr_name, IFNAMSIZ, "%s",
           wanted_name == NULL ? "" : wanted_name);
  if (ioctl(fd, TUNSETIFF, &ifr) != 0) {
    err = errno;
    (void)close(fd);
    errno = err;
    perror("ioctl(TUNSETIFF)");
    return -1;
  }
  snprintf(if_name, IFNAMSIZ, "%s", ifr.ifr_name);
  return fd;

#elif defined(__APPLE__)
  unsigned int id;
  int fd;

  if (wanted_name == NULL || *wanted_name == 0) {
    for (id = 0; id < 32; id++) {
      if ((fd = tun_create_by_id(if_name, id)) != -1) {
        return fd;
      }
    }
    return -1;
  }
  if (sscanf(wanted_name, "utun%u", &id) != 1) {
    errno = EINVAL;
    return -1;
  }
  return tun_create_by_id(if_name, id);

#elif defined(__OpenBSD__) || defined(__FreeBSD__) ||                          \
    defined(__DragonFly__) || defined(__NetBSD__)
  char path[64];
  unsigned int id;
  int fd;

  if (wanted_name == NULL || *wanted_name == 0) {
    for (id = 0; id < 32; id++) {
      snprintf(if_name, IFNAMSIZ, "tun%u", id);
      snprintf(path, sizeof(path), "/dev/%s", if_name);
      if ((fd = open(path, O_RDWR)) != -1) {
        return fd;
      }
    }
    return -1;
  }
  snprintf(if_name, IFNAMSIZ, "%s", wanted_name);
  snprintf(path, sizeof(path), "/dev/%s", wanted_name);
  return open(path, O_RDWR);

#else
  char path[64];

  if (wanted_name == NULL) {
    errno = EINVAL;
    return -1;
  }
  snprintf(if_name, IFNAMSIZ, "%s", wanted_name);
  snprintf(path, sizeof(path), "/dev/%s", wanted_name);
  return open(path, O_RDWR);
#endif
}

static int tun_alloc(char *dev) {
  char wanted_name[IFNAMSIZ];
  strncpy(wanted_name, dev, IFNAMSIZ - 1);
  wanted_name[IFNAMSIZ - 1] = '\0';
  return tun_create(dev, wanted_name[0] ? wanted_name : NULL);
}

static int tun_set_mtu(const char *if_name, int mtu) {
  struct ifreq ifr;
  int fd;

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    return -1;
  }
  ifr.ifr_mtu = mtu;
  snprintf(ifr.ifr_name, IFNAMSIZ, "%s", if_name);
  if (ioctl(fd, SIOCSIFMTU, &ifr) != 0) {
    close(fd);
    return -1;
  }
  return close(fd);
}

static ssize_t tun_read(int fd, void *data, size_t size) {
#if !defined(__APPLE__) && !defined(__OpenBSD__)
  return read(fd, data, size);
#else
  ssize_t ret;
  uint32_t family;
  struct iovec iov[2] = {{.iov_base = &family, .iov_len = sizeof(family)},
                         {.iov_base = data, .iov_len = size}};
  ret = readv(fd, iov, 2);
  if (ret <= (ssize_t)0) {
    return -1;
  }
  if (ret <= (ssize_t)sizeof(family)) {
    return 0;
  }
  return ret - sizeof(family);
#endif
}

static ssize_t tun_write(int fd, const void *data, size_t size) {
#if !defined(__APPLE__) && !defined(__OpenBSD__)
  return write(fd, data, size);
#else
  uint32_t family;
  ssize_t ret;
  if (size < 20) {
    return 0;
  }
  switch (*(const uint8_t *)data >> 4) {
  case 4:
    family = htonl(AF_INET);
    break;
  case 6:
    family = htonl(AF_INET6);
    break;
  default:
    errno = EINVAL;
    return -1;
  }
  struct iovec iov[2] = {{.iov_base = &family, .iov_len = sizeof(family)},
                         {.iov_base = (void *)data, .iov_len = size}};
  ret = writev(fd, iov, 2);
  if (ret <= (ssize_t)0) {
    return ret;
  }
  if (ret <= (ssize_t)sizeof(family)) {
    return 0;
  }
  return ret - sizeof(family);
#endif
}

static void setup_uds_addr(struct sockaddr_un *addr, socklen_t *len,
                           const char *name) {
  memset(addr, 0, sizeof(*addr));
  addr->sun_family = AF_UNIX;
  snprintf(addr->sun_path, sizeof(addr->sun_path), "/tmp/%s.sock", name);
  *len = sizeof(addr->sun_family) + strlen(addr->sun_path);
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

/* configure interface ip and bring it up */
static void configure_ip_and_up(const char *if_name, const char *ip_cidr) {
  char ip[64];
  char peer_ip[64];
  strncpy(ip, ip_cidr, sizeof(ip) - 1);
  ip[sizeof(ip) - 1] = '\0';
  char *slash = strchr(ip, '/');
  if (slash) {
    *slash = '\0';
  }

  char *last_dot = strrchr(ip, '.');
  if (last_dot) {
    int last_num = atoi(last_dot + 1);
    int peer_num = (last_num == 1) ? 2 : 1;
    size_t prefix_len = last_dot + 1 - ip;
    strncpy(peer_ip, ip, prefix_len);
    peer_ip[prefix_len] = '\0';
    snprintf(peer_ip + prefix_len, sizeof(peer_ip) - prefix_len, "%d",
             peer_num);
  } else {
    strcpy(peer_ip, "10.8.0.2");
  }

  char cmd[512];
#if defined(__linux__)
  snprintf(cmd, sizeof(cmd), "ip addr add %s peer %s dev %s 2>/dev/null", ip,
           peer_ip, if_name);
  if (system(cmd) != 0) {
  }
  snprintf(cmd, sizeof(cmd), "ip link set dev %s up 2>/dev/null", if_name);
  if (system(cmd) != 0) {
  }
#elif defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__) ||    \
    defined(__DragonFly__) || defined(__NetBSD__)
  snprintf(cmd, sizeof(cmd), "ifconfig %s %s %s up 2>/dev/null", if_name, ip,
           peer_ip);
  if (system(cmd) != 0) {
  }
#endif
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

  printf(
      "initializing qlinq tund (socket=%s interface=%s ip=%s mock=%s)...\n",
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
    configure_ip_and_up(dev_name, ip_addr);
    tun_set_mtu(dev_name, 1400);
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
        setup_uds_addr(&addr, &addr_len, socket_name);
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
        if (write(uds_fd, reg_hdr, 3) != 3 ||
            write(uds_fd, track_name, reg_hdr[2]) != (ssize_t)reg_hdr[2]) {
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
      ssize_t wret = write(uds_fd, &pkt_len, sizeof(pkt_len));
      if (wret < 0) {
        close(uds_fd);
        uds_fd = -1;
        continue;
      }
      wret = write(uds_fd, &tund_priority, sizeof(tund_priority));
      if (wret < 0) {
        close(uds_fd);
        uds_fd = -1;
        continue;
      }
      wret = write(uds_fd, mock_pkt, pkt_len);
      if (wret < 0) {
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
        ssize_t wret = write(uds_fd, &pkt_len, sizeof(pkt_len));
        if (wret < 0) {
          close(uds_fd);
          uds_fd = -1;
          continue;
        }
        wret = write(uds_fd, &tund_priority, sizeof(tund_priority));
        if (wret < 0) {
          close(uds_fd);
          uds_fd = -1;
          continue;
        }
        size_t written = 0;
        bool write_err = false;
        while (written < (size_t)len) {
          wret = write(uds_fd, packet + written, len - written);
          if (wret < 0) {
            if (errno == EINTR)
              continue;
            write_err = true;
            break;
          }
          written += wret;
        }
        if (write_err) {
          close(uds_fd);
          uds_fd = -1;
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
  }

  if (uds_fd != -1) {
    close(uds_fd);
  }
  if (!mock_mode && tun_fd != -1) {
    close(tun_fd);
  }

  return 0;
}
