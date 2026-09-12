#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "tun_device.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/if.h>
#include <linux/if_tun.h>
#else
#include <net/if.h>
#endif
#ifdef __APPLE__
#include <net/if_utun.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#endif

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

int tun_alloc(char *dev) {
  char wanted_name[IFNAMSIZ];
  strncpy(wanted_name, dev, IFNAMSIZ - 1);
  wanted_name[IFNAMSIZ - 1] = '\0';
  return tun_create(dev, wanted_name[0] ? wanted_name : NULL);
}

int tun_set_mtu(const char *if_name, int mtu) {
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

ssize_t tun_read(int fd, void *data, size_t size) {
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

ssize_t tun_write(int fd, const void *data, size_t size) {
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

static int run_command(char *const argv[]) {
  pid_t pid = fork();
  if (pid < 0)
    return -1;
  if (pid == 0) {
    int null_fd = open("/dev/null", O_WRONLY);
    if (null_fd >= 0) {
      dup2(null_fd, STDERR_FILENO);
      close(null_fd);
    }
    execvp(argv[0], argv);
    _exit(127);
  }
  int status;
  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR)
      return -1;
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

/* configure interface ip and bring it up */
int configure_ip_and_up(const char *if_name, const char *ip_cidr) {
  char ip[64];
  char cidr[64];
  char peer_ip[64];
  if (!if_name || !ip_cidr || strlen(if_name) >= IFNAMSIZ ||
      strlen(ip_cidr) >= sizeof(cidr))
    return -1;
  strcpy(cidr, ip_cidr);
  strncpy(ip, ip_cidr, sizeof(ip) - 1);
  ip[sizeof(ip) - 1] = '\0';
  char *slash = strchr(ip, '/');
  if (slash) {
    *slash = '\0';
    char *end = NULL;
    long prefix = strtol(slash + 1, &end, 10);
    if (!end || *end != '\0' || prefix < 0 || prefix > 32)
      return -1;
  }

  struct in_addr parsed_ip;
  if (inet_pton(AF_INET, ip, &parsed_ip) != 1)
    return -1;

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

#if defined(__linux__)
  char *addr_argv[] = {"ip",    "addr", "add",           cidr, "peer",
                       peer_ip, "dev",  (char *)if_name, NULL};
  char *link_argv[] = {"ip", "link", "set", "dev", (char *)if_name, "up", NULL};
  if (run_command(addr_argv) != 0 || run_command(link_argv) != 0)
    return -1;
#elif defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__) ||    \
    defined(__DragonFly__) || defined(__NetBSD__)
  char *ifconfig_argv[] = {"ifconfig", (char *)if_name, ip, peer_ip, "up",
                           NULL};
  if (run_command(ifconfig_argv) != 0)
    return -1;
#endif
  return 0;
}
