#ifndef QLINQ_TUN_DEVICE_H
#define QLINQ_TUN_DEVICE_H

#include <stddef.h>
#include <sys/types.h>

int tun_alloc(char *dev);
int tun_set_mtu(const char *if_name, int mtu);
int configure_ip_and_up(const char *if_name, const char *ip_cidr);
ssize_t tun_read(int fd, void *data, size_t size);
ssize_t tun_write(int fd, const void *data, size_t size);

#endif
