#include "tun.h"

#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

int tun_open(const std::string& name) {
    int fd = open("/dev/net/tun", O_RDWR);

    if (fd < 0) {
        perror("open /dev/net/tun");
        return -1;
    }

    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("TUNSETIFF");
        close(fd);
        return -1;
    }

    return fd;
}
