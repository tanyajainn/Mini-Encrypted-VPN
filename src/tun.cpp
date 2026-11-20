#include "tun.h"
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

int tun_open(const std::string& name) {
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) { perror("open /dev/net/tun"); return -1; }
    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("TUNSETIFF"); close(fd); return -1;
    }
    return fd;
}

bool tun_wait_up(const std::string& name, unsigned timeout_ms) {
    if (name.empty() || name.size() >= IFNAMSIZ) return false;
    const int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return false;
    const auto until = std::chrono::steady_clock::now() +
                       std::chrono::milliseconds(timeout_ms);
    bool ready = false;
    do {
        struct ifreq ifr{};
        std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0 &&
            (ifr.ifr_flags & IFF_UP)) { ready = true; break; }
        if (std::chrono::steady_clock::now() >= until) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    } while (true);
    close(sock);
    return ready;
}
