#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

int main() {
    int fd = open("/dev/net/tun", O_RDWR);

    if (fd < 0) {
        perror("open /dev/net/tun");
        return 1;
    }

    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    std::strncpy(ifr.ifr_name, "tun0", IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("TUNSETIFF");
        close(fd);
        return 1;
    }

    std::cout << "TUN interface opened: " << ifr.ifr_name << '\n';
    std::cout << "Waiting for an IP packet...\n";

    unsigned char buffer[2000];

    ssize_t n = read(fd, buffer, sizeof(buffer));

    if (n < 0) {
        perror("read");
        close(fd);
        return 1;
    }

    std::cout << "Received " << n << " bytes from TUN.\n";

    close(fd);
    return 0;
}
