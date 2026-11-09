#include <arpa/inet.h>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <thread>
#include <vector>

#include "session.h"
#include "tun.h"

int main() {
    SessionKeys keys;
    if (!keys.read_from(std::cin, false)) {
        std::cerr << "Expected 64 bytes of fresh session key material on stdin.\n";
        return 1;
    }
    int tun_fd = tun_open("tun0");

    if (tun_fd < 0)
        return 1;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        perror("socket");
        return 1;
    }

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(9000);

    if (inet_pton(AF_INET, "172.30.0.1", &server.sin_addr) != 1) {
        std::cerr << "Invalid server address\n";
        return 1;
    }

    std::cout << "Bidirectional VPN client started.\n";

    // TUN -> encrypted UDP
    std::thread tun_to_udp([&]() {
        uint8_t buffer[2000];
        uint64_t sequence = 0;

        while (true) {
            ssize_t n = read(tun_fd, buffer, sizeof(buffer));

            if (n <= 0)
                break;

            auto data = seal_packet(buffer, static_cast<size_t>(n), keys.send, sequence);
            if (data.empty()) {
                std::cerr << "Encryption failed.\n";
                continue;
            }

            if (sendto(
                    sock,
                    data.data(),
                    data.size(),
                    0,
                    reinterpret_cast<sockaddr*>(&server),
                    sizeof(server)) < 0) {
                perror("sendto");
                break;
            }

            std::cout << "TUN -> UDP: "
                      << n << " bytes\n";
        }
    });

    // UDP -> TUN
    std::thread udp_to_tun([&]() {
        uint8_t buffer[4096];
        ReplayWindow window;

        while (true) {
            ssize_t n = recvfrom(
                sock,
                buffer,
                sizeof(buffer),
                0,
                nullptr,
                nullptr);

            if (n < 0) {
                if (errno == EINTR) continue;
                perror("recvfrom");
                break;
            }
            std::vector<uint8_t> plaintext;
            if (!open_packet(buffer, static_cast<size_t>(n), keys.receive, window, plaintext))
                continue;

            if (write(
                    tun_fd,
                    plaintext.data(),
                    plaintext.size()) < 0) {
                perror("write tun0");
                break;
            }

            std::cout << "UDP -> TUN: "
                      << plaintext.size()
                      << " bytes\n";
        }
    });

    tun_to_udp.join();
    udp_to_tun.join();

    close(sock);
    close(tun_fd);

    return 0;
}
