#include <arpa/inet.h>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include "session.h"
#include "tun.h"

int main() {
    SessionKeys keys;
    if (!keys.read_from(std::cin, true)) {
        std::cerr << "Expected 64 bytes of fresh session key material on stdin.\n";
        return 1;
    }
    int tun_fd = tun_open("tun1");

    if (tun_fd < 0) {
        std::cerr << "Failed to open tun1\n";
        return 1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        perror("socket");
        return 1;
    }

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(9000);

    if (bind(
            sock,
            reinterpret_cast<sockaddr*>(&server),
            sizeof(server)) < 0) {
        perror("bind");
        close(sock);
        close(tun_fd);
        return 1;
    }

    std::cout << "Bidirectional VPN server started.\n";

    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    bool client_known = false;

    std::mutex client_mutex;

    // UDP -> TUN
    std::thread udp_to_tun([&]() {
        uint8_t buffer[4096];
        ReplayWindow window;

        while (true) {
            sockaddr_in sender{};
            socklen_t sender_len = sizeof(sender);

            ssize_t n = recvfrom(
                sock,
                buffer,
                sizeof(buffer),
                0,
                reinterpret_cast<sockaddr*>(&sender),
                &sender_len);

            if (n < 0) {
                if (errno == EINTR) continue;
                perror("recvfrom");
                break;
            }
            std::vector<uint8_t> plaintext;
            if (!open_packet(buffer, static_cast<size_t>(n), keys.receive, window, plaintext))
                continue;

            {
                std::lock_guard<std::mutex> lock(client_mutex);
                client_addr = sender;
                client_len = sender_len;
                client_known = true;
            }

            ssize_t written = write(
                tun_fd,
                plaintext.data(),
                plaintext.size());

            if (written < 0) {
                perror("write tun1");
                continue;
            }

            std::cout << "UDP -> TUN: "
                      << written
                      << " bytes\n";
        }
    });

    // TUN -> UDP
    std::thread tun_to_udp([&]() {
        uint8_t buffer[2000];
        uint64_t sequence = 0;

        while (true) {
            ssize_t n = read(
                tun_fd,
                buffer,
                sizeof(buffer));

            if (n <= 0) {
                perror("read tun1");
                break;
            }

            {
                std::lock_guard<std::mutex> lock(client_mutex);

                if (!client_known) {
                    std::cerr << "No VPN client known yet.\n";
                    continue;
                }
            }

            auto data = seal_packet(buffer, static_cast<size_t>(n), keys.send, sequence);
            if (data.empty()) {
                std::cerr << "Encryption failed.\n";
                continue;
            }

            std::lock_guard<std::mutex> lock(client_mutex);

            if (!client_known)
                continue;

            if (sendto(
                    sock,
                    data.data(),
                    data.size(),
                    0,
                    reinterpret_cast<sockaddr*>(&client_addr),
                    client_len) < 0) {
                perror("sendto");
                continue;
            }

            std::cout << "TUN -> UDP: "
                      << n
                      << " bytes\n";
        }
    });

    udp_to_tun.join();
    tun_to_udp.join();

    close(sock);
    close(tun_fd);

    return 0;
}
