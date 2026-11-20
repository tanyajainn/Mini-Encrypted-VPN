#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstdint>
#include <iostream>
#include <thread>
#include <vector>
#include "handshake.h"
#include "session.h"
#include "tun.h"

int main() {
    Psk psk{};
    if (!read_psk(std::cin, psk)) {
        std::cerr << "Expected exactly 32 binary bytes of pre-shared key on stdin.\n";
        return 1;
    }
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }
    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(9000);
    if (inet_pton(AF_INET, "172.30.0.1", &server.sin_addr) != 1) {
        close(sock);
        return 1;
    }
    SessionKeys keys;
    const bool ok = client_handshake(sock, server, psk, keys);
    OPENSSL_cleanse(psk.data(), psk.size());
    if (!ok) {
        std::cerr << "Authenticated X25519 handshake failed.\n";
        close(sock);
        return 1;
    }
    int tun_fd = tun_open("tun0");
    if (tun_fd < 0) { close(sock); return 1; }
    // Do not forward packets before the launch script has assigned IP, MTU,
    // routes and raised the interface. Prevents startup EIO on TUN writes.
    if (!tun_wait_up("tun0", 10000)) {
        std::cerr << "tun0 did not become UP within 10 seconds.\n";
        close(tun_fd); close(sock); return 1;
    }
    std::cout << "Authenticated tunnel client ready.\n";

    std::thread tun_to_udp([&]() {
        uint8_t buffer[2000];
        uint64_t sequence = 0;
        while (true) {
            const ssize_t n = read(tun_fd, buffer, sizeof(buffer));
            if (n <= 0) break;
            auto frame = seal_packet(buffer, static_cast<size_t>(n),
                                     keys.send, keys.send_prefix, sequence);
            if (frame.empty()) {
                std::cerr << "Packet encryption failed or key reached packet limit; stopping.\n";
                break;
            }
            if (sendto(sock, frame.data(), frame.size(), 0,
                       reinterpret_cast<sockaddr*>(&server), sizeof(server)) < 0) {
                perror("sendto"); break;
            }
        }
    });
    std::thread udp_to_tun([&]() {
        uint8_t buffer[4096];
        ReplayWindow window;
        while (true) {
            const ssize_t n = recvfrom(sock, buffer, sizeof(buffer), 0, nullptr, nullptr);
            if (n < 0) { if (errno == EINTR) continue; perror("recvfrom"); break; }
            std::vector<uint8_t> plaintext;
            if (!open_packet(buffer, static_cast<size_t>(n), keys.receive,
                             keys.receive_prefix, window, plaintext)) continue;
            if (write(tun_fd, plaintext.data(), plaintext.size()) < 0) {
                perror("write tun0");
                if (errno == EIO || errno == ENETDOWN) continue;
                break;
            }
        }
    });
    tun_to_udp.join();
    udp_to_tun.join();
    close(sock);
    close(tun_fd);
    return 0;
}
