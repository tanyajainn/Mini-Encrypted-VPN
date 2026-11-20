#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstdint>
#include <iostream>
#include <mutex>
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
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(9000);
    if (bind(sock, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
        perror("bind"); close(sock); return 1;
    }
    sockaddr_in client_addr{};
    SessionKeys keys;
    const bool ok = server_handshake(sock, psk, client_addr, keys);
    OPENSSL_cleanse(psk.data(), psk.size());
    if (!ok) {
        std::cerr << "Authenticated X25519 handshake failed.\n";
        close(sock);
        return 1;
    }
    int tun_fd = tun_open("tun1");
    if (tun_fd < 0) { close(sock); return 1; }
    std::cout << "Authenticated tunnel server ready.\n";
    std::mutex peer_mutex;
    std::thread udp_to_tun([&]() {
        uint8_t buffer[4096];
        ReplayWindow window;
        while (true) {
            sockaddr_in sender{};
            socklen_t sender_len = sizeof(sender);
            const ssize_t n = recvfrom(sock, buffer, sizeof(buffer), 0,
                                       reinterpret_cast<sockaddr*>(&sender), &sender_len);
            if (n < 0) { if (errno == EINTR) continue; perror("recvfrom"); break; }
            std::vector<uint8_t> plaintext;
            if (!open_packet(buffer, static_cast<size_t>(n), keys.receive,
                             keys.receive_prefix, window, plaintext)) continue;
            // Authenticated roaming is supported for this single peer only.
            {
                std::lock_guard<std::mutex> lock(peer_mutex);
                client_addr = sender;
            }
            if (write(tun_fd, plaintext.data(), plaintext.size()) < 0)
                perror("write tun1");
        }
    });
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
            sockaddr_in receiver{};
            {
                std::lock_guard<std::mutex> lock(peer_mutex);
                receiver = client_addr;
            }
            if (sendto(sock, frame.data(), frame.size(), 0,
                       reinterpret_cast<sockaddr*>(&receiver), sizeof(receiver)) < 0)
                perror("sendto");
        }
    });
    udp_to_tun.join();
    tun_to_udp.join();
    close(sock);
    close(tun_fd);
    return 0;
}
