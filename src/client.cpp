#include <arpa/inet.h>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <thread>
#include <vector>

#include "crypto.h"
#include "packet.h"
#include "tun.h"

const std::vector<uint8_t> KEY = {
    0x10, 0x21, 0x32, 0x43,
    0x54, 0x65, 0x76, 0x87,
    0x98, 0xa9, 0xba, 0xcb,
    0xdc, 0xed, 0xfe, 0x0f,
    0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc,
    0xdd, 0xee, 0xff, 0x00
};

int main() {
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

        while (true) {
            ssize_t n = read(tun_fd, buffer, sizeof(buffer));

            if (n <= 0)
                break;

            std::vector<uint8_t> plaintext(buffer, buffer + n);
            std::vector<uint8_t> iv, ciphertext, tag;

            if (!encrypt_data(
                    plaintext, KEY, iv, ciphertext, tag)) {
                std::cerr << "Encryption failed.\n";
                continue;
            }

            std::vector<uint8_t> payload;

            payload.insert(payload.end(), iv.begin(), iv.end());
            payload.insert(payload.end(), tag.begin(), tag.end());
            payload.insert(payload.end(),
                           ciphertext.begin(),
                           ciphertext.end());

            VpnPacket packet{};
            packet.type = 1;
            packet.length = static_cast<uint16_t>(payload.size());
            packet.payload = payload;

            auto data = serialize_packet(packet);

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

        while (true) {
            ssize_t n = recvfrom(
                sock,
                buffer,
                sizeof(buffer),
                0,
                nullptr,
                nullptr);

            if (n < 31)
                continue;

            uint16_t length =
                (static_cast<uint16_t>(buffer[1]) << 8) |
                static_cast<uint16_t>(buffer[2]);

            if (length > n - 3 || length < 28)
                continue;

            std::vector<uint8_t> payload(
                buffer + 3,
                buffer + 3 + length);

            std::vector<uint8_t> iv(
                payload.begin(),
                payload.begin() + 12);

            std::vector<uint8_t> tag(
                payload.begin() + 12,
                payload.begin() + 28);

            std::vector<uint8_t> ciphertext(
                payload.begin() + 28,
                payload.end());

            std::vector<uint8_t> plaintext;

            if (!decrypt_data(
                    ciphertext,
                    KEY,
                    iv,
                    tag,
                    plaintext)) {
                std::cerr << "Authentication failed.\n";
                continue;
            }

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
