#include <arpa/inet.h>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <mutex>
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

            if (n < 31)
                continue;

            {
                std::lock_guard<std::mutex> lock(client_mutex);
                client_addr = sender;
                client_len = sender_len;
                client_known = true;
            }

            uint16_t length =
                (static_cast<uint16_t>(buffer[1]) << 8) |
                static_cast<uint16_t>(buffer[2]);

            if (length > static_cast<size_t>(n - 3) ||
                length < 28) {
                std::cerr << "Invalid packet length\n";
                continue;
            }

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

            std::vector<uint8_t> plaintext(
                buffer,
                buffer + n);

            std::vector<uint8_t> iv;
            std::vector<uint8_t> ciphertext;
            std::vector<uint8_t> tag;

            if (!encrypt_data(
                    plaintext,
                    KEY,
                    iv,
                    ciphertext,
                    tag)) {
                std::cerr << "Encryption failed.\n";
                continue;
            }

            std::vector<uint8_t> payload;

            payload.insert(
                payload.end(),
                iv.begin(),
                iv.end());

            payload.insert(
                payload.end(),
                tag.begin(),
                tag.end());

            payload.insert(
                payload.end(),
                ciphertext.begin(),
                ciphertext.end());

            VpnPacket packet{};
            packet.type = 1;
            packet.length =
                static_cast<uint16_t>(payload.size());
            packet.payload = payload;

            auto data = serialize_packet(packet);

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
