#include "handshake.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cassert>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>

static void check(bool condition, const char* desc) {
    if (!condition) throw std::runtime_error(desc);
}
int main() {
    Psk psk{};
    for (size_t i = 0; i < psk.size(); ++i) psk[i] = static_cast<uint8_t>(i * 7 + 3);
    std::string binary(reinterpret_cast<const char*>(psk.data()), psk.size());
    std::istringstream stream(binary);
    Psk recovered{};
    check(read_psk(stream, recovered) && recovered == psk, "32-byte PSK load");
    for (const auto& invalid : {binary.substr(1), binary + "x"}) {
        std::istringstream s(invalid); Psk p{};
        check(!read_psk(s, p), "invalid PSK length");
    }

    int server_sock = socket(AF_INET, SOCK_DGRAM, 0);
    int client_sock = socket(AF_INET, SOCK_DGRAM, 0);
    int spoof_sock = socket(AF_INET, SOCK_DGRAM, 0);
    check(server_sock >= 0 && client_sock >= 0 && spoof_sock >= 0, "UDP sockets");
    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = 0;
    check(inet_pton(AF_INET, "127.0.0.1", &server.sin_addr) == 1, "loopback");
    check(bind(server_sock, reinterpret_cast<sockaddr*>(&server), sizeof(server)) == 0,
          "bind loopback server");
    socklen_t len = sizeof(server);
    check(getsockname(server_sock, reinterpret_cast<sockaddr*>(&server), &len) == 0,
          "server ephemeral UDP port");
    SessionKeys client_keys, server_keys;
    bool server_ok = false;
    std::thread server_thread([&]() {
        sockaddr_in client{};
        server_ok = server_handshake(server_sock, psk, client, server_keys);
    });
    // A forged hello with no valid PSK MAC must be ignored. A real client can
    // still complete the exchange immediately afterward.
    uint8_t fake[85]{};
    std::memcpy(fake, "MEV1", 4); fake[4] = 1;
    check(sendto(spoof_sock, fake, sizeof(fake), 0,
                 reinterpret_cast<sockaddr*>(&server), sizeof(server)) == sizeof(fake),
          "send unauthenticated spoofed hello");
    bool client_ok = client_handshake(client_sock, server, psk, client_keys);
    server_thread.join();
    check(client_ok && server_ok, "authenticated ephemeral handshake completes");
    check(client_keys.send == server_keys.receive &&
          client_keys.receive == server_keys.send, "complementary HKDF traffic keys");
    check(client_keys.send_prefix == server_keys.receive_prefix &&
          client_keys.receive_prefix == server_keys.send_prefix,
          "complementary derived nonce prefixes");
    check(client_keys.send != client_keys.receive, "direction separation");
    close(server_sock); close(client_sock); close(spoof_sock);
    std::cout << "PASS: ephemeral X25519, PSK authenticated handshake, key agreement\n";
}
