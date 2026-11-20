#pragma once
#include "crypto.h"
#include <array>
#include <cstdint>
#include <istream>
#include <netinet/in.h>

using Psk = std::array<uint8_t, 32>;
struct SessionKeys {
    Key256 send{};
    Key256 receive{};
    std::array<uint8_t, 4> send_prefix{};
    std::array<uint8_t, 4> receive_prefix{};
};

// The caller supplies a *high-entropy* 32-byte secret, provisioned out-of-band.
bool read_psk(std::istream& input, Psk& key);

// A pedagogical PSK-authenticated ephemeral X25519 exchange, NOT Noise or WireGuard.
// Both calls run before starting data-plane threads and return false on failure.
bool client_handshake(int sock, const sockaddr_in& server, const Psk& psk,
                      SessionKeys& keys);
bool server_handshake(int sock, const Psk& psk, sockaddr_in& client,
                      SessionKeys& keys);
