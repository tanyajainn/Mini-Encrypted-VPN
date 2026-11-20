// Deterministic reproducible negative-test campaign; not a formal security proof.
#include "session.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <random>
#include <stdexcept>
#include <vector>

static void require(bool value, const char* why) {
    if (!value) throw std::runtime_error(why);
}

int main() {
    Key256 key{};
    std::array<uint8_t, 4> prefix{0xa1, 0xb2, 0xc3, 0xd4};
    for (unsigned i = 0; i < key.size(); ++i) key[i] = static_cast<uint8_t>(i * 3 + 7);
    std::mt19937_64 rng(20261120);
    uint64_t sender = 0;
    size_t mutations = 0, truncations = 0, valid = 0;

    for (unsigned trial = 0; trial < 96; ++trial) {
        // Every 16th trial reaches the full supported tunnel MTU.
        size_t n = trial % 16 == 0 ? 1433 : 1 + rng() % 256;
        std::vector<uint8_t> payload(n);
        for (auto &b : payload) b = static_cast<uint8_t>(rng());
        auto frame = seal_packet(payload.data(), payload.size(), key, prefix, sender);
        require(frame.size() == payload.size() + 39, "sealing succeeded");
        // A failed mutation must neither poison replay state nor expose plaintext.
        ReplayWindow receiver;
        std::vector<uint8_t> plaintext{0x99};
        for (size_t pos = 0; pos < frame.size(); ++pos) {
            auto changed = frame;
            changed[pos] ^= 1u << (pos % 8);
            require(!open_packet(changed.data(), changed.size(), key, prefix, receiver, plaintext),
                    "single-bit mutation must be rejected");
            require(plaintext.empty(), "no unauthenticated plaintext exposure");
            ++mutations;
        }
        // Select representative truncations, including the final authentication byte.
        const std::array<size_t, 9> sizes{0, 1, 2, 3, 14, 30, 31, 39, frame.size() - 1};
        for (size_t size : sizes) {
            require(!open_packet(frame.data(), size, key, prefix, receiver, plaintext),
                    "truncated datagram must be rejected");
            require(plaintext.empty(), "no plaintext on truncation");
            ++truncations;
        }
        require(open_packet(frame.data(), frame.size(), key, prefix, receiver, plaintext),
                "negative cases must not poison a valid packet");
        require(plaintext == payload, "authenticated roundtrip");
        require(!open_packet(frame.data(), frame.size(), key, prefix, receiver, plaintext),
                "duplicate rejected");
        ++valid;
    }

    // Distinct sequence counters must produce distinct nonces for one key/prefix.
    require(packet_nonce(prefix, 1) != packet_nonce(prefix, 2), "nonce uniqueness");
    require(packet_nonce(prefix, (uint64_t{1} << 32) - 1) != packet_nonce(prefix, 1),
            "nonce uniqueness across the supported session lifetime");
    std::cout << "PASS: " << valid << " authenticated round trips; " << mutations
              << " single-bit rejects; " << truncations << " truncation rejects; "
              << valid << " duplicate rejects (seed=20261120)\n";
}
