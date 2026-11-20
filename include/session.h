#pragma once
#include "crypto.h"
#include "handshake.h"
#include "packet.h"
#include <algorithm>
#include <array>
#include <bitset>
#include <cstdint>
#include <limits>
#include <vector>

// The 128-bit bitmap costs 16 bytes, plus one 8-byte highest-sequence counter.
class ReplayWindow {
    uint64_t highest_ = 0;
    std::bitset<128> seen_{};
public:
    bool accept(uint64_t sequence) {
        if (sequence == 0) return false;
        if (sequence > highest_) {
            const uint64_t offset = sequence - highest_;
            if (offset >= 128) seen_.reset();
            else seen_ <<= static_cast<size_t>(offset);
            seen_.set(0);
            highest_ = sequence;
            return true;
        }
        const uint64_t offset = highest_ - sequence;
        if (offset >= 128 || seen_.test(static_cast<size_t>(offset))) return false;
        seen_.set(static_cast<size_t>(offset));
        return true;
    }
};

inline Nonce96 packet_nonce(const std::array<uint8_t, 4>& prefix, uint64_t sequence) {
    Nonce96 iv{};
    for (int i = 0; i < 4; ++i) iv[i] = prefix[i];
    for (int i = 0; i < 8; ++i)
        iv[4 + i] = static_cast<uint8_t>(sequence >> (56 - 8 * i));
    return iv;
}

// Fresh handshake keys and a non-resettable monotonically increasing counter
// are required per sender instance. Enforces <= 2^32-1 encryptions per AES-GCM key.
inline std::vector<uint8_t> seal_packet(const uint8_t* data, size_t size,
        const Key256& key, const std::array<uint8_t, 4>& prefix, uint64_t& sequence) {
    if (!data || size == 0 || size > 2000 ||
        sequence >= (uint64_t{1} << 32) - 1) return {};
    const uint64_t next = ++sequence; // Never reuse a nonce after an encryption error.
    std::vector<uint8_t> plain(8);
    for (int i = 0; i < 8; ++i)
        plain[i] = static_cast<uint8_t>(next >> (56 - 8 * i));
    plain.insert(plain.end(), data, data + size);
    Nonce96 iv = packet_nonce(prefix, next);
    const uint16_t length = static_cast<uint16_t>(12 + 16 + plain.size());
    const std::array<uint8_t, 3> header{2, static_cast<uint8_t>(length >> 8),
                                       static_cast<uint8_t>(length)};
    std::vector<uint8_t> ciphertext;
    Tag128 tag{};
    if (!encrypt_data(plain, key, iv, header.data(), header.size(), ciphertext, tag))
        return {};
    std::vector<uint8_t> packet;
    packet.reserve(header.size() + iv.size() + tag.size() + ciphertext.size());
    packet.insert(packet.end(), header.begin(), header.end());
    packet.insert(packet.end(), iv.begin(), iv.end());
    packet.insert(packet.end(), tag.begin(), tag.end());
    packet.insert(packet.end(), ciphertext.begin(), ciphertext.end());
    return packet;
}

inline bool open_packet(const uint8_t* data, size_t size,
        const Key256& key, const std::array<uint8_t, 4>& prefix,
        ReplayWindow& window, std::vector<uint8_t>& plain) {
    plain.clear();
    if (!data || size <= 39 || size > 2039 || data[0] != 2) return false;
    const size_t length = (size_t{data[1]} << 8) | data[2];
    if (length != size - 3) return false;
    Nonce96 nonce{};
    std::copy(data + 3, data + 15, nonce.begin());
    if (!std::equal(prefix.begin(), prefix.end(), nonce.begin())) return false;
    Tag128 tag{};
    std::copy(data + 15, data + 31, tag.begin());
    std::vector<uint8_t> decoded;
    if (!decrypt_data(data + 31, size - 31, key, nonce, data, 3, tag, decoded) ||
        decoded.size() <= 8) return false;
    uint64_t sequence = 0;
    for (size_t i = 0; i < 8; ++i) sequence = (sequence << 8) | decoded[i];
    if (sequence == 0 || sequence >= (uint64_t{1} << 32) ||
        packet_nonce(prefix, sequence) != nonce || !window.accept(sequence))
        return false;
    plain.assign(decoded.begin() + 8, decoded.end());
    return true;
}
