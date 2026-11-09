#pragma once

#include "crypto.h"
#include "packet.h"

#include <algorithm>
#include <array>
#include <iostream>
#include <limits>

struct SessionKeys {
    std::vector<uint8_t> send;
    std::vector<uint8_t> receive;

    bool read_from(std::istream& input, bool server) {
        std::array<char, 64> bytes{};
        if (!input.read(bytes.data(), bytes.size()) || input.peek() != EOF)
            return false;
        send.assign(bytes.begin(), bytes.begin() + 32);
        receive.assign(bytes.begin() + 32, bytes.end());
        if (server) send.swap(receive);
        return send != receive;
    }
};

class ReplayWindow {
    uint64_t highest = 0;
    uint64_t seen = 0;

public:
    bool accept(uint64_t sequence) {
        if (sequence == 0) return false;
        if (sequence > highest) {
            uint64_t offset = sequence - highest;
            seen = offset >= 64 ? 1 : (seen << offset) | 1;
            highest = sequence;
            return true;
        }
        uint64_t offset = highest - sequence;
        if (offset >= 64) return false;
        uint64_t bit = uint64_t{1} << offset;
        if (seen & bit) return false;
        seen |= bit;
        return true;
    }
};

inline std::vector<uint8_t> seal_packet(const uint8_t* data, size_t size,
        const std::vector<uint8_t>& key, uint64_t& sequence) {
    if (size == 0 || size > 2000 || sequence == std::numeric_limits<uint64_t>::max())
        return {};
    std::vector<uint8_t> plain(8);
    ++sequence;
    for (int i = 0; i < 8; ++i)
        plain[i] = static_cast<uint8_t>(sequence >> (56 - 8 * i));
    plain.insert(plain.end(), data, data + size);
    std::vector<uint8_t> iv, encrypted, tag;
    if (!encrypt_data(plain, key, iv, encrypted, tag)) return {};
    VpnPacket packet{};
    packet.type = 2;
    packet.payload = iv;
    packet.payload.insert(packet.payload.end(), tag.begin(), tag.end());
    packet.payload.insert(packet.payload.end(), encrypted.begin(), encrypted.end());
    packet.length = static_cast<uint16_t>(packet.payload.size());
    return serialize_packet(packet);
}

inline bool open_packet(const uint8_t* data, size_t size,
        const std::vector<uint8_t>& key, ReplayWindow& window,
        std::vector<uint8_t>& plain) {
    // Header, GCM IV, GCM tag, encrypted sequence number, then the IP packet.
    if (size <= 39 || size > 2039 || data[0] != 2) return false;
    const size_t length = (size_t{data[1]} << 8) | data[2];
    if (length != size - 3) return false;
    std::vector<uint8_t> decoded;
    if (!decrypt_data({data + 31, data + size}, key, {data + 3, data + 15},
                      {data + 15, data + 31}, decoded)) return false;
    uint64_t sequence = 0;
    for (size_t i = 0; i < 8; ++i) sequence = (sequence << 8) | decoded[i];
    if (!window.accept(sequence)) return false;
    plain.assign(decoded.begin() + 8, decoded.end());
    return true;
}
