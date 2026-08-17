#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct VpnPacket {
    uint8_t type;
    uint16_t length;
    std::vector<uint8_t> payload;
};

inline std::vector<uint8_t> serialize_packet(const VpnPacket& packet) {
    std::vector<uint8_t> data;
    data.reserve(3 + packet.payload.size());

    data.push_back(packet.type);
    data.push_back(static_cast<uint8_t>(packet.length >> 8));
    data.push_back(static_cast<uint8_t>(packet.length & 0xFF));

    data.insert(data.end(), packet.payload.begin(), packet.payload.end());

    return data;
}
