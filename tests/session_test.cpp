#include "session.h"

#include <sstream>
#include <stdexcept>

static void check(bool condition, const char* name) {
    if (!condition) throw std::runtime_error(name);
}

int main() {
    std::string input(32, 'a');
    input.append(32, 'b');
    SessionKeys client, server;
    std::istringstream c(input), s(input);
    check(client.read_from(c, false) && server.read_from(s, true), "load keys");
    for (const auto& bad : {input.substr(1), input + "x", std::string(64, 'a')}) {
        std::istringstream stream(bad);
        SessionKeys keys;
        check(!keys.read_from(stream, false), "invalid keys");
    }
    const std::vector<uint8_t> packet{0x45, 0, 0, 20};
    std::vector<uint8_t> plain;
    uint64_t sequence = 0;
    ReplayWindow window;
    auto first = seal_packet(packet.data(), packet.size(), client.send, sequence);
    auto second = seal_packet(packet.data(), packet.size(), client.send, sequence);
    auto accept = [&](const std::vector<uint8_t>& frame) {
        return open_packet(frame.data(), frame.size(), server.receive, window, plain);
    };
    for (size_t index : {0, 2, 3, 15, 31}) {
        auto tampered = second;
        tampered[index] ^= 1;
        check(!accept(tampered), "changed header, IV, tag or ciphertext");
    }
    auto trailing = second;
    trailing.push_back(0);
    check(!accept(trailing), "trailing data");
    check(!open_packet(second.data(), second.size(), client.receive, window, plain),
          "reflection");
    check(accept(second) && plain == packet, "authenticated delivery");
    check(accept(first) && plain == packet, "reordered delivery");
    check(!accept(first) && !accept(second), "replay");
    const std::vector<uint8_t> full_packet(1433, 0x5a);
    auto full_frame = seal_packet(full_packet.data(), full_packet.size(), client.send, sequence);
    check(full_frame.size() + 20 + 8 == 1500, "full frame fits IPv4/UDP link");
    check(accept(full_frame) && plain == full_packet, "full-size packet round trip");
    ReplayWindow boundary;
    check(boundary.accept(65) && boundary.accept(2) && !boundary.accept(1),
          "window boundary");
    check(boundary.accept(129) && !boundary.accept(65), "large forward jump");
}
