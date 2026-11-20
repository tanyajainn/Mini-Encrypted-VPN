// Coverage-guided libFuzzer target for the authenticated datagram parser.
// Build with clang and -DBUILD_FUZZING=ON -DENABLE_SANITIZERS=ON.
#include "session.h"
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* bytes, size_t size) {
    if (size > 4096) return 0;
    Key256 key{};
    for (size_t i = 0; i < key.size(); ++i) key[i] = static_cast<uint8_t>(i + 1);
    const std::array<uint8_t, 4> prefix{1, 2, 3, 4};
    ReplayWindow receiver;
    std::vector<uint8_t> plaintext;

    // Both arbitrary datagrams and transformations of an authenticated frame.
    // This seeds deeper decoding and replay logic rather than exercising only
    // the three-byte packet-header rejection.
    const uint8_t seed_payload[] = {0x45, 0, 0, 0x14, 0x12, 0x34, 0, 0};
    uint64_t counter = 0;
    auto frame = seal_packet(seed_payload, sizeof(seed_payload), key, prefix, counter);
    if (frame.empty()) std::abort();
    if (size > 0 && (bytes[0] & 1)) {
        size_t mut = (size >= 2 ? bytes[1] : bytes[0]) % frame.size();
        frame[mut] ^= static_cast<uint8_t>(size >= 3 ? bytes[2] | 1u : 1u);
        if (size >= 4 && (bytes[0] & 2)) frame.resize(bytes[3] % (frame.size() + 1));
    } else {
        frame.assign(bytes, bytes + size);
    }
    const bool accepted = open_packet(frame.data(), frame.size(), key, prefix, receiver, plaintext);
    if (!accepted && !plaintext.empty()) std::abort();
    if (accepted) {
        std::vector<uint8_t> discarded;
        if (open_packet(frame.data(), frame.size(), key, prefix, receiver, discarded))
            std::abort();  // Replay of a previously accepted packet.
    }
    return 0;
}
