#include "session.h"
#include <stdexcept>
#include <vector>
#include <iostream>

static void check(bool condition, const char* name) {
    if (!condition) throw std::runtime_error(name);
}
int main() {
    Key256 key{}, wrong{};
    std::array<uint8_t, 4> prefix{0x11, 0x22, 0x33, 0x44};
    for (size_t i = 0; i < key.size(); ++i) { key[i] = static_cast<uint8_t>(i + 1); wrong[i] = static_cast<uint8_t>(i + 2); }
    const std::vector<uint8_t> ip_packet{0x45, 0x00, 0x00, 0x14};
    const std::vector<uint8_t> another_packet{0x45, 0x01, 0x00, 0x14};
    std::vector<uint8_t> decoded;
    ReplayWindow receiver;
    uint64_t sequence = 0;
    auto a = seal_packet(ip_packet.data(), ip_packet.size(), key, prefix, sequence);
    auto b = seal_packet(ip_packet.data(), ip_packet.size(), key, prefix, sequence);
    check(a.size() == ip_packet.size() + 39 && b.size() == a.size(), "framing overhead");
    auto accept = [&](const std::vector<uint8_t>& frame) {
        return open_packet(frame.data(), frame.size(), key, prefix, receiver, decoded);
    };
    // Independently mutate each authenticated component without touching the valid input.
    for (size_t index : {0, 1, 2, 3, 14, 15, 30, 31, 39}) {
        auto corrupted = b;
        corrupted[index] ^= 0x80;
        check(!accept(corrupted), "bit-flipped header, nonce, tag or ciphertext");
        check(decoded.empty(), "failure must not leak plaintext");
    }
    for (size_t len : {0, 1, 3, 15, 30, 39, 40}) {
        check(!open_packet(b.data(), len, key, prefix, receiver, decoded), "truncated frame rejected");
    }
    auto trailing = b; trailing.push_back(0);
    check(!accept(trailing), "trailing byte rejected");
    check(!open_packet(b.data(), b.size(), wrong, prefix, receiver, decoded), "spoofed key rejected");
    check(!open_packet(b.data(), b.size(), key, {1, 2, 3, 4}, receiver, decoded), "spoofed prefix rejected");
    check(accept(b) && decoded == ip_packet, "valid frame authenticated");
    check(accept(a) && decoded == ip_packet, "reordered original accepted within window");
    check(!accept(a) && !accept(b), "replay rejected");

    // Same nonce and sequence, two distinct ciphertexts: the second must be
    // rejected by receiver replay tracking. The sender MUST never reset counter.
    ReplayWindow reuse_window;
    uint64_t seq0 = 0, reset_seq = 0;
    auto first = seal_packet(ip_packet.data(), ip_packet.size(), key, prefix, seq0);
    auto reuse = seal_packet(another_packet.data(), another_packet.size(), key, prefix, reset_seq);
    check(first != reuse && std::equal(first.begin() + 3, first.begin() + 15,
                                      reuse.begin() + 3), "test created nonce reuse");
    check(open_packet(first.data(), first.size(), key, prefix, reuse_window, decoded),
          "first use accepted");
    check(!open_packet(reuse.data(), reuse.size(), key, prefix, reuse_window, decoded),
          "nonce reuse detected as replay");

    uint64_t limit = (uint64_t{1} << 32) - 1;
    check(seal_packet(ip_packet.data(), ip_packet.size(), key, prefix, limit).empty(),
          "sender stops at GCM message limit");
    // Reject a properly authenticated packet that arrives beyond the window,
    // rather than confusing legitimate reordering with a replay attack.
    ReplayWindow stale_window;
    uint64_t seq_for_stale = 0;
    auto stale = seal_packet(ip_packet.data(), ip_packet.size(), key, prefix, seq_for_stale);
    check(open_packet(stale.data(), stale.size(), key, prefix, stale_window, decoded),
          "first old packet accepted before high-water advance");
    std::vector<uint8_t> latest;
    for (int i = 0; i < 128; ++i)
        latest = seal_packet(ip_packet.data(), ip_packet.size(), key, prefix, seq_for_stale);
    check(open_packet(latest.data(), latest.size(), key, prefix, stale_window, decoded),
          "high-water advances");
    check(!open_packet(stale.data(), stale.size(), key, prefix, stale_window, decoded),
          "authenticated stale packet outside 128-position window is rejected");
    ReplayWindow boundary;
    check(boundary.accept(129) && boundary.accept(2) && !boundary.accept(1),
          "128-position replay window boundary");
    check(boundary.accept(258) && !boundary.accept(129), "large forward jump");
    const std::vector<uint8_t> mtu(1433, 0x5a);
    auto full = seal_packet(mtu.data(), mtu.size(), key, prefix, sequence);
    check(full.size() + 20 + 8 == 1500, "IPv4 + UDP + encrypted payload fits MTU");
    check(accept(full) && decoded == mtu, "MTU round trip");
    std::cout << "PASS: tampering, truncation, spoofing, reorder, replay, nonce reuse, MTU\n";
}
