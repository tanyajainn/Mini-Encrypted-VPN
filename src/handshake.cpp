#include "handshake.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <vector>

namespace {
using Bytes = std::vector<uint8_t>;
constexpr uint8_t magic[] = {'M', 'E', 'V', '1'};
constexpr size_t ch_size = 4 + 1 + 32 + 16 + 32;
constexpr size_t sh_size = 4 + 1 + 16 + 32 + 16 + 32;
constexpr size_t fin_size = 4 + 1 + 32;
constexpr int max_tries = 5;

struct XKey {
    EVP_PKEY* key = nullptr;
    ~XKey() { EVP_PKEY_free(key); }
    XKey(const XKey&) = delete;
    XKey& operator=(const XKey&) = delete;
    XKey() = default;
    bool generate(std::array<uint8_t, 32>& pub) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        if (!ctx) return false;
        bool ok = EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_keygen(ctx, &key) == 1;
        EVP_PKEY_CTX_free(ctx);
        size_t size = pub.size();
        return ok && EVP_PKEY_get_raw_public_key(key, pub.data(), &size) == 1 && size == 32;
    }
    bool shared(const uint8_t* peer_pub, std::array<uint8_t, 32>& output) const {
        EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub, 32);
        if (!peer) return false;
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);
        if (!ctx) { EVP_PKEY_free(peer); return false; }
        size_t size = output.size();
        bool ok = EVP_PKEY_derive_init(ctx) == 1 &&
                  EVP_PKEY_derive_set_peer(ctx, peer) == 1 &&
                  EVP_PKEY_derive(ctx, output.data(), &size) == 1 && size == 32;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer);
        if (!ok) return false;
        uint8_t nonzero = 0;
        for (uint8_t byte : output) nonzero |= byte;
        return nonzero != 0;
    }
};

bool hmac256(const Key256& key, const Bytes& message, Key256& out) {
    unsigned n = 0;
    return HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
                message.data(), message.size(), out.data(), &n) != nullptr && n == 32;
}
bool mac_valid(const Key256& key, const Bytes& message, const uint8_t* mac) {
    Key256 expected{};
    bool ok = hmac256(key, message, expected) && CRYPTO_memcmp(mac, expected.data(), 32) == 0;
    OPENSSL_cleanse(expected.data(), expected.size());
    return ok;
}
Bytes raw_message(uint8_t type) {
    Bytes m(std::begin(magic), std::end(magic));
    m.push_back(type);
    return m;
}
bool proper_type(const uint8_t* bytes, size_t n, size_t expected, uint8_t type) {
    return n == expected && std::equal(std::begin(magic), std::end(magic), bytes) && bytes[4] == type;
}
void append(Bytes& b, const uint8_t* ptr, size_t n) { b.insert(b.end(), ptr, ptr + n); }
bool authenticate_and_append(const Psk& key, Bytes& b) {
    Key256 tag{};
    if (!hmac256(key, b, tag)) return false;
    append(b, tag.data(), tag.size());
    return true;
}
void set_timeout(int socket_fd) {
    timeval tv{};
    tv.tv_sec = 2;
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}
void clear_timeout(int socket_fd) {
    timeval tv{};
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}
bool same_peer(const sockaddr_in& a, const sockaddr_in& b) {
    return a.sin_family == b.sin_family && a.sin_port == b.sin_port &&
           a.sin_addr.s_addr == b.sin_addr.s_addr;
}
bool send_msg(int sock, const Bytes& payload, const sockaddr_in& address) {
    return sendto(sock, payload.data(), payload.size(), 0,
                  reinterpret_cast<const sockaddr*>(&address), sizeof(address)) ==
                  static_cast<ssize_t>(payload.size());
}
// 32+32 traffic keys, 4+4 nonce prefixes, 32+32 finished MAC keys = 136 bytes.
// HKDF salt commits to both authenticated hellos and the out-of-band PSK.
bool expand_session(const std::array<uint8_t, 32>& dh, const Psk& psk,
                    const Bytes& ch, const Bytes& sh, bool server,
                    SessionKeys& result, Key256& client_finish, Key256& server_finish) {
    Bytes transcript = ch;
    append(transcript, sh.data(), sh.size());
    Key256 salt{};
    if (!hmac256(psk, transcript, salt)) return false;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) return false;
    std::array<uint8_t, 136> material{};
    constexpr uint8_t info[] = "MEV1 X25519 PSK AES256GCM 2026 session";
    size_t n = material.size();
    bool ok = EVP_PKEY_derive_init(ctx) == 1 &&
              EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) == 1 &&
              EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), salt.size()) == 1 &&
              EVP_PKEY_CTX_set1_hkdf_key(ctx, dh.data(), dh.size()) == 1 &&
              EVP_PKEY_CTX_add1_hkdf_info(ctx, info, sizeof(info) - 1) == 1 &&
              EVP_PKEY_derive(ctx, material.data(), &n) == 1 && n == material.size();
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_cleanse(salt.data(), salt.size());
    if (!ok) return false;
    Key256 c2s{}, s2c{};
    std::array<uint8_t, 4> c_prefix{}, s_prefix{};
    std::copy_n(material.begin(), 32, c2s.begin());
    std::copy_n(material.begin() + 32, 32, s2c.begin());
    std::copy_n(material.begin() + 64, 4, c_prefix.begin());
    std::copy_n(material.begin() + 68, 4, s_prefix.begin());
    std::copy_n(material.begin() + 72, 32, client_finish.begin());
    std::copy_n(material.begin() + 104, 32, server_finish.begin());
    OPENSSL_cleanse(material.data(), material.size());
    result.send = server ? s2c : c2s;
    result.receive = server ? c2s : s2c;
    result.send_prefix = server ? s_prefix : c_prefix;
    result.receive_prefix = server ? c_prefix : s_prefix;
    OPENSSL_cleanse(c2s.data(), c2s.size());
    OPENSSL_cleanse(s2c.data(), s2c.size());
    return result.send != result.receive;
}
Bytes finished_packet(uint8_t type, const Key256& key, const Bytes& ch,
                      const Bytes& sh) {
    Bytes transcript = raw_message(type);
    append(transcript, ch.data(), ch.size());
    append(transcript, sh.data(), sh.size());
    Key256 mac{};
    if (!hmac256(key, transcript, mac)) return {};
    Bytes frame = raw_message(type);
    append(frame, mac.data(), mac.size());
    OPENSSL_cleanse(mac.data(), mac.size());
    return frame;
}
} // namespace

bool read_psk(std::istream& input, Psk& key) {
    std::array<char, 32> bytes{};
    if (!input.read(bytes.data(), bytes.size()) || input.peek() != EOF) return false;
    for (size_t i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(bytes[i]);
    return true;
}

bool client_handshake(int sock, const sockaddr_in& server, const Psk& psk,
                      SessionKeys& result) {
    set_timeout(sock);
    XKey ephemeral;
    std::array<uint8_t, 32> pub{};
    std::array<uint8_t, 16> client_random{};
    if (!ephemeral.generate(pub) || RAND_bytes(client_random.data(), 16) != 1) return false;
    Bytes ch = raw_message(1);
    append(ch, pub.data(), pub.size());
    append(ch, client_random.data(), client_random.size());
    if (!authenticate_and_append(psk, ch)) return false;
    std::array<uint8_t, 512> buffer{};
    for (int attempt = 0; attempt < max_tries; ++attempt) {
        if (!send_msg(sock, ch, server)) return false;
        sockaddr_in sender{}; socklen_t sender_len = sizeof(sender);
        const ssize_t n = recvfrom(sock, buffer.data(), buffer.size(), 0,
                                    reinterpret_cast<sockaddr*>(&sender), &sender_len);
        if (n <= 0 || !same_peer(sender, server) ||
            !proper_type(buffer.data(), static_cast<size_t>(n), sh_size, 2) ||
            CRYPTO_memcmp(buffer.data() + 5, client_random.data(), 16) != 0)
            continue;
        Bytes sh(buffer.begin(), buffer.begin() + n);
        Bytes auth = ch;
        append(auth, sh.data(), sh.size() - 32);
        if (!mac_valid(psk, auth, sh.data() + sh.size() - 32)) continue;
        std::array<uint8_t, 32> secret{};
        if (!ephemeral.shared(sh.data() + 21, secret)) return false;
        Key256 client_finish{}, server_finish{};
        bool derived = expand_session(secret, psk, ch, sh, false, result,
                                      client_finish, server_finish);
        OPENSSL_cleanse(secret.data(), secret.size());
        if (!derived) return false;
        Bytes finished = finished_packet(3, client_finish, ch, sh);
        Bytes expected = finished_packet(4, server_finish, ch, sh);
        OPENSSL_cleanse(client_finish.data(), client_finish.size());
        OPENSSL_cleanse(server_finish.data(), server_finish.size());
        if (finished.empty() || expected.empty()) return false;
        for (int tries = 0; tries < max_tries; ++tries) {
            if (!send_msg(sock, finished, server)) return false;
            sender_len = sizeof(sender);
            const ssize_t count = recvfrom(sock, buffer.data(), buffer.size(), 0,
                                           reinterpret_cast<sockaddr*>(&sender), &sender_len);
            if (count == static_cast<ssize_t>(expected.size()) && same_peer(sender, server) &&
                CRYPTO_memcmp(buffer.data(), expected.data(), expected.size()) == 0)
                { clear_timeout(sock); return true; }
        }
        return false;
    }
    return false;
}

bool server_handshake(int sock, const Psk& psk, sockaddr_in& client,
                      SessionKeys& result) {
    set_timeout(sock);
    std::array<uint8_t, 512> buffer{};
    while (true) {
        sockaddr_in sender{}; socklen_t length = sizeof(sender);
        ssize_t n = recvfrom(sock, buffer.data(), buffer.size(), 0,
                             reinterpret_cast<sockaddr*>(&sender), &length);
        if (n < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue; return false; }
        if (!proper_type(buffer.data(), static_cast<size_t>(n), ch_size, 1)) continue;
        Bytes ch(buffer.begin(), buffer.begin() + n);
        Bytes auth(ch.begin(), ch.end() - 32);
        if (!mac_valid(psk, auth, ch.data() + ch.size() - 32)) continue;
        XKey ephemeral;
        std::array<uint8_t, 32> pub{};
        std::array<uint8_t, 16> server_random{};
        if (!ephemeral.generate(pub) || RAND_bytes(server_random.data(), 16) != 1) return false;
        Bytes sh = raw_message(2);
        append(sh, ch.data() + 37, 16); // Echo client challenge from authenticated hello.
        append(sh, pub.data(), pub.size());
        append(sh, server_random.data(), server_random.size());
        Bytes transcript = ch;
        append(transcript, sh.data(), sh.size());
        Key256 mac{};
        if (!hmac256(psk, transcript, mac)) return false;
        append(sh, mac.data(), mac.size());
        OPENSSL_cleanse(mac.data(), mac.size());
        std::array<uint8_t, 32> secret{};
        if (!ephemeral.shared(ch.data() + 5, secret)) continue;
        Key256 client_finish{}, server_finish{};
        bool derived = expand_session(secret, psk, ch, sh, true, result,
                                      client_finish, server_finish);
        OPENSSL_cleanse(secret.data(), secret.size());
        if (!derived) return false;
        Bytes expected = finished_packet(3, client_finish, ch, sh);
        Bytes finished = finished_packet(4, server_finish, ch, sh);
        OPENSSL_cleanse(client_finish.data(), client_finish.size());
        OPENSSL_cleanse(server_finish.data(), server_finish.size());
        if (expected.empty() || finished.empty()) return false;
        for (int attempt = 0; attempt < max_tries; ++attempt) {
            if (!send_msg(sock, sh, sender)) return false;
            length = sizeof(sender);
            n = recvfrom(sock, buffer.data(), buffer.size(), 0,
                         reinterpret_cast<sockaddr*>(&client), &length);
            if (n == static_cast<ssize_t>(expected.size()) && same_peer(sender, client) &&
                CRYPTO_memcmp(buffer.data(), expected.data(), expected.size()) == 0) {
                // Respond after validating the client possesses the ephemeral DH secret.
                if (!send_msg(sock, finished, sender)) return false;
                client = sender;
                clear_timeout(sock);
                return true;
            }
            // The client retransmits CH if SH was lost; retransmit the same SH.
            if (n == static_cast<ssize_t>(ch.size()) && same_peer(sender, client) &&
                CRYPTO_memcmp(buffer.data(), ch.data(), ch.size()) == 0)
                continue;
        }
    }
}
