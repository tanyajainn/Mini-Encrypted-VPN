# Threat model — Mini Encrypted VPN v0.2.0

**Scope:** Educational, single-peer C++ tunnel between two Linux TUN interfaces over UDP. This is not an independently audited or production-ready VPN. The separate `gateway/` WireGuard pilot has a different security model.

## Assets and trust assumptions

- **Protect:** confidentiality and integrity of IP packets transported between the two TUN interfaces, session-key secrecy, and acceptance of only fresh authenticated data packets.
- **Trust:** the two endpoints, their OS and OpenSSL implementations, secure random generation, and a high-entropy 32-byte pre-shared key (PSK) provisioned out of band. The local test harness generates a short-lived PSK and passes it via stdin; this does **not** solve remote key distribution.
- **Boundary:** the UDP underlay, including the veth network, is untrusted. Peer authentication means *knowledge of the PSK*, not proof of an individual person's identity.

## Attackers and expected defenses

| Attacker | Capabilities | Intended protection |
| --- | --- | --- |
| Passive eavesdropper | Records UDP packets and handshake messages | AES-256-GCM encrypts the inner IP payload; ephemeral X25519 and HKDF-SHA256 derive separate directional 256-bit session keys. |
| Active man-in-the-middle | Injects, modifies, truncates, spoofs, delays or drops packets | PSK-HMAC-authenticated handshake and finished checks reject unauthenticated key exchange; AES-GCM's 128-bit tag authenticates data and its three-byte header. Packet modification is rejected. |
| Replayer | Re-sends previously observed tunnel packets or old handshakes | A 128-position sliding replay window rejects duplicate and too-old **data** sequences; legitimate reordering within the window is accepted. Handshake replay can still consume server work. |

## Nonces and packet framing

Each sending direction has a separate key and nonce prefix. A 96-bit data nonce is a **32-bit HKDF-derived prefix concatenated with the 64-bit big-endian packet sequence**. The sender begins at sequence 1, never resets its counter for the same keys, and refuses to encrypt beyond 2^32−1 packets per session. The UDP payload contains a **1-byte type**, **2-byte payload length** (nonce + tag + ciphertext), **12-byte nonce**, **16-byte GCM authentication tag**, and **ciphertext containing an encrypted 8-byte sequence and the inner IP packet**. The three-byte header is authenticated as associated data. Reusing a nonce under the same key would compromise GCM; replay rejection alone cannot repair such reuse.

## Explicitly out of scope

**Traffic analysis** (packet size, timing, peer addresses), **denial of service** (dropping/flooding traffic or replaying valid hello messages), **endpoint compromise or stolen PSK**, malicious authenticated peers, DNS/routing leaks, physical network anonymity, multi-client identities, automatic rekeying and formal verification. A full deployment needs stronger operational controls, malicious-handshake testing, fuzzing and independent cryptographic review. Use reviewed WireGuard for real VPN service.

**Evidence:** `tests/session_test.cpp`, `tests/handshake_test.cpp`, `evaluation/replay_study.cpp`, and `docs/SECURITY.md`. The tests demonstrate selected defenses, not complete security guarantees.
