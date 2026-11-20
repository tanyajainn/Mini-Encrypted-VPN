# Security design and threat model — Mini Encrypted VPN v0.2 (experimental)

> Not a production VPN or audited secure channel. This custom authenticated
> protocol is for learning, not a substitute for WireGuard/Noise. Test only in
> isolated namespaces or environments you administer.

## Cryptographic inventory (implementation, not aspiration)

| Property | Design |
| --- | --- |
| Data cipher | OpenSSL AES-256-GCM (AEAD) |
| Data key | Independent 256-bit send/receive keys from HKDF-SHA256 |
| Data nonce | 96 bits: per-direction 32-bit HKDF prefix \+ 64-bit big-endian packet sequence |
| Tag | 128-bit AES-GCM tag |
| Associated data | 3-byte packet header (`type=2`, big-endian ciphertext length) |
| Plaintext | Big-endian 64-bit sequence, then original IP packet (up to 2,000 B) |
| Wire frame | type(1) + length(2) + nonce(12) + tag(16) + ciphertext(seq(8) + IP packet) |
| Per-frame overhead | 39 bytes (plus outer IPv4 20 + UDP 8 on the underlay) |
| Sender counter | Starts at zero for each fresh session; pre-incremented, never wraps |
| Key lifetime | Stops sealing after 2^32-1 packets per sender; restart to rekey |
| Receiver replay state | 128-bit sliding bitmap + 64-bit highest sequence, ~24 B logical state |

### Key exchange

1. An out-of-band **32-byte uniformly random PSK** is provisioned on each peer.
   The local test script generates one via `openssl rand -out ... 32` and sends
   the same PSK to two isolated processes through stdin. **Never commit it.**
2. ClientHello carries magic `MEV1`, type 1, an ephemeral X25519 public key,
   a 16-byte random challenge and HMAC-SHA256(PSK, ClientHello fields).
3. Server rejects unauthenticated ClientHello, generates fresh X25519 key pair,
   and returns ServerHello with the client's challenge, its own ephemeral key,
   16-byte server random and HMAC-SHA256(PSK, ClientHello || ServerHello fields).
4. Both sides compute the ephemeral X25519 shared secret. HKDF-SHA256 derives
   136 bytes from that secret, salted by HMAC-SHA256(PSK, both complete hellos),
   with a protocol-specific info string. These comprise two traffic keys,
   two nonce prefixes and two *different* finished-MAC keys.
5. ClientFinished and ServerFinished HMACs authenticate the complete hello
   transcript with the derived keys; traffic starts only after verification.
6. Each direction has a separate key, prefix and monotonically advancing sequence.
   Invalid tags, mismatched frame lengths/nonces, old sequences and duplicates
   are dropped before exposing plaintext to TUN.

**Scope of authentication:** a peer that knows the same PSK, not a named
identity/certificate. The project currently supports one client peer per
server process; a replayed authenticated ClientHello can cause handshake
work. No identity PKI, anti-DoS cookie, session migration recovery or rekey
without restart has been implemented.

## Attacker and defenses

Assume an attacker can read, reorder, drop, truncate, replay and inject UDP
packets on the underlay, and spoof source IP/port. We seek confidentiality and
integrity of IP payloads, peer authentication by possession of a 32-byte PSK,
and freshness of accepted packets. A passive recorder should not recover
traffic from the recorded transcript if the ephemeral X25519 secrets are
properly erased; a later PSK leak alone should not recover past traffic.

We **do not** defend against compromised hosts or stolen PSKs, traffic
analysis (size/timing/endpoints), denial of service, malicious traffic at an
authenticated endpoint, DNS leaks, routing misconfiguration, packet injection
*inside* a TUN interface by a compromised namespace, or cryptographic
implementation vulnerabilities. `run_vpn.sh` is a test rig, not a trusted
key-distribution protocol.

### Nonce-reuse caveat

GCM nonce reuse with the same key can catastrophically compromise confidentiality
and authenticity. The sender computes nonce from a derived per-direction
prefix and a monotonic sequence and refuses to exceed the invocation limit.
Two independently constructed sender-counter objects reusing the same session
keys would violate this invariant, even though the receiver's anti-replay
bitmap rejects the second sequence number. **A receiver rejection does not
make sender-side nonce reuse cryptographically safe.** Do not reset a sender
counter while reusing session keys. Rotation requires a new handshake.

### Remaining protocol caveats

- Handshake retransmission is deliberately basic: a lost final server-finished
  message may require restarting the process.
- A recorded valid old hello can be replayed to cause server handshake work;
  authentication alone is not denial-of-service protection.
- The cipher is AES-GCM, not ChaCha20-Poly1305; performance depends on hardware.
- Need third-party cryptographic review, fuzzing, malicious-handshake test cases,
  rate limiting and long-running `tc netem` tests before claiming robustness.
- WireGuard is a separate, established protocol. This project does **not**
  implement WireGuard's NoiseIK handshake and should not be portrayed as equal.

## Test evidence

`ctest --test-dir build --output-on-failure` runs packet attack, handshake and
replay-study checks without root. `evaluation/benchmark.sh` runs throughput,
RTT, UDP loss and reordering-impairment measurements in the real namespaces;
these *require* Linux network administration and iperf3. Do not conflate
synthetic replay-window drops with observed underlay packet loss.
