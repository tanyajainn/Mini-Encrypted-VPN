# Mini Encrypted VPN 🔐

A small C++/OpenSSL **educational** IP-over-UDP tunnel for studying authenticated
key exchange, AEAD encryption, anti-replay protection and Linux networking.
**Not audited or suitable for production deployment.** For real VPN service,
prefer WireGuard or another reviewed implementation.

## What it implements

- Linux TUN interfaces in two network namespaces, connected by a veth underlay.
- A **PSK-authenticated ephemeral X25519 handshake** and HKDF-SHA256 directional
  session keys (not the WireGuard/Noise protocol).
- AES-256-GCM **AEAD** for each IP datagram, with an authenticated packet header,
  128-bit tag and deterministic per-direction sequence-derived 96-bit nonce.
- A 128-packet anti-replay window that accepts safely reordered originals while
  dropping duplicates and out-of-window stale packets.
- A deliberately limited single-peer design, with a stop-before-wrap GCM packet
  limit and no live rekey. See [Security and threat model](docs/SECURITY.md).

```text
client TUN (10.10.0.2) --AEAD over UDP:9000--> server TUN (10.10.0.1)
      veth-client (172.30.0.2) <--> veth-server (172.30.0.1)
      key exchange: ephemeral X25519 + shared 32-byte PSK + HKDF
```

## Project Status

**Educational Networking and Cryptography Prototype | Maintenance Mode**

Active feature development concluded in November 2026.

This project demonstrates encrypted IP tunneling, authenticated key exchange, AES-256-GCM, anti-replay protection, and reproducible network experiments.

The v0.2.0 baseline was validated in WSL2. The v0.3.0 candidate passed automated tests, sanitizer checks, and bounded fuzz testing, but still requires live end-to-end validation.

**Known limitations:** No independent cryptographic audit, automatic rekeying, or production deployment assurance.

This project is retained for educational, research, and portfolio purposes.

## Quickstart (Ubuntu/Linux)

```bash
git clone https://github.com/tanyajainn/Mini-Encrypted-VPN.git
cd Mini-Encrypted-VPN
sudo apt-get update
sudo apt-get install -y cmake g++ libssl-dev iproute2 iputils-ping openssl
cmake -S . -B build -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
chmod +x run_vpn.sh
./run_vpn.sh
```

The script uses `sudo` for network namespaces/TUN and runs both local endpoints
with a newly generated **32-byte random PSK**, passed via stdin. That PSK is
intentionally short-lived and deleted on exit. The *traffic keys* are derived
in an authenticated network handshake rather than directly shared on stdin.
End the test with Ctrl+C. WSL2 support depends on the kernel and TUN settings.
Never use this script to provide anonymous browsing or a public VPN service.

## Crypto design

| Component | Choice |
| --- | --- |
| Data encryption | OpenSSL AES-256-GCM AEAD, 256-bit directional keys |
| Nonce | 32-bit HKDF-derived prefix + 64-bit monotonically increasing sequence |
| Authentication | 32-byte high-entropy shared PSK authenticates both X25519 hello messages |
| Key derivation | HKDF-SHA256 from ephemeral X25519 DH + PSK-bound handshake transcript |
| Frame integrity | 128-bit GCM tag with 3-byte header as associated data |
| Replay defense | 128-bit receiver bitmap with highest-sequence tracking |
| Key lifetime | One handshake per process; sender refuses at 2^32-1 packets |

Threats covered: passive packet sniffing, malicious packet modifications,
unauthenticated spoofing and replays of data packets. Not covered: compromised
endpoints, stolen PSK, traffic analysis, denial of service, DNS/routing leaks or
independent protocol audit. **Important:** AES-GCM nonce reuse is dangerous; a
receiver's duplicate check cannot undo nonce reuse by a broken sender.
Full protocol details: [docs/SECURITY.md](docs/SECURITY.md). For a one-page assessment, see [Threat model](docs/THREAT_MODEL.md).

## Experimental capstone validation (candidate v0.3.0)

The candidate capstone upgrade adds a TUN interface readiness gate, a seeded
packet-attack campaign, Clang AddressSanitizer/UndefinedBehaviorSanitizer and
libFuzzer support, and a four-profile replay-window research experiment
(20 seeds per profile/configuration). See [capstone methods and limitations](docs/CAPSTONE_UPGRADE.md),
[experimental findings](docs/CAPSTONE_RESULTS.md), and
[updated validation evidence](docs/VALIDATION.md).

**The research delay models are synthetic; previous WSL2 throughput numbers
were measured on the v0.2.0 baseline, not the candidate changes.** This is
not an independent cryptographic audit or a production VPN.

## Tests and experiments

```bash
ctest --test-dir build --output-on-failure
./build/replay_study > evaluation/replay-results.csv
python3 evaluation/plot_replay.py evaluation/replay-results.csv
```

Tests check authenticated key agreement, tampered and truncated frames, spoofed
traffic, duplicate and stale packet rejection, in-window reordering and a
controlled nonce-reuse incident. The replay study sends 4,096 packets with
simulated delays for each of five seeds and compares the production 128-bit
window against an independent reference.

The previous **64-packet** bitmap dropped **7,981/20,480 (39.0%)** delayed
legitimate originals at max delay 128 ticks. The **128-packet** window dropped
zero in the same synthetic scenario and consumes a 16-byte bitmap plus an
8-byte high-water counter (8 bytes more state than the 64-packet version).
This is a **simulation**, not a measured internet packet-loss rate.

For `iperf3` direct vs tunnel throughput, ping latency, UDP packet loss,
`tc netem` reordering, and a same-namespace WireGuard comparison, read
[Benchmarking methodology](docs/BENCHMARKING.md). The benchmark writes raw observations, CSV rows and per-condition median
comparisons. Measurements are generated only on a suitable Linux environment;
no unmeasured numbers are claimed.

## Repository map

```text
include/            Packet, AES-GCM, session and handshake interfaces
src/                Client, server, crypto, handshake, TUN implementation
tests/              Packet attack tests and authenticated handshake tests
evaluation/         Replay simulation, plotting, iperf and WireGuard scripts
docs/               Security/threat model and benchmark methodology
gateway/            Separate WireGuard regional exit pilot
.github/workflows/  CMake build + CTest CI
run_vpn.sh          Two-namespace local test harness
CMakeLists.txt      Build and test setup
```

The [regional exit gateway pilot](gateway/README.md) uses actual WireGuard
and is **separate from** this experimental C++ tunnel.

The replay evidence plot is in [evaluation/replay-window.png](evaluation/replay-window.png).
For the capstone candidate overlay, follow [CAPSTONE_APPLY.md](CAPSTONE_APPLY.md).

## Limitations and authorship

This prototype illustrates UDP tunneling, key agreement, GCM authentication,
nonce construction, sequence numbers, replay windows, `ip netns`, TUN routing,
reproducible experiments and system-comparison pitfalls. Multi-client support,
rolling rekeys, production-grade resistance to DoS, and protocol auditing are
not implemented. MIT licensed; see `LICENSE`.

**Author:** Tanya Jain — cybersecurity and networking learning project.
