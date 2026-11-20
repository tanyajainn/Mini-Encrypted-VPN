# Validation record — v0.2.0 baseline and capstone candidate v0.3.0

This document distinguishes **operator-observed network experiments** from
**locally verified root-free checks** and tasks not yet verified.

## v0.2.0 baseline: operator-observed on Ubuntu/WSL2, November 20, 2026

- Initial CMake build and 3/3 CTest passing.
- Authenticated X25519 handshake and TUN ping: 3/3 standard ICMP, 3/3
  1,433-byte tunnel-MTU ICMP; both reported 0% loss.
- WireGuard peer ping successful in the same two namespaces.
- Direct/custom/WireGuard 18 benchmark runs completed in clean and netem
  settings, with three repetitions each; the median CSV was committed to GitHub.
- Main-branch GitHub Actions passed on the merged v0.2.0 code and again after
  the documentation commit (as observed at the time).
- An intermittent TUN `write ... Input/output error` occurred during startup
  despite later successful connectivity; that issue prompted the new gate.
- **These observations do not validate candidate v0.3.0 behavior.**

## Candidate v0.3.0: local container checks, November 20, 2026

- GCC and Clang configurations and builds completed; OpenSSL crypto linked.
- Normal CTest: **6/6 passed** (`session_packets`, `handshake_auth`,
  `replay_window_model`, `replay_robustness_campaign`,
  `packet_attack_campaign`, `tun_startup_readiness`).
- Clang AddressSanitizer + UndefinedBehaviorSanitizer CTest: **6/6 passed**.
- Clang libFuzzer: **2,000 executions completed** with sanitizers; no
  reported crash within that bounded run.
- Synthetic replay research: 1,600 deterministic scenario/seed/width
  simulations exported; summary statistics and plot generated. No accepted
  duplicate or deliberately re-submitted previously seen ID.
- Local environment lacked privileged namespace/network setup, so the new
  startup gate has **not yet** been verified in WSL2 live traffic.

## Candidate release gates not yet satisfied

- Rerun end-to-end TUN ping and MTU test from `./run_vpn.sh` after applying
  upgrade; repeat cold starts with `evaluation/stability_smoke.sh 30`
  after stopping any existing tunnels, recording warnings and failures.
- Confirm new GitHub Actions `linux` and `sanitized-fuzz` jobs pass on PR.
- Review the complete diff, including `CMakeLists.txt`, before merging.
- Re-run direct/custom/WireGuard benchmarks if reporting post-upgrade figures.
- No third-party cryptographic audit, transport key rotation or resilient
  multi-peer operation. **Not a production VPN.**
