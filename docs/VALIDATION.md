# Validation record — proposed security upgrade

## Root-free local checks performed

- Platform: Linux container, GCC/OpenSSL and CMake C++17 toolchain.
- Configure/build: `cmake -S . -B build -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Release && cmake --build build -j2`
- CTest: **3/3 passed**, including `session_packets`, `handshake_auth`,
  `replay_window_model`.
- Replay study: 4,096 unique messages × 5 seeds per configuration.
  With a 128-tick simulated maximum delay and 20,480 original arrivals,
  out-of-window originals discarded were:

  | Replay window | Rejected originals | Drop rate |
  | ---: | ---: | ---: |
  | 32 | 13,029 | 63.62% |
  | 64 | 7,981 | 38.97% |
  | 128 | 0 | 0% |
  | 256 | 0 | 0% |
  | 512 | 0 | 0% |

  All immediate duplicate deliveries in the replay study were rejected.
  These are **simulated reordering observations** after authentication, not
  real network delivery or application loss measurements.
- Source includes the replay CSV/PNG and tools to reproduce the analysis.

## Checks **not** completed

- End-to-end tunnel, `ping`, IPv4 TUN MTU and background client/server
  execution. This container lacks `CAP_NET_ADMIN` / `CAP_NET_RAW`.
- `iperf3`, actual `tc netem` traffic under load, and WireGuard live throughput
  or latency measurements. Required networking tools/capabilities are absent.
- WireGuard source line-count comparison: needs a revision-pinned upstream
  kernel or WireGuard compatibility source checkout.
- GitHub Actions run on remote origin, remote branch, pull request, and version
  tag: GitHub connection is read-only and those actions were not performed.

This local result is **not** an independent audit, a production-readiness
finding, or a WireGuard performance claim. Follow `docs/BENCHMARKING.md` on a
privileged isolated Linux installation, then add a date, machine, exact commit,
raw measured values, median comparisons and reproducibility notes.
