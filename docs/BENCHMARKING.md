# Reproducible benchmark protocol — custom tunnel vs WireGuard

## Preconditions

Ubuntu/Linux kernel with TUN, network namespaces, `tc netem`, kernel WireGuard,
`sudo`, `iperf3`, `ip`, `wg`, OpenSSL and `ping` available. WSL2 may lack relevant
kernel/module or namespace support, so prefer a dedicated Linux VM if needed.
Run only on namespaces and interfaces you own.

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev iproute2 \
    iputils-ping iperf3 wireguard-tools python3 python3-matplotlib
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Terminal A, keep the script running:

```bash
./run_vpn.sh
```

Terminal B, after the custom tunnel reports ready:

```bash
sudo bash evaluation/setup_wireguard.sh
bash evaluation/benchmark.sh
sudo bash evaluation/teardown_wireguard.sh
```

For each condition (`clean` and bidirectional netem `delay 20ms 5ms loss 1%
reorder 10% 50%`), the benchmark runs the *same* three endpoints within the
same namespaces:

- Direct: client `172.30.0.2` -> server `172.30.0.1` over veth.
- Custom tunnel: `10.10.0.2` -> `10.10.0.1` (AES-256-GCM userspace TUN).
- WireGuard: `10.20.0.2` -> `10.20.0.1` (Linux kernel WireGuard).

The script collects three repeated 8-second TCP iperf3 runs, 8-second UDP runs
at 20 Mbps and 20-packet ping RTT/loss samples for each condition. Output is
saved as timestamped raw JSON/text plus `summary.csv`, `medians.csv`, `environment.txt` and underlying `tc -s` snapshots. Publish **median** values and the original raw runs. Report range/standard deviation separately when useful, rather than only best runs. Record host CPU model,
process load, kernel, iperf3/OpenSSL/wg versions and capture any errors.

- `tcp_mbps_received`: net application throughput (iperf3 receiver).
- `tcp_retransmits`: transport reliability signal, **not packet loss rate**.
- `udp_loss_percent`: packet loss *as reported by iperf3* at fixed 20 Mbps.
- `udp_out_of_order`: may be absent depending on iperf3 version; record the
  actual field or report not available, do not fabricate reorder counts.
- `ping_avg_ms`: observed RTT, including namespace and scheduler noise.
- `ping_loss_percent`: ICMP packet loss, not equivalent to encrypted data loss.

Compute tunnel overhead per condition as `custom RTT - direct RTT`, and
`custom TCP throughput / direct TCP throughput`. Repeat for WireGuard. Different
MTUs, code paths, protocol handshakes, cryptographic primitives and TUN routing
mean results compare *systems*, not only cipher speeds.

`evaluation/loc.sh [PATH_TO_LINUX_KERNEL_OR_WIREGUARD_SOURCE]` reports raw line counts of the
project's active C++ implementation vs C and header files in the `drivers/net/wireguard` subtree of a user-provided Linux kernel checkout (or an explicitly selected WireGuard compatibility source directory). **LOC is not security or speed.** WireGuard's kernel module
and its userspace tools have different scopes, so these totals are inherently
non-equivalent; cite exact upstream repository and revision when reporting.

### Replay bitmap result and recommendation

Generate a plot using the seeded (synthetic) experiment:

```bash
./build/replay_study > evaluation/replay-results.csv
python3 evaluation/plot_replay.py evaluation/replay-results.csv \
    --out evaluation/replay-window.png
```

Under the existing synthetic max delay of 128 ticks, the **64-packet window**
dropped 7,981/20,480 legitimate original arrivals (39%). The **128-packet
window** dropped none in that model. Consequently this version uses a **128-
packet** bitmap by default: 16 bytes plus 8-byte high-water mark, compared to
8 + 8 bytes for a 64-packet bitmap. At a fixed 128-bit bitmap there is no
observable memory penalty per packet, only 8 bytes extra state per receiver.
Testing a wider window (256/512) under real workloads is recommended if
reordering regularly exceeds 128 sequence positions. A larger window will
allow more delayed originals but also retains more replay candidates; duplicates
remain blocked. The synthetic model is not evidence of real-life loss rates.
