# Live VPN Benchmark — November 20, 2026

## Test environment
- OS: Ubuntu on WSL2
- Kernel: 6.18.58.1-microsoft-standard-WSL2
- CPU: Intel Core Ultra 7 355
- OpenSSL: 3.0.13
- iperf3: 3.16
- WireGuard tools: 1.0.20210914
- Three repetitions per path and condition

## Clean network results

| Path | TCP Mbps | Average RTT (ms) |
|---|---:|---:|
| Direct | 64261.680 | 0.063 |
| Custom VPN | 1690.508 | 0.652 |
| WireGuard | 1677.870 | 0.732 |

## Network impairment results

tc netem: delay 20ms 5ms, loss 1%,
reorder 10% 50%, in both directions.

| Path | TCP Mbps | RTT (ms) | UDP loss |
|---|---:|---:|---:|
| Direct | 5.345 | 40.755 | 0.927% |
| Custom VPN | 3.654 | 40.783 | 0.988% |
| WireGuard | 3.651 | 41.313 | 1.047% |

## Limitations
- Local WSL2 namespaces, not internet deployment.
- Only three repetitions per condition.
- UDP rate fixed at 20 Mbps.
- UDP out-of-order counters were unavailable.
- Results do not establish superiority to WireGuard.
- Raw benchmark data remain stored locally.
