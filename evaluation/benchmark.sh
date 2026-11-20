#!/usr/bin/env bash
# Measure directly comparable veth, custom TUN, and optional WireGuard paths
# in the SAME two Linux network namespaces already created by ./run_vpn.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
for tool in iperf3 ping tc python3 ip sudo; do command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 1; }; done
sudo -v
sudo ip netns exec vpn-client ip link show tun0 >/dev/null || { echo 'Run ./run_vpn.sh first' >&2; exit 1; }
sudo ip netns exec vpn-server ip link show tun1 >/dev/null
: "${DURATION:=8}"
: "${REPEATS:=3}"
: "${UDP_RATE:=20M}"
OUT="${1:-evaluation/results/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT/raw"
OUT="$(cd "$OUT" && pwd)"
SERVER_PID=''
cleanup() {
    sudo ip netns exec vpn-client tc qdisc del dev veth-client root 2>/dev/null || true
    sudo ip netns exec vpn-server tc qdisc del dev veth-server root 2>/dev/null || true
    [[ -z "$SERVER_PID" ]] || { sudo kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
}
trap cleanup EXIT
# Refuse to overwrite an existing netem profile; this is essential for parity.
if { sudo ip netns exec vpn-client tc qdisc show dev veth-client; sudo ip netns exec vpn-server tc qdisc show dev veth-server; } | grep -q netem; then
    echo 'Existing client netem qdisc detected; reset it before benchmarking' >&2
    exit 1
fi
sudo ip netns exec vpn-server iperf3 -s -p 5201 >"$OUT/iperf-server.log" 2>&1 &
SERVER_PID=$!
sleep 1
# Capture actual runtime environment along with the raw observations.
{
    date -u +'%Y-%m-%dT%H:%M:%SZ'
    uname -a
    grep -m1 'model name' /proc/cpuinfo || true
    iperf3 --version | head -2
    openssl version
    wg --version 2>&1 || true
    git rev-parse HEAD 2>/dev/null || echo 'git commit unavailable in archive'
    echo "DURATION=$DURATION REPEATS=$REPEATS UDP_RATE=$UDP_RATE"
} > "$OUT/environment.txt"

paths=(direct custom)
if sudo ip netns exec vpn-client ip link show wg0 >/dev/null 2>&1 &&
   sudo ip netns exec vpn-server ip link show wg1 >/dev/null 2>&1; then
    paths+=(wireguard)
fi
ip_for() {
    case "$1" in
        direct) echo 172.30.0.1 ;;
        custom) echo 10.10.0.1 ;;
        wireguard) echo 10.20.0.1 ;;
    esac
}
for condition in clean netem; do
    if [[ "$condition" == netem ]]; then
        # Same impairment profile on each underlying direction for all three paths.
        sudo ip netns exec vpn-client tc qdisc replace dev veth-client root \
            netem delay 20ms 5ms loss 1% reorder 10% 50%
        sudo ip netns exec vpn-server tc qdisc replace dev veth-server root \
            netem delay 20ms 5ms loss 1% reorder 10% 50%
    fi
    {
      echo "Condition: $condition; underlay qdisc stats at start"
      sudo ip netns exec vpn-client tc -s qdisc show dev veth-client
      sudo ip netns exec vpn-server tc -s qdisc show dev veth-server
    } > "$OUT/raw/$condition-netem-start.txt"
    for path in "${paths[@]}"; do
        dest=$(ip_for "$path")
        for ((repeat=1; repeat<=REPEATS; repeat++)); do
            label="$condition-$path-$repeat"
            sudo ip netns exec vpn-client ping -n -c 20 -i 0.2 -W 2 "$dest" \
                >"$OUT/raw/$label.ping.txt" || true
            sudo ip netns exec vpn-client iperf3 -c "$dest" -p 5201 -t "$DURATION" -J \
                >"$OUT/raw/$label.tcp.json"
            sudo ip netns exec vpn-client iperf3 -c "$dest" -p 5201 -u -b "$UDP_RATE" -t "$DURATION" -J \
                >"$OUT/raw/$label.udp.json"
            printf '%s: %s / %s complete\n' "$condition" "$path" "$repeat"
        done
    done
    {
      echo "Condition: $condition; underlay qdisc stats after test"
      sudo ip netns exec vpn-client tc -s qdisc show dev veth-client
      sudo ip netns exec vpn-server tc -s qdisc show dev veth-server
    } > "$OUT/raw/$condition-netem-end.txt"
done
python3 evaluation/parse_bench.py "$OUT/raw" > "$OUT/summary.csv"
python3 evaluation/summarize_bench.py "$OUT/summary.csv" > "$OUT/medians.csv"
echo "Results: $OUT/summary.csv and $OUT/medians.csv"
echo 'Save Linux kernel, CPU, OpenSSL, iperf3, and WireGuard versions with the results.'
