#!/usr/bin/env bash
# Two-namespace local test rig. Both peers receive the same, fresh 32-byte PSK
# through stdin; their traffic keys are NOT directly provisioned by this script.
set -euo pipefail
cd "$(dirname "$0")"
[[ -x ./build/vpn_server && -x ./build/vpn_client ]] || {
    echo 'Build first: cmake -S . -B build && cmake --build build' >&2
    exit 1
}
umask 077
psk_file=$(mktemp)
CLIENT_PID=''
SERVER_PID=''
cleanup() {
    # Clean up VPN processes, not just their sudo wrappers.
    local ns pid name
    for ns in vpn-client vpn-server; do
        while read -r pid; do
            [[ "$pid" =~ ^[0-9]+$ ]] || continue
            name=$(cat "/proc/$pid/comm" 2>/dev/null || true)
            case "$ns:$name" in
                vpn-client:vpn_client|vpn-server:vpn_server)
                    sudo kill "$pid" 2>/dev/null || true ;;
            esac
        done < <(sudo ip netns pids "$ns" 2>/dev/null || true)
    done
    for pid in "$CLIENT_PID" "$SERVER_PID"; do
        if [[ -n "$pid" ]]; then sudo kill "$pid" 2>/dev/null || true; fi
    done
    rm -f -- "$psk_file"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
openssl rand -out "$psk_file" 32
sudo -v

echo '=== Configuring isolated test namespaces ==='
sudo ip netns add vpn-client 2>/dev/null || true
sudo ip netns add vpn-server 2>/dev/null || true
sudo ip netns exec vpn-client ip link delete veth-client 2>/dev/null || true
sudo ip netns exec vpn-server ip link delete veth-server 2>/dev/null || true
sudo ip link add veth-client type veth peer name veth-server
sudo ip link set veth-client netns vpn-client
sudo ip link set veth-server netns vpn-server
sudo ip netns exec vpn-client ip addr add 172.30.0.2/24 dev veth-client
sudo ip netns exec vpn-client ip link set veth-client mtu 1500 up
sudo ip netns exec vpn-client ip link set lo up
sudo ip netns exec vpn-server ip addr add 172.30.0.1/24 dev veth-server
sudo ip netns exec vpn-server ip link set veth-server mtu 1500 up
sudo ip netns exec vpn-server ip link set lo up

echo '=== Starting authenticated X25519 server + client ==='
sudo ip netns exec vpn-server ./build/vpn_server < "$psk_file" &
SERVER_PID=$!
sleep 0.5
sudo ip netns exec vpn-client ./build/vpn_client < "$psk_file" &
CLIENT_PID=$!

ready=0
for i in {1..40}; do
    if sudo ip netns exec vpn-client ip link show tun0 >/dev/null 2>&1 &&
       sudo ip netns exec vpn-server ip link show tun1 >/dev/null 2>&1; then
        ready=1; break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null || ! kill -0 "$CLIENT_PID" 2>/dev/null; then break; fi
    sleep 0.25
done
if [[ "$ready" -ne 1 ]]; then
    echo 'Handshake or TUN setup failed; see client/server output above.' >&2
    exit 1
fi
# Finish the complete two-sided address, MTU and route configuration
# before enabling either interface. The daemons wait for IFF_UP.
sudo ip netns exec vpn-client ip addr add 10.10.0.2/32 dev tun0
sudo ip netns exec vpn-server ip addr add 10.10.0.1/32 dev tun1
sudo ip netns exec vpn-client ip link set tun0 mtu 1433
sudo ip netns exec vpn-server ip link set tun1 mtu 1433
sudo ip netns exec vpn-client ip link set tun0 up
sudo ip netns exec vpn-server ip link set tun1 up
sudo ip netns exec vpn-client ip route add 10.10.0.1/32 dev tun0
sudo ip netns exec vpn-server ip route add 10.10.0.2/32 dev tun1

echo '=== Connectivity and MTU checks ==='
sudo ip netns exec vpn-client ping -c 3 -W 2 10.10.0.1
sudo ip netns exec vpn-client ping -M do -s 1405 -c 3 -W 2 10.10.0.1
printf '\nTunnel running (10.10.0.2 -> 10.10.0.1). Press Ctrl+C to stop.\n'
wait
