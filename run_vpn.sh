#!/bin/bash

set -e

cd "$(dirname "$0")"

# Each launch starts a new session with independent keys for both directions.
umask 077
key_file=$(mktemp)
cleanup() {
    for pid in "${CLIENT_PID:-}" "${SERVER_PID:-}"; do
        if [[ -n "$pid" ]]; then
            sudo kill "$pid" 2>/dev/null || true
        fi
    done
    rm -f -- "$key_file"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
openssl rand -out "$key_file" 64
sudo -v

echo "=== Setting up VPN namespaces ==="

# Create namespaces if they don't exist
sudo ip netns add vpn-client 2>/dev/null || true
sudo ip netns add vpn-server 2>/dev/null || true

# Remove old veth interfaces if present
sudo ip netns exec vpn-client ip link delete veth-client 2>/dev/null || true
sudo ip netns exec vpn-server ip link delete veth-server 2>/dev/null || true

# Create veth pair
sudo ip link add veth-client type veth peer name veth-server

# Move each end into its namespace
sudo ip link set veth-client netns vpn-client
sudo ip link set veth-server netns vpn-server

# Configure client side
sudo ip netns exec vpn-client ip addr add 172.30.0.2/24 dev veth-client
sudo ip netns exec vpn-client ip link set veth-client up
sudo ip netns exec vpn-client ip link set lo up

# Configure server side
sudo ip netns exec vpn-server ip addr add 172.30.0.1/24 dev veth-server
sudo ip netns exec vpn-server ip link set veth-server up
sudo ip netns exec vpn-server ip link set lo up

echo "=== Starting VPN server ==="

sudo ip netns exec vpn-server ./build/vpn_server < "$key_file" &
SERVER_PID=$!

sleep 1

echo "=== Starting VPN client ==="

sudo ip netns exec vpn-client ./build/vpn_client < "$key_file" &
CLIENT_PID=$!

echo "=== Waiting for TUN interfaces ==="

for i in {1..20}; do
    if sudo ip netns exec vpn-client ip link show tun0 >/dev/null 2>&1 &&
       sudo ip netns exec vpn-server ip link show tun1 >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done

echo "=== Configuring VPN tunnel ==="

sudo ip netns exec vpn-client ip addr add 10.10.0.2/32 dev tun0
sudo ip netns exec vpn-server ip addr add 10.10.0.1/32 dev tun1

sudo ip netns exec vpn-server ip link set tun1 up
sudo ip netns exec vpn-client ip link set tun0 up

sudo ip netns exec vpn-client ip route add 10.10.0.1/32 dev tun0
sudo ip netns exec vpn-server ip route add 10.10.0.2/32 dev tun1

echo
echo "================================"
echo "       VPN IS RUNNING"
echo "================================"
echo "Client: 10.10.0.2"
echo "Server: 10.10.0.1"
echo

sleep 1

echo "=== Testing VPN connectivity ==="

sudo ip netns exec vpn-client ping -c 3 10.10.0.1

echo
echo "================================"
echo "       VPN TEST COMPLETE"
echo "================================"
echo
echo "Press Ctrl+C to stop."

wait

