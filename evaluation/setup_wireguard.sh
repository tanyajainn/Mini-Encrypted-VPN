#!/usr/bin/env bash
# Configure WireGuard in the same vpn-client and vpn-server namespaces, over
# the same veth pair, with independent tunnel addresses and UDP port 9001.
set -euo pipefail
for tool in ip wg sudo; do command -v "$tool" >/dev/null || { echo "Missing: $tool" >&2; exit 1; }; done
sudo -v
sudo ip netns exec vpn-client ip link show veth-client >/dev/null
sudo ip netns exec vpn-server ip link show veth-server >/dev/null
if sudo ip netns exec vpn-client ip link show wg0 >/dev/null 2>&1 || \
   sudo ip netns exec vpn-server ip link show wg1 >/dev/null 2>&1; then
    echo 'wg0 already exists. Run evaluation/teardown_wireguard.sh to reset.' >&2
    exit 1
fi
umask 077
KEYDIR=$(mktemp -d)
cleanup() { rm -rf -- "$KEYDIR"; }
trap cleanup EXIT
wg genkey >"$KEYDIR/c-private"
wg genkey >"$KEYDIR/s-private"
wg pubkey <"$KEYDIR/c-private" >"$KEYDIR/c-public"
wg pubkey <"$KEYDIR/s-private" >"$KEYDIR/s-public"
sudo ip netns exec vpn-client ip link add wg0 type wireguard
sudo ip netns exec vpn-server ip link add wg1 type wireguard
sudo ip netns exec vpn-client wg set wg0 listen-port 9002 private-key "$KEYDIR/c-private" \
    peer "$(cat "$KEYDIR/s-public")" allowed-ips 10.20.0.1/32 \
    endpoint 172.30.0.1:9001 persistent-keepalive 25
sudo ip netns exec vpn-server wg set wg1 private-key "$KEYDIR/s-private" \
    peer "$(cat "$KEYDIR/c-public")" allowed-ips 10.20.0.2/32 \
    endpoint 172.30.0.2:9002 persistent-keepalive 25
sudo ip netns exec vpn-server wg set wg1 listen-port 9001
sudo ip netns exec vpn-client ip address add 10.20.0.2/32 dev wg0
sudo ip netns exec vpn-server ip address add 10.20.0.1/32 dev wg1
sudo ip netns exec vpn-client ip link set wg0 mtu 1420 up
sudo ip netns exec vpn-server ip link set wg1 mtu 1420 up
sudo ip netns exec vpn-client ip route add 10.20.0.1/32 dev wg0
sudo ip netns exec vpn-server ip route add 10.20.0.2/32 dev wg1
sudo ip netns exec vpn-client ping -c 2 -W 2 10.20.0.1
printf 'WireGuard peer ready in the same namespaces. Run evaluation/benchmark.sh.\n'
