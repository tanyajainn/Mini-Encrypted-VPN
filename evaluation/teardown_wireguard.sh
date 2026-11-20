#!/usr/bin/env bash
set -euo pipefail
sudo ip netns exec vpn-client ip link delete wg0 2>/dev/null || true
sudo ip netns exec vpn-server ip link delete wg1 2>/dev/null || true
printf 'Removed WireGuard namespace interfaces.\n'
