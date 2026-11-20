#!/usr/bin/env bash
# Counts selected implementation source files, not an apples-to-apples metric.
set -euo pipefail
cd "$(dirname "$0")/.."
echo 'Mini VPN active C++ implementation (src/ excluding test programs, include/):'
find src include -type f \( -name '*.cpp' -o -name '*.h' \) ! -name '*test*' -print0 \
    | xargs -0 wc -l | tail -1
printf 'Mini VPN revision: '
git rev-parse --short HEAD 2>/dev/null || echo 'not available in archive'
if [[ $# -eq 0 ]]; then
  echo 'Supply a checked-out WireGuard kernel source directory as argument to count its .c/.h files.'
  exit 0
fi
wgroot="$1"
if [[ -d "$wgroot/drivers/net/wireguard" ]]; then
  wgroot="$wgroot/drivers/net/wireguard"
elif [[ -d "$wgroot/src" && -f "$wgroot/src/device.c" ]]; then
  wgroot="$wgroot/src"  # WireGuard Linux compatibility tree.
fi
if [[ ! -d "$wgroot" ]] || ! find "$wgroot" -type f \( -name '*.c' -o -name '*.h' \) | grep -q .; then
    echo "WireGuard source directory not found at: $wgroot" >&2
    exit 1
fi
printf 'WireGuard selected source directory: %s\n' "$wgroot"
find "$wgroot" -type f \( -name '*.c' -o -name '*.h' \) -print0 \
    | xargs -0 wc -l | tail -1
printf 'WireGuard source revision: '
git -C "$wgroot" rev-parse --short HEAD 2>/dev/null || echo 'not available'
echo 'Warning: not equivalent in scope, language, kernel vs userspace, or functionality.'
