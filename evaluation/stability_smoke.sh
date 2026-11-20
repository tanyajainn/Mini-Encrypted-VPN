#!/usr/bin/env bash
# Repeated privileged cold-start regression. Run only on a controlled WSL2/Linux
# machine with both custom VPN and WireGuard stopped (no live sessions to disrupt).
# Usage: bash evaluation/stability_smoke.sh [runs=5] [output_dir]
set -euo pipefail
cd "$(dirname "$0")/.."
RUNS=${1:-5}
[[ "$RUNS" =~ ^[1-9][0-9]*$ ]] || { echo 'runs must be a positive integer' >&2; exit 2; }
OUT=${2:-evaluation/results/stability-$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd)
command -v timeout >/dev/null || { echo 'missing coreutils timeout' >&2; exit 1; }
sudo -v
printf 'run,exit_status,completed_pings,tun_write_eio\n' > "$OUT/startups.csv"
fail=0
for ((i=1; i<=RUNS; ++i)); do
    logfile="$OUT/run-$i.log"
    set +e
    # run_vpn.sh does not exit after its pings; timeout is expected.
    timeout -s INT --kill-after=3 22 ./run_vpn.sh >"$logfile" 2>&1
    result=$?
    set -e
    if grep -q 'Tunnel running' "$logfile"; then complete=1; else complete=0; fi
    if grep -Eq '^write tun[01]:.*Input/output error|tun[01] did not become UP' "$logfile"; then eio=1; else eio=0; fi
    printf '%d,%d,%d,%d\n' "$i" "$result" "$complete" "$eio" >> "$OUT/startups.csv"
    if [[ "$complete" != 1 || "$eio" != 0 ]]; then fail=$((fail + 1)); fi
    echo "cold-start $i/$RUNS: connected=$complete startup_warning=$eio (log: $logfile)"
    sleep 1
 done
printf 'Reproducible startup dataset: %s/startups.csv\n' "$OUT"
[[ "$fail" == 0 ]] || { echo "$fail/$RUNS startup trials failed or warned" >&2; exit 1; }
