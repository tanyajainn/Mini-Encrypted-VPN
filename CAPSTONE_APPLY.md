# Apply the fourth-year-capstone enhancement candidate (v0.3.0)

This ZIP is **a source overlay**, not an independently deployable VPN.
It is intended for the already-merged repository at
`https://github.com/tanyajainn/Mini-Encrypted-VPN`.

## Install on WSL Ubuntu

First download the ZIP to Windows `C:\Users\istgt\Downloads`.
Do not run the commands in Windows PowerShell; use your Ubuntu prompt.

```bash
cd ~/Mini-Encrypted-VPN-security-work
git switch main
git pull --ff-only origin main
git switch -c capstone-v0.3.0
unzip -o /mnt/c/Users/istgt/Downloads/Mini-Encrypted-VPN-capstone-v0.3.0-candidate.zip -d .
```

This copies only the changed and newly added files; it preserves untouched
repository files, including `gateway/` and `LICENSE`. Inspect before running:

```bash
git status --short
git diff --stat
```

## Root-free tests (run before any network setup)

```bash
sudo apt-get update
sudo apt-get install -y cmake g++ clang libssl-dev python3
cmake -S . -B build -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
ctest --test-dir build --output-on-failure
cmake -S . -B build-sanitized -DCMAKE_CXX_COMPILER=clang++ \
  -DBUILD_TESTING=ON -DENABLE_SANITIZERS=ON -DBUILD_FUZZING=ON
cmake --build build-sanitized -j
ctest --test-dir build-sanitized --output-on-failure
./build-sanitized/packet_fuzzer -runs=2000 -max_len=256
```

## Reproduce the research

```bash
./build/replay_robustness > evaluation/replay-robustness.csv
python3 evaluation/analyze_robustness.py evaluation/replay-robustness.csv \
  evaluation/replay-robustness-summary.csv
# Optional: sudo apt-get install -y python3-matplotlib
python3 evaluation/plot_robustness.py \
  evaluation/replay-robustness-summary.csv evaluation/replay-robustness.png
```

## Live Linux/WSL acceptance test

Make sure no old `./run_vpn.sh` or WireGuard namespaces are in use.
The launch script **recreates the veth underlay**, disrupting existing tunnels.

```bash
chmod +x run_vpn.sh evaluation/stability_smoke.sh
./run_vpn.sh
# After both ping tests pass, press Ctrl+C.
# For repeated cold-start evidence, with both tunnels stopped:
bash evaluation/stability_smoke.sh 5
```

The `stability_smoke.sh` command intentionally takes up to 22 seconds per run,
so start with 5 before choosing a longer 30-run experiment. Inspect its CSV
and raw logs. **If startup failures occur, stop: do not merge or tag.**

## Publish through a pull request (not a release yet)

After reviewing the resulting diff and after the tests pass:

```bash
git add -A
git diff --cached --check
git commit -m "Add capstone reliability, fuzzing and replay research"
git push -u origin capstone-v0.3.0
```

Open the PR to `main`; verify both new GitHub Actions jobs (standard and
sanitizer/fuzz), rerun live tests under WSL, and only then merge. This patch
**does not** create a tag, release, or claim a production-grade VPN.

## Source and evidence

- `docs/CAPSTONE_UPGRADE.md` — modifications, research question, tests and work remaining.
- `docs/CAPSTONE_RESULTS.md` — measured synthetic findings and prior baseline measurements.
- `docs/VALIDATION.md` — what has actually been verified and what has not.
- `evaluation/replay-robustness.csv`, `-summary.csv`, `.png` — reproducible model evidence.
