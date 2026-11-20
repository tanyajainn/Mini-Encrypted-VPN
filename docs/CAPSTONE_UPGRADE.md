# Capstone upgrade — validation and research plan (candidate v0.3.0)

**Status:** Patch prepared and tested locally; NOT merged/released as v0.3.0.
The current v0.2.0 educational implementation remains unaudited and unsuitable
for production deployment. Avoid claiming formal verification or equivalence
to WireGuard.

## Engineering improvements implemented

1. **TUN startup readiness gate**: each peer blocks after the authenticated
   handshake and before starting forwarders until its own TUN device is
   administratively UP. The namespace harness sets both IP addresses, MTUs,
   and routes before enabling the interfaces. This specifically addresses the
   earlier transient `write tun0/tun1: Input/output error` startup race.
   A live WSL rerun is still required to confirm the fix on the target machine.
2. **Extended adversarial test suite**: seeded, authenticated frames are
   subjected to *every possible single-byte position* bit flip, a range of
   truncations, duplicate delivery, and valid post-attack delivery. The
   ready-check test exercises existing/missing TUN interface states without root.
   This adds to existing spoofed-hello, key agreement, stale/reordered/replay,
   nonce-limit and nonce-reuse demonstration tests.
3. **Coverage-guided fuzzing + sanitizers**: Clang libFuzzer targets the packet
   parser with arbitrary bytes and mutations of a valid encrypted frame;
   ASan/UBSan run both unit tests and a bounded fuzz smoke in CI. CI fuzz smoke
   does NOT replace long-duration fuzzing; run longer locally before assessment.
4. **Reproducible research campaign**: 20 seeds, four synthetic delay profiles
   (uniform, truncated-normal, 85/15 burst, alternating), four delay ceilings
   (32/64/128/256 ticks), and five replay-window widths (32 to 512). An
   independent set-based oracle checks every sample, and the production 128-bit
   window must agree with it. Replays are reinserted and checked. Aggregation
   reports mean drop rate, seed-to-seed worst case, bootstrap confidence
   intervals and replay-state memory tradeoffs.

## Research question and evidence quality

**RQ:** Under which delay patterns does increasing a packet anti-replay window
minimize false rejection of legitimate late packets, and at what memory cost?

**Hypothesis:** A wider window decreases false late-packet rejection but
increases receiver bitmap memory; the preferred width depends strongly on the
arrival-delay distribution. Duplicate replays should remain rejected.

This is a **synthetic, post-authentication ordering model**, not a proof of
network reliability or an active-attack security guarantee. Tick delays are
relative sequence-generation steps, not milliseconds. The report deliberately
does **not** call the model a real packet capture. It also does not imply that
increasing the window adapts securely to an on-path attacker.

## Run the independent checks

```bash
cmake -S . -B build -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
ctest --test-dir build --output-on-failure
./build/replay_robustness > evaluation/replay-robustness.csv
python3 evaluation/analyze_robustness.py evaluation/replay-robustness.csv \
  evaluation/replay-robustness-summary.csv
python3 evaluation/plot_robustness.py \
  evaluation/replay-robustness-summary.csv evaluation/replay-robustness.png
```

For ASan/UBSan/libFuzzer, install `clang`, `libssl-dev`, `cmake` and run:

```bash
cmake -S . -B build-sanitized -DCMAKE_CXX_COMPILER=clang++ \
  -DENABLE_SANITIZERS=ON -DBUILD_FUZZING=ON -DBUILD_TESTING=ON
cmake --build build-sanitized -j
ctest --test-dir build-sanitized --output-on-failure
./build-sanitized/packet_fuzzer -runs=2000 -max_len=256
```

For a separate **live** end-to-end test in WSL2, rebuild and run `./run_vpn.sh`
(the harness requires sudo, TUN and network namespace privileges) and collect
both ping results. Repeat the WireGuard comparison after any changes that
materially affect performance. In GitHub Actions, only the root-free tests
run; live routing is not claimed to have been rerun by CI.

## Unresolved work for a genuine top-mark submission

- Demonstrate startup reliability in a repeated 30-run WSL2 smoke test
  (`bash evaluation/stability_smoke.sh 30`, **with all tunnels stopped**);
  collect errors and latency to tunnel-up (do not claim clean startup yet).
- Collect **authenticated arrival sequence traces** under varied `tc netem`
  profiles. Without a packet trace, the robustness model remains synthetic.
- Run multi-hour fuzzing across malformed handshakes and networking errors.
  Audit the PSK and session-key lifecycle and rekey/session-recovery design.
- Run multiple hosts/VMs with statistically supported performance evaluation,
  report full distributions and repeat on a second machine.
- Pin the upstream WireGuard revision and count source lines using the provided
  `evaluation/loc.sh`; interpret LOC only as descriptive, never security merit.
- Assemble a formal capstone paper: problem, hypotheses, prior work, protocol
  trust assumptions, controlled experiments, threats to validity, results,
  discussion, ethics, reproducibility, and honest limitations.

## References

- NIST SP 800-38D: GCM uniqueness requirements and IV construction guidance.
  https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf
- LLVM libFuzzer: coverage-guided fuzzing and sanitizer instrumentation.
  https://llvm.org/docs/LibFuzzer.html
