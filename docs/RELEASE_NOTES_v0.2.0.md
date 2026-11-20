# Proposed v0.2.0 — NOT TAGGED

This proposed educational release adds PSK-authenticated ephemeral X25519,
HKDF-SHA256 derived independent AES-256-GCM traffic keys, sequence-based
96-bit nonces, header AAD, a 128-packet anti-replay window, adversarial packet
and handshake tests, GitHub Actions CTest, seeded replay plot scripts, and a
reproducible direct/custom/WireGuard `iperf3`/`tc netem` comparison procedure.

**Release gate**: merge the changes, verify CI, run `run_vpn.sh` on Linux,
review the documented handshake limitations, collect real benchmark results,
then create a tag on the merged commit:

```bash
git tag -a v0.2.0 -m "Mini VPN authenticated experimental tunnel v0.2.0"
git push origin v0.2.0
```

Never claim an audit, complete key rotation, or unmeasured performance.
