# Applying the v0.2.0 security upgrade

This ZIP is a **source-file overlay** for the existing GitHub repository, **not**
a stand-alone clone or an already published release. It intentionally excludes
unchanged `gateway/` content and the existing `LICENSE`.

## On Ubuntu / WSL2

1. Back up or commit any uncommitted local edits first. This archive replaces
   `README.md`, `.gitignore`, `CMakeLists.txt`, `run_vpn.sh`, the listed C++
   source/headers, and adds `docs/`, `tests/`, `evaluation/`, and CI files.
2. Clone the real project (if not already present), open a new branch, and
   extract the **contents of this ZIP at the root of the repository**:

   ```bash
   git clone https://github.com/tanyajainn/Mini-Encrypted-VPN.git
   cd Mini-Encrypted-VPN
   git switch -c security-v0.2.0
   unzip -o ~/Downloads/Mini-Encrypted-VPN-security-upgrade-v0.2.0.zip -d .
   ```

   Change the path to the ZIP if it lives somewhere else. If using a prior
   clone, do not rerun `git clone`; start at `cd Mini-Encrypted-VPN`.

3. Remove the tracked Windows download-stream artifact. In the GitHub repo its
   colon-like separator may be a Unicode character, so use a glob:

   ```bash
   find . -maxdepth 1 -type f -name 'README.md*Zone.Identifier' -print -delete
   chmod +x run_vpn.sh evaluation/*.sh
   cmake -S . -B build -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Release
   cmake --build build -j
   ctest --test-dir build --output-on-failure
   git status --short
   ```

4. On a Linux VM or WSL2 kernel with TUN and `CAP_NET_ADMIN`, run two terminals:

   ```bash
   # Terminal 1
   ./run_vpn.sh
   # Terminal 2, only after the tunnel is running
   sudo bash evaluation/setup_wireguard.sh
   bash evaluation/benchmark.sh
   sudo bash evaluation/teardown_wireguard.sh
   ```

   Required packages are in `docs/BENCHMARKING.md`. This runs only in local
   network namespaces. It requires root network privileges and `iperf3`.
   Results appear in `evaluation/results/` (gitignored to avoid leaking host
   details). This ZIP does **not** include fabricated throughput results.

5. Inspect the changes, especially the educational security model, then
   commit/push the branch and open a pull request:

   ```bash
   git add -A
   git commit -m "Document and test authenticated experimental tunnel"
   git push -u origin security-v0.2.0
   ```

   Run GitHub Actions and the real network tests. Only after review and merge,
   create a signed or annotated version tag according to
   `docs/RELEASE_NOTES_v0.2.0.md`. The tag has **not** been created by this ZIP.

## Important limits

- This is a custom educational PSK-authenticated X25519 protocol, **not** a
  compatible or independently reviewed implementation of WireGuard/Noise.
- The 32-byte PSK is passed to both peers from a locally generated temporary
  file. Real remote key provisioning is intentionally out of scope.
- Reordered valid packets **within** the replay window should be accepted;
  replays and very old originals must be rejected. A reset of the sender nonce
  counter with the same key is a **severe GCM misuse**, even if the receiver
  subsequently rejects the duplicate sequence number.
- GitHub Actions here only runs root-free unit tests; it does not establish
  a successful kernel TUN, netem, or WireGuard benchmark.
