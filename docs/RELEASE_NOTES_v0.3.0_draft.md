# Candidate v0.3.0 capstone upgrade — DRAFT, NOT PUBLISHED

**Do not tag this candidate until the operator confirms a clean Linux/WSL2
end-to-end run and the new GitHub Actions sanitizer/fuzz job succeeds.**

Improvements since v0.2.0:

- Gate forwarding on TUN interface readiness and complete namespace setup
  before activating either interface (addresses a startup race).
- Add deterministic 96-frame packet-attack campaign and root-free interface
  readiness test, expanding CTest from 3 suites to 6.
- Add Clang ASan/UBSan CI and a bounded coverage-guided libFuzzer packet parser
  smoke test; longer fuzzing remains recommended.
- Add a 1,600-run, four-profile reproducible synthetic replay-window study,
  bootstrap confidence bounds, independent oracle checks, memory tradeoffs,
  and an explicit limitations section. Existing runtime replay width remains 128.
- Reconcile validation claims, separating original WSL2 measurements from
  newly implemented candidate code that still requires live retesting.

Experimental research software only. No independent cryptographic review,
automated rekey or assurance of anonymity, DoS resistance or production safety.
