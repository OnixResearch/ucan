# Track Dependency Posture: Implementation Evidence

Date: 2026-08-16

## Advisory policy

- `deny.toml` (repo root, cargo-deny 0.20.2 compatible): a checked
  dependency-advisory policy with an `[advisories].ignore` list pinning
  `RUSTSEC-2024-0436` (paste) and `RUSTSEC-2026-0190` (anyhow) with explicit
  non-exploitable rationale, plus a `[licenses]` allow list covering the
  workspace licenses.
- `tools/check-dependency-posture.rs`: a zero-dependency rustc check run by
  the Nix `dependency-posture` gate. It validates the committed policy, the
  committed `Cargo.lock`, and the fixture rail.
- `cargo-deny/fixtures/`: `positive-locked.deny.toml` (both pins) and
  `negative-missing-pin.deny.toml` (paste pin dropped).
- `tests/dependency_posture.rs`: test-only include-rail asserting the pins,
  the license coverage, and the missing-pin rejection.

## Check wiring

- `flake.nix` adds the `dependency-posture` check: it compiles the checker
  with rustc, runs it against the repository root, and invokes
  `cargo-deny check advisories -D warnings -A advisory-not-detected` against
  the committed `Cargo.lock`. The check never resolves a fresh dependency
  set. If the online advisory-DB fetch is unavailable in the sandbox, the
  deterministic posture gate still passes; an unpinned applicable advisory
  always fails the gate.
- Note: `RUSTSEC-2026-0190` targets `anyhow`, which reaches only the
  vendored `repo_index` tooling module outside the workspace crate graph.
  cargo-deny therefore reports `advisory-not-detected` for the justified pin;
  the check registers that lint as allowed while `-D warnings` keeps every
  other advisory finding an error. The paste pin is in-graph and enforced.

## Checks run

- `tools/check-dependency-posture.rs` (local run): 4 PASS (policy accepts the
  locked pins; lockfile binds `paste` and `anyhow`; positive fixture
  accepted; negative fixture fails for the missing pin).
- `cargo-deny check advisories -D warnings -A advisory-not-detected` against
  the committed lock: `advisories ok`, exit 0.
- `cargo-deny` with the negative fixture (paste unpinned):
  `advisories FAILED`, exit 1, reporting RUSTSEC-2024-0436 with the paste
  unmaintained detail and dependency chain (hegeltest, dev ucan). This is
  the positive/negative executable evidence for the advisory rail.
- `cargo test --test dependency_posture`: 3 passed, 0 failed.
- `check-production-readiness check` with the available Nickel evaluator:
  `PASS catalog_blake3=d46317f0... profiles_accepted=3 profiles_rejected=7`.
  The generated catalog section is unchanged, so the machine-readable
  readiness output has no posture surface to regenerate; the posture record
  lives in `docs/production-readiness.md` and `docs/dependency-posture.md`.
- rustfmt: both Rust files fmt-clean.

## Non-claims

The posture covers the locked dependency set at the recorded revision. It
does not claim the absence of vulnerabilities in future bumps, unbuilt
crates outside the graph, cryptographic correctness, or authority correctness.
`cargo-deny`'s online advisory DB is advisory; the deterministic gate is the
enforcement boundary.
