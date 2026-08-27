# Verification evidence

Date: 2026-08-27

## Dependency alignment

`crates/ucan-core/Cargo.toml` and `crates/ucan-nostr/Cargo.toml` now require exact BLAKE3 `1.8.5`.
Cargo regenerated `Cargo.lock`.
The lock contains one `blake3` package entry at version `1.8.5`.

No hash domain, framing rule, feature meaning, or public authority type changed.

## Positive and negative checks

Passed:

- `ucan-core --all-features`: 96 tests;
- `ucan-nostr`: 12 tests;
- dependency posture: five tests, including aligned and deliberately drifted exact-pin cases;
- workspace tests with the external Hegel property names skipped;
- strict workspace Clippy across all targets and features;
- `cargo fmt --all -- --check`.

A first direct workspace run started the three external Hegel property tests.
The local Python server stopped making progress for more than nine minutes.
The process was terminated and is not counted as passing evidence.

## Nix rail

`nix flake check path:$PWD -L --builders ''` passed.
The sandbox-safe nextest rail passed 353 tests.
It also passed strict Clippy, the durable-authority source check, production-readiness checks, and the Aeneas time-bounds evidence check.

## Bounded conclusion

The checked UCAN graph composes its peer-authentication and Nostr crates on one BLAKE3 cohort.
This evidence does not prove BLAKE3 implementation correctness, UCAN cryptographic correctness, every downstream graph, or release eligibility.
