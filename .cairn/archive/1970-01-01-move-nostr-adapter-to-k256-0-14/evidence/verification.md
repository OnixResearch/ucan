# k256 0.14 verification

Verified on 2026-11-22 in a fresh UCAN clone at `6b12853e5f6af1fa5c8b4532eca20e3078fdf114`.

## Toolchain

The `nix develop` shell could not start: a store-path lock on the flake's `tests/hegel-constraints.txt` input was held by another session. The Cargo rails therefore ran under the environment that direnv captured from this flake's development shell. That shell used the same `flake.lock`, the same `rust-toolchain.toml`, and the same development package set. Toolchain: `/nix/store/kna68qfj6p56s866bx6q6xzrkdlmzi79-rust-default-1.97.0-nightly-2026-04-19` (`rustc 1.97.0-nightly 0febdbab2 2026-04-18`).

## Baseline

At `6b12853e`, `cargo audit` reported `RUSTSEC-2026-0387` for `crypto-bigint 0.5.5`. The only path was `ucan-nostr` → `k256 0.13.4` → `elliptic-curve 0.13.8`.

## Lock change

`cargo update -p k256 --precise 0.14.0` changed only the `k256` closure:

- removed `base16ct 0.2.0`, `crypto-bigint 0.5.5`, `ecdsa 0.16.9`, `elliptic-curve 0.13.8`, `ff 0.13.1`, `group 0.13.0`, `k256 0.13.4`, and `sec1 0.7.3`;
- added `base16ct 1.0.0`, `block-buffer 0.12.1`, `cmov 0.5.4`, `const-oid 0.10.3`, `cpubits 0.1.1`, `crypto-bigint 0.7.11`, `crypto-common 0.2.2`, `ctutils 0.4.8`, `der 0.8.3`, `digest 0.11.3`, `ecdsa 0.17.0`, `elliptic-curve 0.14.3`, `ff 0.14.0`, `group 0.14.0`, `hybrid-array 0.4.15`, `k256 0.14.0`, `pkcs8 0.11.0`, `primefield 0.14.0`, `primeorder 0.14.0`, `rand_core 0.10.1`, `sec1 0.8.1`, `serdect 0.4.3`, `sha2 0.11.1`, `signature 3.0.0`, `spki 0.8.1`, and `wnaf 0.14.1`.

## Implementation identity

The Nostr implementation-identity input in `crates/ucan-nostr/src/context.rs` now names `k256@0.14.0` instead of `k256@0.13.4`. A throwaway probe outside the repository verified a signed NIP-42 event with the adapter's public `verify_credential` and printed `implementation_identity().to_hex()`:

- before the edit, and for Basalt `1c142e2`'s vendored adapter: `38ee3e2bbf9af15fbf67910d11f2932326b42ea67ace165b711680a9dc5d6dc3`;
- after the edit: `8d93504d1473a6ce668eea30cd81246186187470b3650131f603de8a05219392`.

No UCAN fixture, test, document, or Nickel contract pinned the old label or hash, so no other pinned value changed.

## BIP-340 verification vectors

`k256 0.14` computes R in verification on a different, variable-time wNAF path. `crates/ucan-nostr/src/tests.rs` now runs all 19 verification rows of `https://raw.githubusercontent.com/bitcoin/bips/c38071c8c45a1fc50cecaac0d82d99e3bbd56911/bip-0340/test-vectors.csv` (SHA-256 `34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d`) through `verify_bip340_message`. A script outside the repository compared the test table with the downloaded file: every public key, message, signature, published result, and comment matches verbatim.

All 19 vectors produce their published results. Vectors 0–4 and 15–18 are accepted, including the 0-, 1-, 17-, and 100-byte messages. The rejections map to typed issues as follows:

- vectors 5 and 14 (public key not on the curve, or at least the field size): `InvalidPublicKeyPoint`;
- vectors 12 and 13 (`r` equal to the field size, `s` equal to the group order): `InvalidSignatureEncoding`;
- vectors 6, 7, and 8 (odd R, negated message, negated `s`): `SignatureInvalid`;
- vectors 9, 10, and 11 (`r` = 0, `r` = 1, `r` not an x coordinate): the test requires one of the two signature issues, because the curve library decides which stage rejects a degenerate `r`. `k256 0.14.0` currently returns `InvalidSignatureEncoding` for vector 9 and `SignatureInvalid` for vectors 10 and 11.

## Checks

All of these exited 0 after the identity change:

- `cargo fmt --manifest-path Cargo.toml -p ucan -p ucan-core -p ucan-nostr --check`;
- the README Clippy command and the flake Clippy command with `ucan-core/peer-auth`, both with `-D warnings`;
- `cargo test --locked -p ucan-nostr`: 12 tests;
- `cargo test --locked -p ucan --test dependency_posture`: 9 tests, including a drifted `k256` manifest, a stale `k256` identity label, and a drifted `crypto-bigint` lock;
- `cargo test --workspace --locked`: 392 tests in 11 suites;
- `cargo run --locked --example issue_and_verify`;
- `tools/check-dependency-posture.rs --root .`: five PASS lines;
- `cargo run --locked --bin check-production-readiness -- check --root . --nickel nickel`;
- `cairn validate --root . --strict`.

One workspace run on a host with load average near 100 failed `token::tests::repeated_caveated_issuance_retains_bounded_memory` in the root `ucan` crate: 70,867 retained bytes against a 65,536-byte bound. The root crate does not depend on `ucan-nostr`. The test passed alone and in a full workspace rerun, so it is recorded as load-sensitive, not as a result of this change.

Run against the unchanged `6b12853e` lock, the posture checker exits 1 because the lock resolves `k256 0.13.4`.

With the new lock, `cargo audit` (RustSec `advisory-db` `55e1c3dfbd834237a05bbbf7b50ba3b5be27b662`) reports no vulnerability. Its two warnings are `RUSTSEC-2024-0436` (`paste`) and `RUSTSEC-2026-0486` (`rustix 1.1.4`, dev-only). Both predate this change.

## Nix rails

Both rails ran on revision `4ec3ac9a` after the store lock cleared:

- `nix develop . --option builders '' -c cargo test --workspace --locked` exited 0: 392 tests passed and none failed in 11 suites.
- `nix flake check -L --keep-going --option builders ''` exited 0 on `x86_64-linux` and reported "all checks passed!". It evaluated 14 checks, including `dependency-posture`, `blake3-identity-posture`, `nextest`, `clippy`, `fmt`, `minimal-profile`, `minimal-tests`, and `production-readiness`, and every check output is in the store. The run did not check `aarch64-linux`, `aarch64-darwin`, or `x86_64-darwin`.

## Claim boundary

This evidence covers tested dependency resolution and adapter compatibility only. It does not prove `k256` or `crypto-bigint` constant-time behavior, BIP-340 implementation correctness, or release eligibility.
