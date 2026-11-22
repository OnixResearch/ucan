## Why

The Nostr adapter pins `k256 0.13.4`. That version reaches `crypto-bigint 0.5.5`, which `RUSTSEC-2026-0387` reports for timing variability in operations intended to be constant-time. The patched release is `crypto-bigint 0.7.6`. `k256 0.14.0` resolves a patched `crypto-bigint`, so the advisory leaves the locked graph instead of being pinned away.

Basalt vendors UCAN and already carries this adapter change. Its vendored snapshot must match a real UCAN revision again.

## What Changes

- Require exact `k256 0.14.0` in `crates/ucan-nostr`.
- Convert x-only public-key bytes to `k256::FieldBytes` at the three verifying-key construction sites, and convert the adapter test secret the same way. Schnorr signing and verification calls stay unchanged.
- Update `Cargo.lock` for `k256 0.14.0` and its required companion crates only.
- Rename the Nostr implementation-identity input from `k256@0.13.4` to `k256@0.14.0`. The adapter implementation identity changes from `38ee3e2b…6dc3` to `8d93504d…9392`.
- Extend the dependency-posture rail so the lock must resolve `k256 0.14.0`, the identity input must name `k256@0.14.0`, and no `crypto-bigint` below `0.7.6` may remain.
- Re-run the advisory audit and update the posture record and the Nostr dependency table.

## Impact

- **Files**: `crates/ucan-nostr/Cargo.toml`, `crates/ucan-nostr/src/model.rs`, `crates/ucan-nostr/src/protocol.rs`, `crates/ucan-nostr/src/context.rs`, `crates/ucan-nostr/src/tests.rs`, `Cargo.lock`, `tools/check-dependency-posture.rs`, `tests/dependency_posture.rs`, `docs/dependency-posture.md`, `docs/production-readiness.md`, `docs/nostr-identity-adapter.md`.
- **Testing**: workspace tests, the `issue_and_verify` example, scoped formatting and strict Clippy, the dependency-posture checker, the production-readiness checker, and Cairn validation.

This change alters the Nostr adapter implementation identity by design. Credentials issued before it keep their original identity and do not migrate. It does not alter NIP-01 identity, BIP-340 verification semantics, adapter identity framing, UCAN token paths, or authorization.
