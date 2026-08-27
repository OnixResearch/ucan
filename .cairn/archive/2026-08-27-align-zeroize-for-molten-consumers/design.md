## Context

The reviewed BLAKE3 cohort now composes, but Cargo next rejects UCAN's exact Zeroize `1.8.2` against Iroh's `^1.9` requirement.

## Decision

Set both UCAN-owned exact Zeroize requirements to `1.9.0`. Regenerate `Cargo.lock` with Cargo.

Update the peer-authentication implementation revision input to name `zeroize@1.9.0`. Update the reviewed dependency table with the lockfile checksum.

Extend `tests/dependency_posture.rs` to bind both manifests, the lock, and the implementation identity. A deliberately drifted identity must fail.

## Compatibility

Zeroize `1.9.0` preserves the APIs used by UCAN. The exact cohort now matches Molten's Iroh requirement.

The implementation identity changes by design. Old receipts do not migrate or gain authority.

## Verification

Run focused dependency and peer-authentication tests before and after the change. Run broad nextest, strict Clippy, formatting, Nix, Cairn, and the patched Molten check.

## Non-claims

A resolved graph and passing tests do not prove memory erasure on every platform. They do not prove UCAN cryptographic correctness or Molten release eligibility.
