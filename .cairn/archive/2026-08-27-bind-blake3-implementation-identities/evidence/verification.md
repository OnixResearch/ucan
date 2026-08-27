# BLAKE3 implementation-identity verification

Verified on 2026-08-27 in the dedicated UCAN worktree.

## Baseline

The existing dependency-posture test passed five tests before the repair. Ten focused peer-authentication tests and one Nostr context test also passed.

Those tests did not detect the stale `blake3@1.8.4` identity inputs. The manifests and lock already resolved BLAKE3 `1.8.5`.

## Repair

The peer-authentication and Nostr implementation revision inputs now name BLAKE3 `1.8.5`.

The two dependency tables now record version `1.8.5` and registry checksum `0aa83c34e62843d924f905e0f5c866eb1dd6545fc4d719e803d9ba6030371fce`.

The dependency-posture test binds these items:

- both exact manifest requirements;
- the single lock entry;
- both implementation-identity inputs;
- one deliberately drifted manifest;
- one deliberately drifted identity input.

## Focused checks

The repaired source passed these checks:

- five dependency-posture tests;
- ten peer-authentication tests;
- one Nostr context test;
- two durable-authority source tests;
- scoped Rust formatting.

## Broad checks

The scoped nextest rail passed 353 library and example tests. Strict scoped Clippy passed with warnings denied.

The external Hegel property target was not part of this bounded rail. Earlier runs stopped making progress, so this evidence does not count those properties.

## Nix

The first Nix run found that the clean Cargo source excludes documentation files. The compile-time rail was then limited to manifests, lock data, and Rust identity inputs.

The documentation tables remain corrected review artifacts. The final `nix flake check -L --builders ''` passed all supported-system checks.

The new `blake3-identity-posture` check ran the positive and negative dependency-posture cases in the Nix sandbox.

## Claim boundary

This evidence proves tested source-label and dependency-cohort alignment only. It does not prove BLAKE3 correctness, UCAN cryptographic correctness, or universal consumer compatibility.
