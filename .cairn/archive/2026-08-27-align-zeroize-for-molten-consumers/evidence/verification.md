# Zeroize consumer-cohort verification

Verified on 2026-08-27 in the dedicated UCAN worktree.

## Baseline

Five dependency-posture tests and ten peer-authentication tests passed before the change. The lock still selected Zeroize `1.8.2`.

A patched Molten check then failed during dependency resolution. Iroh required Zeroize `^1.9`, while vendored UCAN required exact `1.8.2`.

## Alignment

Both UCAN-owned manifests now require exact Zeroize `1.9.0`. Cargo generated the updated lock entry and checksum.

The peer-authentication implementation input now names `zeroize@1.9.0`. The dependency review table records the same version and checksum.

The dependency-posture rail now checks these items:

- the root exact requirement;
- the `ucan-core` exact requirement;
- the single lock entry;
- the peer-authentication implementation input;
- one deliberately stale identity input.

## UCAN checks

The focused rail passed seven dependency-posture tests and ten peer-authentication tests.

The broad nextest rail passed 353 library and example tests. Two durable-authority source tests also passed.

Strict scoped Clippy passed with warnings denied. Scoped formatting and the full Nix flake check passed.

The external Hegel property target was not part of this bounded rail. Earlier runs stopped making progress, so this evidence does not count those properties.

## Molten consumer check

The consumer check used Molten `origin/molten` revision `d4785791ec68e3092cca4fb95c7cb54144eb00a7` in a temporary detached worktree.

The temporary lock reconciled `serde_json` from `1.0.150` to UCAN's exact `1.0.149`. It did not change the source repository.

Cargo then checked the Molten library with the candidate Basalt path. The graph selected Zeroize `1.9.0`, `iddqd 0.4.5`, and BLAKE3 `1.8.5`.

The check completed successfully. The temporary worktree was removed after the result.

## Claim boundary

This evidence proves tested dependency resolution and source-label alignment only. It does not prove memory erasure, cryptographic correctness, or Molten release eligibility.
