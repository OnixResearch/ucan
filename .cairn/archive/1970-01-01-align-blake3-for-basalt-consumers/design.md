## Context

Two UCAN mechanism crates use an exact BLAKE3 pin. Basalt enables those crates and must coexist with consumers that already require exact `1.8.5`.

## Decision

Update both exact UCAN pins together and let Cargo regenerate the lock. Keep every API, feature, framing domain, and authority boundary unchanged.

Do not add a patch override, duplicate hash implementation, warning allowance, or dependency fallback. A single reviewed exact version keeps the graph auditable.

## Verification

Run positive workspace and focused core tests. Run negative compile and policy tests already present in the workspace. Deny Clippy warnings and evaluate the Nix flake checks.

## Non-claims

Version alignment does not prove BLAKE3 implementation correctness, UCAN cryptographic correctness, downstream compatibility beyond tested graphs, or release eligibility.
