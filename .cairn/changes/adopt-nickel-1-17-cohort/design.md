# Design: Adopt Nickel 1.17 for UCAN policy and evidence

## Context

UCAN uses Nickel for policy, proof profiles, readiness configuration, and evidence contracts. The current package set provides Nickel `1.16.0`.

## Decisions

### Decision: Pin the exact upstream evaluator

**Choice:** Select Nickel `1.17.0` from commit `1320a983e6c3d1e2fb53dd2464b084b4903b1426`.

Use a narrow source input when the current Nix package set lacks this version.

**Rationale:** A broad package-set update would mix unrelated protocol and tool changes into the migration.

### Decision: Preserve authority ownership

**Choice:** Nickel validates policy shape. UCAN Rust code retains token, proof-chain, caveat, replay, and revocation decisions.

**Rationale:** Configuration acceptance does not grant authority or trust.

### Decision: Test valid and invalid configuration

**Choice:** Run valid policy and proof fixtures. Reject malformed, missing-import, contract, unknown-field, stale, and identity-mismatch fixtures.

Regenerate `flake.lock` only with Nix lock commands.

**Rationale:** Negative fixtures protect the fail-closed authority boundary.

### Decision: Record bounded evaluator evidence

**Choice:** Relevant release evidence records the exact version and source commit.

The record does not prove key trust, revocation freshness, replay durability, or effect correctness.

## Risks and trade-offs

- Policy export and diagnostics can change without protocol changes.
- New validation can expose stale readiness fixtures.
- A passing configuration does not prove external authority facts.
