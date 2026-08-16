# UCAN Nickel Toolchain

## ADDED Requirements

### Requirement: UCAN pins Nickel 1.17 exactly

r[ucan.nickel_toolchain.cohort] UCAN MUST use Nickel `1.17.0` from upstream commit `1320a983e6c3d1e2fb53dd2464b084b4903b1426` for policy, proof, and release configuration.

#### Scenario: UCAN tools resolve

r[ucan.nickel_toolchain.cohort.resolve]
- GIVEN UCAN builds policy, proof, and readiness checks
- WHEN cohort admission runs
- THEN every Nickel command MUST use the exact reviewed evaluator

#### Scenario: An older or floating evaluator resolves

r[ucan.nickel_toolchain.cohort.older]
- GIVEN an ambient package, branch, or older pin supplies Nickel
- WHEN admission runs
- THEN admission MUST fail

### Requirement: UCAN authority remains outside Nickel

r[ucan.nickel_toolchain.boundary] Nickel MUST validate configuration shape only. UCAN Rust MUST retain token, proof-chain, caveat, revocation, replay, and authority decisions.

#### Scenario: Policy configuration passes

r[ucan.nickel_toolchain.boundary.policy]
- GIVEN Nickel accepts a policy value
- WHEN UCAN verifies a request
- THEN UCAN MUST still apply its complete authority checks

### Requirement: Compatibility includes negative authority configuration

r[ucan.nickel_toolchain.compatibility] Tests MUST cover valid policy and proof fixtures plus malformed, missing-import, contract, unknown-field, stale, identity-mismatch, and cohort cases.

#### Scenario: The fixture matrix runs

r[ucan.nickel_toolchain.compatibility.matrix]
- GIVEN representative valid and invalid configurations
- WHEN Nickel `1.17.0` evaluates them
- THEN valid configurations MUST retain supported outcomes
- AND invalid configurations MUST fail closed

### Requirement: Evidence records bounded evaluator facts

r[ucan.nickel_toolchain.evidence] Nickel-dependent evidence MUST record the exact evaluator version and source commit. It MUST retain authority and freshness non-claims.

#### Scenario: Release evidence is generated

r[ucan.nickel_toolchain.evidence.release]
- GIVEN Nickel-backed checks pass
- WHEN evidence is emitted
- THEN the evaluator identity MUST be explicit
- AND the evidence MUST NOT claim key trust, revocation freshness, or replay durability

### Requirement: The repository validation rail passes

r[ucan.nickel_toolchain.validation] The change MUST pass policy fixtures, proof checks, readiness checks, formatting, Clippy, Cairn gates, and relevant Nix checks.

#### Scenario: Validation completes

r[ucan.nickel_toolchain.validation.completes]
- GIVEN the pin, fixtures, and evidence are current
- WHEN validation runs
- THEN every required check MUST pass or report one exact blocker
