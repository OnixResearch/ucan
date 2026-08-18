# Durable Authority State adoption evidence

## Baseline

Before adapter changes, 18 holder-invocation tests and 9 revocation-focused tests passed.
The primary UCAN worktree had unrelated edits to `README.md` and `examples/pentest_chain.rs`.
All work occurred in the dedicated `drain/adopt-durable-authority-state` worktree.

## Source

- Canonical RID: `rad:z3kGDT73ja8rewvGLwJFLF5MTx1ih`
- Admitted adapter: `https://seed.radicle.garden/z3kGDT73ja8rewvGLwJFLF5MTx1ih.git`
- Reviewed object: `a0de79303f3f45c18a34fff535b690a85cb3cf59`
- Packages: `replay-ledger-core` and `revocation-view-core`

Cargo resolves both packages at the same full object.
Crane consumes the checked `Cargo.lock`, and the Nix source check runs in the sandbox.
The positive source test passed.
The negative source test rejected GitHub, sibling, branch, tag, and path fallback forms.

## Implementation

`src/durable_authority.rs` provides two separate shell adapters.

`DurableHolderReplayAdmission` maps the verified audience, nonce, and holder request digest into the shared replay scope.
The caller supplies tenant, operation profile, generation, namespace, attempt, durability requirement, and persistence port.
First use applies the exact compare-and-swap reservation before success.
Duplicate, conflict, stale, uncertain, unavailable, malformed, and unknown-commit cases fail closed.

`DurableRevocationChecker` loads one caller-selected source through a caller-owned port.
The caller supplies minimum generation and current time.
Only current, complete, caller-authenticated snapshots can answer revoked or not revoked.
Stale, partial, unauthenticated, missing, and unavailable views fail closed through existing UCAN errors.

The `ucan-core` no-std package remains unchanged.
UCAN still performs all token, signature, profile, capability, and caveat checks before one final replay call.

## Validation

- New adapter tests: 7 passed.
- New exact-source tests: 2 passed.
- Existing holder-invocation tests after changes: 18 passed.
- Existing revocation-focused tests after changes: 9 passed.
- Sandbox-safe direct workspace scope: 343 library and example tests passed.
- Nix nextest: 353 passed.
- Formatting passed.
- Clippy passed with denied warnings for all first-party packages and targets.
- Dependency posture tests passed.
- Nickel toolchain fixtures passed.
- Production-readiness and Aeneas evidence checks passed.
- Cairn proposal, design, task, policy-freshness, and validation gates passed.
- Cairn traceability reported 66 of 180 accepted identifiers referenced.
- All 21 new durable-authority identifiers are referenced; 114 inherited identifiers remain missing.
- `nix flake check path:$PWD -L` passed with local builders.

A direct `cargo test --workspace` run reached all ordinary tests, then its three Hegel integration tests did not finish after one hour.
The process was stopped.
The documented sandbox-safe Nix test scope excludes Hegel and passed all 353 selected tests.

The Nix gate also exposed an existing Nickel-version check that exited before creating `$out`.
The check now continues to output creation after it accepts Nickel 1.17.

## Bounded portfolio search

The exact goal was a no-fallback UCAN integration that preserves final replay ordering and consumer-owned authority.
False completion included documentation-only adoption, copied state logic, direct Redb ownership, ambient sibling paths, floating source, replay before policy checks, or state receipts treated as authorization.

Three correlated serial lenses were used because subagents were not authorized:

| Family | Mechanism | Evidence | State |
|---|---|---|---|
| direct-core-adapter | UCAN shell implements existing traits over the two pure shared cores | focused and full tests pass | validated |
| concrete-storage-adapter | UCAN imports shared Redb shell | rejected because UCAN must not own application persistence | falsified |
| copied-consumer-logic | UCAN duplicates replay and revocation decisions | rejected by source identity and component ownership | falsified |

The surviving direct-core adapter was audited against duplicate, conflict, stale, incomplete, unauthenticated, unavailable, stale-write, and unknown-commit cases.
The declared budget was three architecture lenses, one exact source, two adapter boundaries, and one full repository gate.

## Non-claims

This pilot does not prove global replay exclusion, revocation authenticity, backend honesty, downstream effect completion, indefinite Radicle availability, production readiness, or whole-system authorization correctness.
Callers retain storage, clock, authenticity, tenant, generation, recovery, outage, and effect authority.
