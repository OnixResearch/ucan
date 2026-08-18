# Durable Authority Adoption Specification

## Purpose

Defines the `durable-authority-adoption` capability.

## Requirements

### Requirement: Exact Durable Authority State source
r[ucan.durable_authority.source] UCAN MUST acquire both authority-state cores from canonical Radicle RID `rad:z3kGDT73ja8rewvGLwJFLF5MTx1ih` at one full reviewed object without fallback.

#### Scenario: Exact source is available
r[ucan.durable_authority.source.exact]
- GIVEN the admitted Radicle adapter and full reviewed object
- WHEN Cargo and Nix resolve the two core packages
- THEN both paths MUST select the same object

#### Scenario: A fallback source is supplied
r[ucan.durable_authority.source.reject]
- GIVEN a branch, tag, abbreviation, GitHub URL, sibling path, wrong RID, or path override
- WHEN dependency admission runs
- THEN UCAN MUST reject the source

### Requirement: Durable holder replay adapter
r[ucan.durable_authority.replay_adapter] The UCAN shell MUST map a verified holder replay candidate into a complete shared replay scope and reserve first use through a caller-owned port.

#### Scenario: First use reserves the slot
r[ucan.durable_authority.replay_adapter.first]
- GIVEN complete scope inputs and an empty trustworthy slot
- WHEN final holder replay admission runs
- THEN the adapter MUST apply the exact reservation and return success only after an applied commit observation

#### Scenario: Replay state cannot admit use
r[ucan.durable_authority.replay_adapter.deny]
- GIVEN duplicate, conflicting, cancelled, uncertain, unavailable, stale-write, malformed, or unknown-commit state
- WHEN holder replay admission runs
- THEN the adapter MUST fail closed through an existing UCAN replay error class

### Requirement: Current revocation adapter
r[ucan.durable_authority.revocation_adapter] The UCAN shell MUST answer revocation only from a caller-selected current, complete, authenticated snapshot loaded through a caller-owned port.

#### Scenario: Current snapshot answers lookup
r[ucan.durable_authority.revocation_adapter.current]
- GIVEN the required source, generation, explicit time, and current complete authenticated snapshot
- WHEN UCAN checks one proof reference
- THEN the adapter MUST return the canonical shared lookup result

#### Scenario: Snapshot cannot support lookup
r[ucan.durable_authority.revocation_adapter.unknown]
- GIVEN missing, wrong-source, old-generation, future, expired, partial, unauthenticated, unavailable, or failed storage state
- WHEN UCAN checks one proof reference
- THEN the adapter MUST return a fail-closed UCAN backend error

### Requirement: Final replay ordering
r[ucan.durable_authority.ordering] Durable replay reservation MUST remain the only state-consuming operation in holder verification and MUST occur after all fallible UCAN checks.

#### Scenario: Holder verification succeeds
r[ucan.durable_authority.ordering.success]
- GIVEN token, signature, profile, capability, and caveat checks succeed
- WHEN holder verification reaches replay
- THEN it MUST call the durable adapter once and perform no later UCAN work

#### Scenario: Earlier verification fails
r[ucan.durable_authority.ordering.denied]
- GIVEN any token, signature, profile, capability, or caveat check fails
- WHEN holder verification returns denial
- THEN it MUST make no replay persistence call

### Requirement: Consumer-owned authority and claims
r[ucan.durable_authority.claims] UCAN MUST retain protocol meaning and callers MUST retain persistence, time, authenticity, tenant, generation, recovery, outage, and effect authority.

#### Scenario: Adapter receipt is bounded
r[ucan.durable_authority.claims.bounded]
- GIVEN an adapter returns a replay or revocation observation
- WHEN UCAN records integration evidence
- THEN it MUST deny claims of token verification, authorization grant, global replay truth, revocation authenticity, backend honesty, effect completion, and release eligibility

#### Scenario: Shared state is treated as authority
r[ucan.durable_authority.claims.overclaim]
- GIVEN a caller treats a state digest or storage receipt as live authorization
- WHEN the boundary is reviewed
- THEN UCAN MUST reject the integration

### Requirement: Durable authority adapter validation
r[ucan.durable_authority.validation] UCAN MUST verify positive and negative adapter behavior with focused suites and full repository gates.

#### Scenario: Adapter suite passes
r[ucan.durable_authority.validation.pass]
- GIVEN exact source and complete adapter tests
- WHEN the repository gate runs
- THEN focused tests, formatting, Clippy, source checks, Cairn validation, traceability, and Nix checks MUST pass

#### Scenario: Negative case is accepted
r[ucan.durable_authority.validation.fail]
- GIVEN a duplicate, conflict, stale, incomplete, unauthenticated, or unavailable case returns success
- WHEN the adapter suite runs
- THEN the suite MUST fail

### Requirement: Adoption lifecycle completion
r[ucan.durable_authority.lifecycle] The pilot MUST sync accepted requirements, archive completed tasks, and publish the verified completion through `origin/main`.

#### Scenario: Pilot is complete
r[ucan.durable_authority.lifecycle.complete]
- GIVEN source, implementation, validation, sync, archive, and integration evidence pass
- WHEN completion is evaluated
- THEN the accepted spec and archive MUST be reachable from `origin/main`

#### Scenario: Pilot is incomplete
r[ucan.durable_authority.lifecycle.incomplete]
- GIVEN any required evidence is absent
- WHEN completion is evaluated
- THEN the change MUST remain active or blocked
