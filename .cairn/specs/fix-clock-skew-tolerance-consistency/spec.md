# Fix Clock Skew Tolerance Consistency Specification

## Purpose

Defines the `fix-clock-skew-tolerance-consistency` capability.

## Requirements

### Requirement: One tolerance for every verification gate

r[ucan.skew.consistent] The envelope gate and the live proof-traversal DAG gate MUST use the same clock-skew tolerance for the same verification time.

#### Scenario: Token verified inside the documented grace window

r[ucan.skew.consistent.grace]
- GIVEN a token whose `nbf` or `exp` boundary falls inside the 60-second grace window relative to the verification time
- WHEN `verify_compact_token` runs
- THEN verification MUST admit the token
- AND the admission MUST match the documented clock-tolerance behavior

#### Scenario: Token verified outside the grace window

r[ucan.skew.consistent.reject]
- GIVEN a token whose verification time is more than the tolerance past `exp` or before `nbf`
- WHEN `verify_compact_token` runs
- THEN verification MUST reject the token
- AND rejection MUST report the temporal failure

### Requirement: Temporal failures report honestly

r[ucan.skew.honest] A temporal boundary failure MUST be reported as a temporal failure, not as a proof-chain or proof-graph failure.

#### Scenario: Expired token reports temporal state

r[ucan.skew.honest.class]
- GIVEN a token is expired beyond the allowed tolerance
- WHEN verification rejects the token
- THEN the error MUST identify the temporal boundary as the cause
- AND the error MUST NOT name the proof graph as the cause

### Requirement: Opt-in strict behavior stays available

r[ucan.skew.strict] A caller MUST be able to request zero-tolerance verification through an explicit surface without changing the default.

#### Scenario: Caller selects strict verification

r[ucan.skew.strict.surface]
- GIVEN a caller selects the strict surface
- WHEN verification runs on a token inside the default grace window
- THEN verification MUST reject the token
- AND the default surface MUST remain lenient

### Requirement: Boundary coverage is explicit

r[ucan.skew.coverage] Positive and negative fixtures MUST cover the `nbf`-1, `nbf`, `exp`, `exp+60`, and `exp+61` boundaries plus the strict-opt-in surface.

#### Scenario: Boundary matrix passes

r[ucan.skew.coverage.matrix]
- GIVEN fixtures at each declared boundary
- WHEN the focused test suite runs
- THEN each in-grace boundary MUST be admitted by default
- AND each out-of-grace boundary MUST be rejected with a temporal error
