# Track Dependency Posture Specification Delta

## ADDED Requirements

### Requirement: The Nostr adapter keeps the crypto-bigint advisory out of the locked graph

r[track_dependency_posture.k256_advisory_closure] The `ucan-nostr` adapter MUST require exact `k256` `0.14.0`, and its implementation-identity input MUST name `k256@0.14.0`. The committed lock MUST resolve that single `k256` version and MUST NOT contain a `crypto-bigint` version below `0.7.6`, the first release patched for `RUSTSEC-2026-0387`.

#### Scenario: Locked graph clears the advisory

- GIVEN the Nostr manifest requires exact `k256` `0.14.0`
- AND the lock resolves `k256` `0.14.0` with a patched `crypto-bigint`
- WHEN the dependency-posture rail runs
- THEN the rail MUST pass without an advisory pin for `RUSTSEC-2026-0387`

#### Scenario: Lock or manifest drifts back

- GIVEN the Nostr manifest names another `k256` version
- OR the lock contains `crypto-bigint` below `0.7.6`
- WHEN the dependency-posture rail runs
- THEN the rail MUST fail before publication

#### Scenario: Implementation identity label is stale

- GIVEN the Nostr manifest and lock resolve `k256` `0.14.0`
- WHEN the Nostr implementation-identity input names another `k256` version
- THEN the dependency-posture rail MUST fail before publication
