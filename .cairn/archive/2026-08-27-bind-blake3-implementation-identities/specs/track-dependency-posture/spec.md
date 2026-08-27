# Track Dependency Posture Specification Delta

## ADDED Requirements

### Requirement: Implementation identities bind the reviewed BLAKE3 cohort

r[track_dependency_posture.blake3_implementation_identity] UCAN implementation-identity inputs MUST name the same reviewed BLAKE3 version as the exact peer-authentication and Nostr manifest requirements and the resolved workspace lock.

#### Scenario: Reviewed cohort is aligned

- GIVEN both exact BLAKE3 consumers and the lock resolve version `1.8.5`
- WHEN peer-authentication and Nostr implementation identities are derived
- THEN both identity inputs MUST name BLAKE3 `1.8.5`

#### Scenario: Identity label is stale

- GIVEN a manifest resolves the reviewed BLAKE3 cohort
- WHEN its implementation-identity input names another BLAKE3 version
- THEN the dependency-posture rail MUST fail before publication
