# Track Dependency Posture Specification Delta

## ADDED Requirements

### Requirement: Zeroize composes with reviewed consumers

r[track_dependency_posture.zeroize_consumer_alignment] UCAN MUST use one reviewed exact Zeroize version that satisfies its root shell, peer-authentication core, implementation identity, and supported Molten consumer graph.

#### Scenario: Reviewed consumer graph resolves

- GIVEN UCAN and Molten require the reviewed Zeroize `1.9.0` cohort
- WHEN Cargo resolves Basalt's vendored UCAN in Molten
- THEN one compatible Zeroize version MUST satisfy both graphs

#### Scenario: Implementation identity is stale

- GIVEN both UCAN manifests resolve Zeroize `1.9.0`
- WHEN the peer-authentication implementation identity names another Zeroize version
- THEN the dependency-posture rail MUST fail before publication
