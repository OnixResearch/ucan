# Durable authority dependency profile

## ADDED Requirements

### Requirement: Default-preserving optional adapters
r[ucan.durable_profile.selection] UCAN MUST enable durable-authority adapters by default. Explicit no-default consumers MUST omit the concrete durable module, its re-exports and both durable-state dependency edges. Verifier services and checks SHALL remain unchanged.

#### Scenario: Default caller
- GIVEN default features
- WHEN UCAN builds and tests
- THEN durable adapter types and their fail-closed behavior remain available

#### Scenario: Explicit opt-out
- GIVEN default features disabled
- WHEN UCAN verifies a holder invocation
- THEN caller-provided replay and revocation checks remain required without the concrete durable adapters

### Requirement: Observed profile compatibility
r[ucan.durable_profile.verification] Verification MUST cover both library profiles and reject durable libraries in the minimal normal dependency graph. The minimal library SHALL compile on pinned Rust 1.95 without ignoring version requirements. Evidence MUST NOT imply backend durability or production authority.

#### Scenario: Minimal compiler
- GIVEN the selected normal library graph and pinned Rust 1.95
- WHEN the compile check runs
- THEN it succeeds without either durable-state library

#### Scenario: Forbidden dependency
- GIVEN either durable library in a minimal dependency observation
- WHEN the profile gate runs
- THEN the gate fails rather than treating command exit alone as acceptance
