# Track Dependency Posture Specification Delta

## ADDED Requirements

### Requirement: Exact BLAKE3 consumers resolve one reviewed cohort

r[ucan.deps.blake3_alignment] UCAN peer-authentication and Nostr crates MUST use one reviewed exact BLAKE3 version that can compose with supported Onix consumers. Both exact pins and the Cargo lock MUST move together.

#### Scenario: Basalt composes UCAN with another exact consumer

- GIVEN Basalt enables the vendored UCAN peer-authentication crate
- AND another dependency requires the reviewed exact BLAKE3 cohort
- WHEN Cargo resolves the combined graph
- THEN resolution MUST succeed without a patch override or alternate hash implementation

#### Scenario: Exact pins drift apart

- GIVEN the UCAN core and Nostr manifests select different exact BLAKE3 versions
- WHEN dependency validation runs
- THEN validation MUST fail before publication

### Requirement: Alignment evidence remains bounded

r[ucan.deps.blake3_alignment.verification] Verification MUST cover the focused crates and workspace while preserving existing authority and wire semantics. It MUST NOT claim cryptographic correctness or universal downstream compatibility.

#### Scenario: Focused verification passes

- GIVEN both manifests and the lock select the reviewed cohort
- WHEN tests, Clippy, formatting, Nix evaluation, and Cairn validation run
- THEN the evidence MAY report tested dependency compatibility only
