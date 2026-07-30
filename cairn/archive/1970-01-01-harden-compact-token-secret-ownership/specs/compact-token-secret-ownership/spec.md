# Compact-Token Secret Ownership Specification

## ADDED Requirements

### Requirement: Allocation audit is explicit

r[ucan.compact_token_secret_ownership.audit] UCAN MUST audit compact-token owners, borrowed string verification, resolver and proof-store traversal, base64 decode, JSON decode, signing input, signature and proof buffers, error and debug paths, and clones before implementation.

#### Scenario: An unaudited bearer copy remains

- GIVEN a compact token or reconstruction-capable temporary enters an ordinary owned allocation
- WHEN the secret-ownership audit runs
- THEN validation MUST fail before the change is archived.

### Requirement: Bearer owners zeroize without stale reallocations

r[ucan.compact_token_secret_ownership.owners] UCAN MUST store owned compact tokens and reconstruction-capable temporary bytes in zeroizing owners, and bearer-bearing buffers MUST NOT reallocate after secret bytes enter them.

#### Scenario: Exact construction succeeds

- GIVEN a bounded compact token or deterministic issuance component
- WHEN UCAN creates its owner
- THEN the owner MUST use exact preallocation or bounded two-pass construction and MUST wipe its complete live allocation on drop.

### Requirement: Secret owners have a narrow public surface

r[ucan.compact_token_secret_ownership.public_surface] Secret owners MUST NOT derive or expose `Debug`, `Display`, `Serialize`, `Deserialize`, `Clone`, or ordinary public reconstruction unless a safe implementation has explicit positive and negative tests.

#### Scenario: A secret trait implementation appears

- GIVEN the source adds formatting, serde, cloning, or ordinary reconstruction for a compact-token owner
- WHEN the public-surface guard runs
- THEN the guard MUST fail with the forbidden surface.

### Requirement: Borrowed verification is bounded before allocation

r[ucan.compact_token_secret_ownership.borrowed_verification] UCAN MUST provide borrowed compact-token verification and MUST apply the complete input byte limit before serde allocation, base64 output allocation, proof lookup, or BLAKE3 identity derivation.

#### Scenario: Oversized malformed input arrives

- GIVEN input exceeds the configured compact-token byte limit and also has malformed compact syntax
- WHEN borrowed verification runs
- THEN verification MUST return the size-limit error before parsing and MUST NOT emit an exact token reference.

### Requirement: Proof traversal does not clone bearer tokens

r[ucan.compact_token_secret_ownership.proof_traversal] `ProofStore` traversal MUST accept borrowed or zeroizing proof-token values and MUST NOT clone compact proof-token bytes into ordinary storage.

#### Scenario: A proof chain verifies

- GIVEN a bounded child token and a store-owned bounded parent token
- WHEN recursive proof verification runs
- THEN the store MUST lend or move secure proof material and the verified result MUST retain only public proof references.

### Requirement: Public token evidence is complete and fixed-width

r[ucan.compact_token_secret_ownership.public_evidence] Public token identity evidence MUST be a fixed-width BLAKE3 reference over one complete bounded compact input and MUST NOT represent a prefix as the exact identity of oversized input.

#### Scenario: Two complete bounded inputs differ after a shared prefix

- GIVEN two bounded compact tokens share a prefix but differ in a later byte
- WHEN UCAN derives their references
- THEN the references MUST differ and each reference MUST bind the complete corresponding input.

### Requirement: Codec temporaries are zeroizing and non-growing

r[ucan.compact_token_secret_ownership.codec] Base64 and JSON decode stages MUST use borrowed input where possible, MUST store decoded reconstruction bytes in non-growing zeroizing buffers, and MUST reject serde paths that copy token string bytes into ordinary scratch storage.

#### Scenario: JSON escape syntax requires serde scratch storage

- GIVEN a decoded token header or payload contains JSON escape syntax
- WHEN secret-aware parsing runs
- THEN parsing MUST reject the input before serde copies escaped string bytes.

### Requirement: Issuance avoids bearer-bearing reallocation

r[ucan.compact_token_secret_ownership.issuance] Token issuance MUST use deterministic exact or two-pass construction for JSON, base64 segments, signing input, signature ownership, and final compact output after bearer reconstruction becomes possible.

#### Scenario: The signer returns a valid signature

- GIVEN bounded deterministic claims and a valid signer response
- WHEN UCAN assembles the compact token
- THEN no bearer-bearing buffer MUST grow and all intermediate owners MUST zeroize on success or error.

### Requirement: Positive and negative ownership tests are maintained

r[ucan.compact_token_secret_ownership.tests] The test suite MUST cover success, malformed and oversized input, proof chains, early error cleanup, exact capacity, secret formatting and serialization rejection, clone rejection, and compatibility boundaries.

#### Scenario: An ownership invariant changes

- GIVEN code changes compact-token allocation, parsing, proof resolution, signing, formatting, or evidence behavior
- WHEN the focused suite runs
- THEN at least one accepting case and one rejecting case MUST exercise the changed invariant.

### Requirement: Compatibility boundaries remain explicit

r[ucan.compact_token_secret_ownership.compatibility] UCAN MUST preserve explicit resolver, proof, revocation, replay, time, and limit inputs while documenting intentional source incompatibilities from removed bearer-copy APIs.

#### Scenario: A caller migrates from ordinary token reconstruction

- GIVEN a caller previously cloned, formatted, serialized, or consumed a compact token into ordinary storage
- WHEN the caller adopts the secure API
- THEN the caller MUST use a borrowed token view or move a zeroizing owner without gaining ambient authority.

### Requirement: Final evidence remains bounded

r[ucan.compact_token_secret_ownership.final_validation] UCAN MUST run focused and workspace tests, formatting, strict Clippy, readiness checks, Nix checks, Cairn gates, sync, archive, and post-archive validation before claiming completion.

#### Scenario: A dependency blocks the guarantee

- GIVEN serde, base64, zeroization, or another dependency can leave an unowned stale bearer copy
- WHEN final validation reviews the source-level guarantee
- THEN the change MUST remain active with the exact blocker and required dependency change.
