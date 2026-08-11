# Nostr Identity Adapter Specification

## Purpose

Defines the `nostr-identity-adapter` capability.

## Requirements

### Requirement: Nostr integration remains an optional adapter

r[ucan.nostr_identity_adapter.package_boundary] UCAN MUST provide Nostr identity verification through an optional in-tree adapter. Existing UCAN token paths MUST remain independent from this adapter.

#### Scenario: Existing UCAN consumers omit the adapter

- GIVEN a consumer uses `ucan-core` or `ucan` without `ucan-nostr`
- WHEN the consumer builds and runs existing issue, verify, proof, invocation, and authorization flows
- THEN those flows MUST retain their current algorithms and public behavior
- AND no Nostr dependency MUST enter their runtime graph

#### Scenario: Adapter code enters a token path

- GIVEN a change routes UCAN token parsing, signing, proof traversal, or authorization through Nostr code
- WHEN dependency and package-boundary verification runs
- THEN verification MUST fail
- AND the adapter MUST remain optional

### Requirement: The adapter verifies exact Nostr protocol identity

r[ucan.nostr_identity_adapter.protocol_verification] The adapter MUST verify canonical NIP-01 serialization, SHA-256 event identity, and BIP-340 signature validity over an x-only secp256k1 public key.

#### Scenario: Canonical signed event passes

- GIVEN an event matches the closed NIP-01 shape and official canonical rules
- AND its event ID and BIP-340 signature are valid
- WHEN protocol verification runs
- THEN verification MUST preserve the raw public key and protocol SHA-256 event identity

#### Scenario: Malformed or tampered event fails

- GIVEN a key, event field, canonical serialization, event ID, or signature is malformed or tampered
- WHEN protocol verification runs
- THEN verification MUST fail with a deterministic issue code
- AND no verified credential MUST be constructed

### Requirement: Authentication is bound to an explicit context

r[ucan.nostr_identity_adapter.authentication_context] The adapter MUST use a closed authentication profile. It MUST bind every result to caller-supplied audience, purpose, challenge, request, freshness, and replay expectations.

#### Scenario: Exact request context passes

- GIVEN a valid event matches the selected NIP-42, NIP-98, or application profile
- AND every expected request field, freshness fact, and replay fact is admitted
- WHEN context verification runs
- THEN the result MUST bind those exact values
- AND the event MUST NOT widen the caller policy

#### Scenario: Context mismatch denies

- GIVEN a validly signed event has the wrong relay, URL, method, audience, purpose, challenge, request identity, event kind, time, or replay disposition
- WHEN context verification runs
- THEN verification MUST deny
- AND no subject or authority fact MUST be inferred

### Requirement: Verified credentials do not grant authority

r[ucan.nostr_identity_adapter.credential_boundary] Only successful verification MUST construct `VerifiedNostrCredential`. The type MUST represent bounded key control for one request only.

#### Scenario: Downstream consumer receives a verified credential

- GIVEN protocol and context verification pass
- WHEN the adapter returns `VerifiedNostrCredential`
- THEN the value MUST contain only bounded public identity and decision metadata
- AND it MUST state that subject resolution and authorization remain downstream responsibilities

#### Scenario: Metadata attempts identity or authority promotion

- GIVEN a NIP-05 name, profile event, relay response, `npub` text, or signer label claims identity or authority
- WHEN the adapter evaluates the input
- THEN that metadata MUST NOT create a verified credential or UCAN grant

### Requirement: Support claims stay catalog-bound

r[ucan.nostr_identity_adapter.support_profile] UCAN MUST add a preview Nostr identity-adapter surface to the Rust-owned support catalog and all generated projections.

#### Scenario: Projection overstates support

- GIVEN JSON, Nickel, fixture, or documentation claims built-in relay, DNS, signer, clock, replay-store, subject, or authorization support
- WHEN support freshness verification runs
- THEN verification MUST fail
- AND the caller-owned boundary MUST remain explicit

### Requirement: Digest roles and failure coverage remain explicit

r[ucan.nostr_identity_adapter.final_validation] The adapter MUST preserve Nostr protocol SHA-256 identities separately from adapter-owned BLAKE3 identities. Positive and negative fixtures MUST cover every declared boundary.

#### Scenario: Digest substitution fails

- GIVEN a BLAKE3 value is supplied as a Nostr event ID
- OR a SHA-256 event ID is supplied as an adapter receipt identity
- WHEN typed digest verification runs
- THEN verification MUST fail with a digest-role issue

#### Scenario: Complete focused matrix passes

- GIVEN implementation, vectors, fixtures, support projections, documentation, and dependency evidence are complete
- WHEN focused package, workspace, Clippy, Cairn, and Nix verification runs
- THEN valid inputs MUST pass
- AND each malformed, stale, replayed, secret-bearing, or overclaiming input MUST fail as declared
