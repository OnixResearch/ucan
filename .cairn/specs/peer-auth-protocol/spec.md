# Peer Auth Protocol Specification

## Purpose

Defines the `peer-auth-protocol` capability.

## Requirements

### Requirement: Authenticated-message framing stays optional

r[ucan.peer_auth.framing] UCAN MUST provide authenticated-message framing through an optional surface in `ucan-core`. Existing UCAN token paths MUST remain independent from this surface.

#### Scenario: Existing UCAN consumers omit the framing

- GIVEN a consumer uses `ucan-core` or `ucan` without the authenticated-message surface
- WHEN the consumer builds and runs existing issue, parse, proof, invocation, and authorization flows
- THEN those flows MUST retain their current algorithms and public behavior
- AND no framing dependency MUST enter their runtime graph

#### Scenario: Framing enters a token path

- GIVEN a change routes UCAN token parsing, proof traversal, or authorization through authenticated-message code
- WHEN dependency and package-boundary verification runs
- THEN verification MUST fail
- AND the framing surface MUST remain optional

### Requirement: The core verifies a body-bound authenticated message

r[ucan.peer_auth.validation] The core MUST verify protocol version, body-bound signature, HMAC, clock bound, and replay disposition over supplied message bytes and caller-supplied expectations.

#### Scenario: Bound message passes

- GIVEN a message matches the negotiated version
- AND its body-bound signature, HMAC, timestamp, and replay disposition are valid
- WHEN validation runs
- THEN validation MUST admit the message exactly once within the caller policy
- AND the message content MUST NOT widen the caller policy

#### Scenario: Tampered or stale message fails

- GIVEN a wrong version, altered body, bad HMAC, stale timestamp, out-of-bound skew, or denied replay disposition
- WHEN validation runs
- THEN validation MUST fail with a deterministic issue code
- AND no authenticated-message verdict MUST be constructed

### Requirement: Verdicts do not grant authority

r[ucan.peer_auth.verdict] Only successful validation MUST construct the authenticated-message verdict. The type MUST represent bounded authentication for one bound message only.

#### Scenario: Consumer receives a verified message

- GIVEN framing and validation pass
- WHEN the core returns the authenticated-message verdict
- THEN the value MUST contain only bounded public identity and decision metadata
- AND it MUST state that authorization and end-user authentication remain downstream responsibilities

#### Scenario: Message metadata attempts promotion

- GIVEN a message label, transport hint, or key label claims a capability or identity
- WHEN validation evaluates the input
- THEN that metadata MUST NOT create an authenticated-message verdict or a UCAN grant

### Requirement: The reference stays bounded

r[ucan.peer_auth.reference] The change MUST record the reviewed Celld peer-protocol design as a bounded, non-parity input with its revision and license evidence.

#### Scenario: Reference overclaims parity

- GIVEN documentation claims parity with, or equivalence to, the Celld peer protocol
- WHEN reference verification runs
- THEN that claim MUST fail
- AND the reference MUST remain non-parity

### Requirement: Consumer boundary stays explicit

r[ucan.peer_auth.boundary] Transport, key custody, clock, replay, subject, and authorization MUST remain consumer-owned. The framing MUST NOT claim them.

#### Scenario: Projection overstates built-in support

- GIVEN a support surface claims built-in transport, key custody, clock, replay, subject, or authorization support
- WHEN support verification runs
- THEN verification MUST fail
- AND the consumer-owned boundary MUST remain explicit

### Requirement: Roles and failure coverage remain explicit

r[ucan.peer_auth.verification] The core MUST preserve BLAKE3 message identities separately from raw secrets and body bytes. Positive and negative fixtures MUST cover every declared boundary.

#### Scenario: Digest or secret substitution fails

- GIVEN a raw secret, an empty body, or a substituted digest role is supplied as the message identity
- WHEN typed validation runs
- THEN validation MUST fail with a clear issue
- AND the raw value MUST NOT be exposed except as a bounded BLAKE3 identity

#### Scenario: Complete focused matrix passes

- GIVEN implementation, vectors, fixtures, documentation, and dependency evidence are complete
- WHEN focused package, workspace, Clippy, Cairn, and Nix verification runs
- THEN valid inputs MUST pass
- AND each wrong-version, altered, stale, replayed, secret-bearing, or overclaiming input MUST fail as declared
