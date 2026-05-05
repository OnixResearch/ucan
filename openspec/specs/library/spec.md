# library Specification

## Purpose
TBD - created by archiving change make-ucan-library-usable. Update Purpose after archive.
## Requirements
### Requirement: End-to-end token round-trip

The `ucan` crate MUST let a consumer build, sign, serialize to a JWT/JWS-style compact token string carrying the first usable claim set (`iss`, `aud`, `att`, `prf`, `exp`, `nbf`), parse that string back, and verify a UCAN token through the public library API without hand-assembling token claims or orchestrating raw verified primitives directly.
r[library.token-round-trip]

#### Scenario: Consumer issues and verifies a token
r[library.token-round-trip.consumer-issues-and-verifies-a-token]

- GIVEN an Ed25519 issuer key, an audience DID, a non-empty capability set, and valid temporal bounds
- WHEN the consumer issues a compact token string, parses it back, and verifies it through the public `ucan` API
- THEN verification MUST succeed
- AND the verified result MUST expose the issuer, audience, capability set, proof list, and effective time window
- AND the flow MUST not require the consumer to call `sign_ed25519`, `verify_ed25519_signature`, or `validate_token_envelope` directly

#### Scenario: Invalid serialized token is rejected
r[library.token-round-trip.invalid-serialized-token]

- GIVEN a compact token string with malformed structure, invalid encoding, or missing required claims
- WHEN a consumer parses or verifies it through the public API
- THEN the library MUST return a structured error
- AND the library MUST not panic

### Requirement: did:key Ed25519 issuance and verification

The first usable library surface MUST support issuing and verifying tokens whose issuer identity is a `did:key` derived from an Ed25519 keypair.
r[library.did-key-ed25519]

#### Scenario: Issuer did:key matches the signing key
r[library.did-key-ed25519.issuer-did-key-matches-the-signing-key]

- GIVEN an Ed25519 secret key and a token issued through the public shell API
- WHEN the library derives the issuer `did:key`, signs the token, and later verifies the signature
- THEN the verified token MUST report the same issuer DID
- AND signature verification MUST succeed

#### Scenario: Signature mismatch is rejected
r[library.did-key-ed25519.signature-mismatch-is-rejected]

- GIVEN a token whose serialized content or signature bytes no longer match the issuer key
- WHEN the consumer verifies it through the public API
- THEN verification MUST fail with a signature-related error
- AND the library MUST not report the token as valid

### Requirement: Delegation proof chains are verified end to end

The library MUST verify delegation proof chains across parent tokens, including issuer/audience linkage, temporal narrowing, and capability attenuation.
r[library.delegation-chain]

#### Scenario: Narrower child token is accepted
r[library.delegation-chain.narrower-child-token-is-accepted]

- GIVEN a parent token and a child token whose proof links to the parent
- AND the child issuer matches the parent audience
- AND the child capability set is no broader than the parent capability set
- AND the child time window is no wider than the parent time window
- WHEN the library verifies the child token and its proof chain
- THEN verification MUST succeed
- AND the result MUST expose the effective delegation constraints

#### Scenario: Broken proof chain is rejected
r[library.delegation-chain.broken-proof-chain-is-rejected]

- GIVEN a token whose proof list omits a required parent, links to the wrong parent, or breaks the issuer/audience chain
- WHEN the library verifies the proof chain
- THEN verification MUST fail with a proof-chain error
- AND the token MUST not be treated as authorized

#### Scenario: Over-broad child delegation is rejected
r[library.delegation-chain.over-broad-child-delegation-is-rejected]

- GIVEN a child token whose capability set or expiration exceeds what its parent token delegates
- WHEN the library verifies the proof chain
- THEN verification MUST fail with an attenuation or temporal error
- AND the token MUST not be treated as authorized

#### Scenario: Self-delegation is rejected
r[library.delegation-chain.self-delegation-is-rejected]

- GIVEN a token whose issuer and audience are the same DID
- WHEN the `ucan` shell verifies the token or any proof chain containing it
- THEN verification MUST fail with a structured self-delegation error
- AND the token MUST not be treated as authorized

### Requirement: Functional core and imperative shell stay separate

Deterministic claim-shape parsing and structural validation MUST live in `crates/ucan-core`, while compact-token encoding/decoding, clocks, proof loading, and key resolution MUST live in the repo-root `ucan` crate.
r[library.fcis-boundary]

#### Scenario: Core validation remains pure
r[library.fcis-boundary.core-validation-remains-pure]

- GIVEN decoded token claims and capability values
- WHEN the library performs structural parsing and deterministic validation
- THEN that logic MUST be testable through `ucan-core` without filesystem, network, or clock dependencies

#### Scenario: Shell adapts validated values into verified semantics
r[library.fcis-boundary.shell-adapts-validated-values-into-verified-semantics]

- GIVEN a compact token string plus explicit time, proof, and key inputs
- WHEN the shell decodes it and verifies authorization semantics
- THEN it MUST bridge through `vendor/verified-logic` primitives instead of reimplementing attenuation, temporal, or signature rules locally

#### Scenario: Shell semantic bridge is auditable
r[library.fcis-boundary.shell-semantic-bridge-is-auditable]

- GIVEN the `ucan` shell crate source tree and the repo's verification checks
- WHEN the bridge audit runs
- THEN capability attenuation, token-time validation, and signature verification MUST remain delegated through `vendor/verified-logic`-backed functions
- AND the check MUST fail if equivalent local semantic implementations replace those bridges

### Requirement: `ucan-core` remains `no_std`

The token-claim model and structural validation work added to `crates/ucan-core` MUST preserve the crate's `#![no_std]` boundary.
r[library.core-no-std]

#### Scenario: Core compiles without `std`
r[library.core-no-std.core-compiles-without-std]

- GIVEN the `ucan-core` crate with the usable-library changes applied
- WHEN the repo runs the dedicated no-std verification rail for `ucan-core`
- THEN the crate MUST compile without `std`
- AND the new token-claim validation surface MUST remain available to that build

### Requirement: Consumer onboarding is part of the library surface

The repository MUST document the supported issuance and verification flow with runnable examples that match the public API.
r[library.consumer-onboarding]

#### Scenario: Fresh consumer follows the documented flow
r[library.consumer-onboarding.fresh-consumer-follows-the-documented-flow]

- GIVEN a fresh checkout and the documented example
- WHEN a consumer follows the README or example steps to issue and verify a token
- THEN the example MUST build against the public crate surface
- AND the flow MUST succeed without reading internal modules first

#### Scenario: Docs state current support limits
r[library.consumer-onboarding.docs-state-current-support-limits]

- GIVEN the initial usable-library release
- WHEN a consumer reads the documentation
- THEN it MUST clearly state the supported DID methods, signing algorithms, proof-loading model, and notable out-of-scope UCAN features

### Requirement: Secret key material is redacted from formatting

The `ucan` shell MUST ensure secret signing material is not exposed through `Debug`, display, error messages, or test failure output.
r[library.production-signers.secret-redaction]

#### Scenario: Debug output redacts in-memory signer secrets
r[library.production-signers.secret-redaction.debug-redacts-in-memory-secrets]

- GIVEN an in-memory Ed25519 signer initialized with known secret bytes
- WHEN a caller formats the signer or secret-key wrapper with `Debug`
- THEN the formatted output MUST NOT contain the secret bytes, seed bytes, or a direct byte-array representation
- AND the output SHOULD identify the type using a redacted placeholder

#### Scenario: Invalid key errors do not echo secret material
r[library.production-signers.secret-redaction.invalid-key-errors-do-not-echo-secrets]

- GIVEN malformed secret key input
- WHEN construction fails
- THEN the error MUST describe the validation failure without embedding the provided secret bytes

### Requirement: Token issuance is driven by a signer abstraction

The public token issuance path MUST accept a signer abstraction that provides issuer identity and signatures without requiring callers to expose raw secret bytes to the issuance function.
r[library.production-signers.signer-abstraction]

#### Scenario: In-memory signer issues the same token shape
r[library.production-signers.signer-abstraction.in-memory-signer-issues-token]

- GIVEN an in-memory Ed25519 signer, audience DID, capabilities, proofs, and valid time bounds
- WHEN a caller issues a token through the signer-based API
- THEN the token MUST use the existing compact-token claim shape
- AND verification through the public verifier MUST succeed

#### Scenario: Signer failure returns structured issue error
r[library.production-signers.signer-abstraction.signer-failure-is-structured]

- GIVEN a signer implementation that refuses to sign
- WHEN a caller issues a token through the signer-based API
- THEN issuance MUST fail with a structured signer-related error
- AND the library MUST NOT panic

#### Scenario: Bad signer output is rejected
r[library.production-signers.signer-abstraction.bad-signer-output-is-rejected]

- GIVEN a signer implementation that reports an unsupported algorithm, returns malformed signature bytes, or reports an issuer identity inconsistent with its verification material
- WHEN a caller issues or verifies a token through the signer-based API
- THEN the library MUST fail with a structured signer, signature, or issuer-mismatch error
- AND the library MUST NOT treat the token as valid

### Requirement: Ed25519 signer adapter preserves verified semantics

The existing Ed25519 behavior MUST remain available as a concrete signer adapter, and its DID derivation, signing, and verification MUST continue to route through `vendor/verified-logic`.
r[library.production-signers.ed25519-adapter]

#### Scenario: Ed25519 signer issuer matches derived did:key
r[library.production-signers.ed25519-adapter.issuer-matches-derived-did-key]

- GIVEN an Ed25519 signer adapter
- WHEN the library derives its issuer DID and issues a token
- THEN the issuer claim MUST match the verified `did:key` derived from the signer public key
- AND signature verification MUST succeed through the verified-logic bridge

### Requirement: Signer APIs preserve the core/shell boundary

Signer construction, key custody, randomness, and signing MUST remain in the `ucan` std shell, while `ucan-core` remains free of signer, key-generation, clock, filesystem, network, JSON, and compact-token codec dependencies.
r[library.production-signers.fcis-boundary]

#### Scenario: Core remains independent of signer implementation
r[library.production-signers.fcis-boundary.core-independent-of-signer]

- GIVEN the signer abstraction and Ed25519 signer adapter
- WHEN `ucan-core` is built and audited
- THEN it MUST not depend on std-only signer, randomness, key-storage, JSON, filesystem, network, or clock concerns

### Requirement: Examples and docs teach the signer boundary

The repository MUST update affected examples and public docs so consumers see signer-based issuance as the production-oriented path.
r[library.production-signers.consumer-onboarding]

#### Scenario: Existing examples use signer-based issuance where appropriate
r[library.production-signers.consumer-onboarding.examples-use-signer-api]

- GIVEN the runnable `issue_and_verify` and `proof_chain` examples
- WHEN the signer abstraction is available
- THEN examples SHOULD demonstrate the signer-based issuance path instead of encouraging direct raw secret-key handling as the primary reusable-crate pattern

### Requirement: Verified tokens authorize concrete requests

The `ucan` crate MUST let consumers ask whether a verified token's effective delegation authorizes a concrete resource and ability.
r[library.authorization-decisions.authorize-concrete-request]

#### Scenario: Matching effective capability is allowed
r[library.authorization-decisions.authorize-concrete-request.matching-effective-capability-is-allowed]

- GIVEN a verified token whose effective delegation contains a capability covering a requested resource and ability
- WHEN the consumer evaluates an authorization request against the verified token
- THEN the result MUST be allowed
- AND the result MUST expose the matched effective capability

#### Scenario: Missing effective capability is denied
r[library.authorization-decisions.authorize-concrete-request.missing-effective-capability-is-denied]

- GIVEN a verified token whose effective delegation does not cover a requested resource or ability
- WHEN the consumer evaluates an authorization request against the verified token
- THEN the result MUST be denied
- AND the denial reason MUST identify that no effective capability matched

### Requirement: Authorization uses verified capability semantics

Authorization matching MUST reuse the same verified-logic-backed resource and ability containment semantics used for proof-chain attenuation.
r[library.authorization-decisions.verified-matching]

#### Scenario: Wildcard ability segment authorizes child ability
r[library.authorization-decisions.verified-matching.wildcard-authorizes-child-ability]

- GIVEN an effective capability with ability `store/*`
- AND a request for ability `store/add`
- WHEN authorization matching runs
- THEN the request MUST be allowed if the resource is also covered

#### Scenario: Embedded wildcard remains invalid
r[library.authorization-decisions.verified-matching.embedded-wildcard-is-invalid]

- GIVEN an authorization request whose ability contains `*` inside a non-wildcard segment
- WHEN the request is constructed or evaluated
- THEN the library MUST reject the request with a structured validation error
- AND authorization MUST NOT fall back to string-prefix matching

#### Scenario: Authorization requests are concrete operations
r[library.authorization-decisions.verified-matching.request-must-be-concrete]

- GIVEN an authorization request whose requested ability uses `*` as a full wildcard segment
- WHEN the request is constructed or evaluated
- THEN the library MUST reject the request with a structured validation error
- AND wildcard abilities MUST remain valid only on delegated capabilities, not concrete requested operations

#### Scenario: Broader resource requests are denied
r[library.authorization-decisions.verified-matching.broader-resource-request-denied]

- GIVEN an effective capability delegated for a child resource scope
- AND an authorization request for a broader parent resource scope
- WHEN authorization matching runs
- THEN the request MUST be denied with a no-matching-capability reason

### Requirement: Authorization denials are structured

Authorization checks MUST return machine-readable denial reasons instead of losing detail in a bare boolean.
r[library.authorization-decisions.structured-denials]

#### Scenario: Denial reason distinguishes malformed input from no match
r[library.authorization-decisions.structured-denials.distinguishes-malformed-input-from-no-match]

- GIVEN one request with malformed capability input and one valid request not covered by the token
- WHEN both requests are evaluated
- THEN the malformed request MUST produce a validation error or malformed-input denial
- AND the uncovered valid request MUST produce a no-matching-capability denial
