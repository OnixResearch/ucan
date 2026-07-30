# Holder-Signed Invocation Specification

## ADDED Requirements

### Requirement: Holder canonicalization is domain-separated and complete

r[ucan.holder_invocation.canonical] UCAN MUST define one versioned, domain-separated canonical holder request that binds the complete bounded compact-token BLAKE3 reference, verified audience DID, resource, ability, operation-profile identity, exact request-binding digest, and fixed-size nonce.

#### Scenario: One bound field changes

- GIVEN two admitted holder requests differ in exactly one bound field
- WHEN the functional core canonicalizes both requests
- THEN their canonical bytes MUST differ without concatenation ambiguity.

### Requirement: Canonical core tests cover accepting and rejecting paths

r[ucan.holder_invocation.core_tests] The no-std functional core MUST test exact canonical length, deterministic output, field order, field bounds, output length mismatch, and one-field substitutions without shell dependencies.

#### Scenario: Output storage has the wrong length

- GIVEN valid bounded fields and an output slice with a non-exact length
- WHEN the core writes the canonical request
- THEN it MUST reject the output before a partial result is accepted.

### Requirement: Downstream operation binding is typed and fixed-width

r[ucan.holder_invocation.typed_binding] UCAN MUST expose fixed-width typed operation-profile identity, request-binding digest, and nonce values, and MUST NOT define downstream action-enum semantics.

#### Scenario: Basalt maps a closed action

- GIVEN Basalt selects a closed action variant and its downstream request
- WHEN Basalt constructs the UCAN operation binding
- THEN it MUST provide its stable profile identity and exact request digest without transferring action interpretation to UCAN.

### Requirement: Holder verification borrows and bounds input before canonicalization

r[ucan.holder_invocation.borrowed_verification] Holder verification MUST borrow compact token, resource, ability, signature, and policy inputs; MUST verify the complete compact token first; and MUST apply reviewed per-field and total canonical hard maxima before fallible exact allocation or canonicalization.

#### Scenario: Oversized input is also malformed

- GIVEN a compact token or request field exceeds its explicit limit and is also malformed
- WHEN holder verification runs
- THEN it MUST fail at the applicable bound before canonical allocation or field hashing and MUST return an error instead of requesting unbounded storage.

### Requirement: Success proves the verified audience key signed the exact request

r[ucan.holder_invocation.holder_proof] UCAN MUST resolve the key for the audience DID obtained from the verified token, MUST confirm that the resolved public key encodes that DID, and MUST verify that key's signature over the exact canonical holder request before success.

#### Scenario: A different holder signs the request

- GIVEN a valid UCAN delegates to one audience and a different key signs the canonical request
- WHEN holder verification runs
- THEN it MUST reject the invocation as an invalid holder signature.

### Requirement: Profile and replay truth remain injected

r[ucan.holder_invocation.injected_boundaries] UCAN MUST treat operation-profile and caveat policy checks as non-consuming observations, MUST call them only after holder signature verification, and MUST call the explicit audience-scoped nonce/replay boundary exactly once as the only state-consuming and final commit point.

#### Scenario: A nonce is submitted twice

- GIVEN two valid holder requests use the same verified audience and nonce
- WHEN profile and caveat observations allow both and the caller-owned replay boundary admits the first request and rejects the second
- THEN UCAN MUST return success only for the first request and MUST perform no work after either replay decision.

### Requirement: Live success cannot be fabricated or serialized

r[ucan.holder_invocation.live_success] The holder-invocation success value MUST have private fields and private construction and MUST NOT implement `Clone`, `Serialize`, or `Deserialize`; all owned fields MUST be prepared before replay admission and accepted replay MUST return that value without further work.

#### Scenario: A caller needs durable evidence

- GIVEN holder verification returns live success
- WHEN a caller needs a durable receipt
- THEN the caller MUST construct its own bounded evidence after applying downstream policy rather than serialize or clone UCAN live success.

### Requirement: Audience-only compatibility does not claim possession

r[ucan.holder_invocation.compatibility] Existing audience-only invocation helpers MAY remain for compatibility, but their types and documentation MUST NOT call the token audience an invoker or holder and MUST state that no sender-possession proof occurred.

#### Scenario: A compatibility caller authorizes by audience

- GIVEN a valid token audience has a matching delegated capability
- WHEN the caller uses the compatibility invocation helper
- THEN the result MAY expose audience authorization but MUST NOT expose holder-possession evidence.

### Requirement: Direct and delegated holder invocations succeed

r[ucan.holder_invocation.integration_tests] The integration suite MUST accept both direct and proof-chain delegated holder-signed invocations when token, holder signature, profile, caveat, and replay inputs are valid.

#### Scenario: A delegated audience signs the exact request

- GIVEN a valid parent and child proof chain delegates the requested capability to the child audience
- WHEN that audience signs the exact canonical request and replay admission allows it
- THEN holder verification MUST return live success with the effective delegation bounds.

### Requirement: Security substitutions and verification failures fail closed

r[ucan.holder_invocation.security_tests] The suite MUST reject wrong-holder signatures, resolved-key DID substitution, duplicate replay, malformed or substituted nonce, request-binding substitution, ability substitution, resource substitution, profile substitution, malformed signatures, excessive configured limits, excessive total canonical size, allocation failure, invalid time, missing or invalid proof, revocation, caveat denial, and unknown profiles; call-order tests MUST prove that failed prior checks do not reach later injected boundaries.

#### Scenario: Signed request data is substituted

- GIVEN a holder signs one valid canonical request
- WHEN a verifier changes its resource, ability, profile, request digest, nonce, or token
- THEN signature verification or an earlier explicit admission boundary MUST reject the request.

### Requirement: Documentation preserves exact non-claims

r[ucan.holder_invocation.documentation] Public documentation MUST distinguish holder signature proof from audience-only authorization; MUST define profile and caveat policy checks as non-consuming; and MUST assign consumptive rate limits, action semantics, request canonicalization, profile registry truth, nonce durability, resolver freshness, and execution safety to downstream consumers.

#### Scenario: A consumer reads the API guide

- GIVEN a consumer selects the holder-signed API
- WHEN it reviews the support and non-claim sections
- THEN it MUST find the exact caller-owned profile, request, replay, key, transport, and execution boundaries.

### Requirement: Final evidence uses canonical policy and dated archive

r[ucan.holder_invocation.final_validation] UCAN MUST run focused and workspace tests, all-target checks, formatting, strict Clippy, readiness, pre-commit, Nix, canonical Cairn policy gates, spec sync, dated archive execution, and post-archive validation before claiming completion.

#### Scenario: A required security class or gate fails

- GIVEN any required negative test, repository check, policy gate, sync plan, archive plan, or post-archive validation fails
- WHEN lifecycle completion is evaluated
- THEN the change MUST remain active with the exact blocker and MUST NOT claim holder-proof completion.
