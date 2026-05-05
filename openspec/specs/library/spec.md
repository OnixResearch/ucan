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

The library MUST verify delegation proof chains across parent tokens, including issuer/audience linkage, temporal narrowing, and capability attenuation. Issuer/audience proof-link admission MUST route through the vendored verified-chain bridge rather than a shell-local direct semantic comparison.
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

#### Scenario: Proof link uses verified chain semantics [r[library.delegation-chain.proof-link-uses-verified-chain-semantics]]

- GIVEN a parent token audience DID and a child token issuer DID
- WHEN the shell verifies proof-chain linkage
- THEN the parent-audience/child-issuer check MUST pass through the verified-chain bridge helper
- AND a mismatch MUST still fail with a proof-chain error

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

The repository MUST document the supported issuance and verification flow with runnable examples that match the public API, including explicit revocation-checker support where relevant.
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
- THEN it MUST clearly state the supported DID methods, signing algorithms, proof-loading model, explicit revocation model, and notable out-of-scope UCAN features

#### Scenario: Support limits name revocation model
r[library.consumer-onboarding.revocation-model-documented]

- GIVEN a consumer reads the support-limits documentation
- WHEN they look for revocation support
- THEN the documentation MUST state that explicit caller-supplied revocation checks are supported and registry/network/storage semantics remain out of scope

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

Authorization matching and concrete request admission MUST reuse the same verified-logic-backed resource and ability containment semantics used for proof-chain attenuation.
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
- AND the wildcard check MUST be routed through the verified capability bridge rather than a parallel shell-local ability parser

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

### Requirement: Verifiers use explicit key resolvers

The `ucan` shell MUST support verification through an explicit key resolver abstraction rather than only a concrete in-memory vector.
r[library.resolver-proof-store.key-resolver]

#### Scenario: In-memory resolver verifies existing tokens
r[library.resolver-proof-store.key-resolver.in-memory-resolver-verifies-existing-tokens]

- GIVEN a token issued by an Ed25519 signer and an in-memory resolver containing the issuer verification key
- WHEN the token is verified through the resolver-based context
- THEN verification MUST succeed
- AND the result MUST match the current in-memory-key behavior

#### Scenario: Missing issuer key is structured
r[library.resolver-proof-store.key-resolver.missing-issuer-key-is-structured]

- GIVEN a token whose issuer key is not available from the resolver
- WHEN verification attempts to resolve the issuer
- THEN verification MUST fail with a structured missing-key error that includes the issuer DID

### Requirement: Proof traversal uses explicit proof stores

The verifier MUST support resolving proof tokens through a proof store abstraction instead of requiring every proof token to be pre-collected in one vector.
r[library.resolver-proof-store.proof-store]

#### Scenario: Proof store supplies parent token by reference
r[library.resolver-proof-store.proof-store.supplies-parent-by-reference]

- GIVEN a child token whose proof reference points to a parent token
- AND a proof store that can return the parent token for that reference
- WHEN the child token is verified
- THEN verification MUST resolve the parent through the proof store
- AND proof-chain validation MUST succeed when linkage, time, and attenuation are valid

#### Scenario: Missing proof is structured
r[library.resolver-proof-store.proof-store.missing-proof-is-structured]

- GIVEN a child token whose proof reference is not available from the proof store
- WHEN verification attempts to resolve proofs
- THEN verification MUST fail with a structured missing-proof error
- AND the verifier MUST NOT silently ignore the missing proof

### Requirement: Recursive verification has deterministic limits
Proof-chain verification MUST enforce explicit limits for traversal depth, proof count, and serialized compact-token byte size. The token-size limit MUST apply to the input token and to each resolved proof token before parsing. Proof-depth budget admission MUST route through the vendored verified delegation-depth bridge so the shell does not maintain a parallel depth predicate.
r[library.resolver-proof-store.verification-limits]

#### Scenario: Serialized token size limit rejects oversized input
r[library.resolver-proof-store.verification-limits.serialized-token-size-limit]

- GIVEN an input token or resolved proof token whose compact string byte length exceeds the configured maximum
- WHEN verification attempts to process that token
- THEN verification MUST fail with a structured limit-exceeded error
- AND the oversized token MUST NOT be parsed or trusted

#### Scenario: Depth limit stops recursive traversal
r[library.resolver-proof-store.verification-limits.depth-limit-stops-recursion]

- GIVEN a proof chain deeper than the configured maximum depth
- WHEN verification traverses proofs
- THEN verification MUST fail with a structured limit-exceeded error
- AND the verifier MUST NOT continue unbounded recursion

#### Scenario: Proof-count limit stops broad traversal
r[library.resolver-proof-store.verification-limits.proof-count-limit-stops-traversal]

- GIVEN a token or chain whose total resolved proof count exceeds the configured maximum proof count
- WHEN verification traverses proofs
- THEN verification MUST fail with a structured limit-exceeded error
- AND the verifier MUST NOT continue resolving additional proofs

#### Scenario: Cycle detection remains enforced with stores
r[library.resolver-proof-store.verification-limits.cycle-detection-with-proof-store]

- GIVEN proof tokens that form a reference cycle through the proof store
- WHEN verification traverses the chain
- THEN verification MUST reject the cycle with a structured proof-chain error

#### Scenario: Proof-depth budget uses verified delegation-depth semantics [r[library.resolver-proof-store.verification-limits.depth-budget-uses-verified-logic]]

- GIVEN a verification traversal depth and a configured maximum proof depth
- WHEN the verifier decides whether recursion may continue
- THEN it MUST evaluate the depth budget through the verified delegation-depth bridge
- AND it MUST preserve the existing structured limit-exceeded error when the bridge rejects the depth

### Requirement: Resolver/store abstractions preserve the core/shell boundary

Key resolver and proof store abstractions MUST live in the `ucan` std shell and MUST NOT add storage, network, clock, resolver, or codec dependencies to `ucan-core`.
r[library.resolver-proof-store.fcis-boundary]

#### Scenario: Core remains independent of resolver/store implementations
r[library.resolver-proof-store.fcis-boundary.core-independent-of-resolvers]

- GIVEN resolver and proof-store traits in the shell
- WHEN `ucan-core` is built and audited
- THEN it MUST remain free of resolver, storage, network, filesystem, clock, JSON, and compact-token codec dependencies

### Requirement: Resolver/store onboarding is documented

The repository MUST document resolver/store injection and provide at least one runnable example using a simple proof store.
r[library.resolver-proof-store.consumer-onboarding]

#### Scenario: Proof-store example resolves a parent token
r[library.resolver-proof-store.consumer-onboarding.proof-store-example]

- GIVEN the proof-store example
- WHEN it runs through the public crate API
- THEN it MUST resolve a parent token by proof reference and verify the child token without private modules

### Requirement: Capability claims can carry caveats

The token model MUST support optional caveat payloads on capabilities while preserving deterministic structural validation in `ucan-core` and codec-specific handling in the `ucan` shell.
r[library.caveats.capability-caveats]

#### Scenario: Caveat payload round-trips through compact tokens
r[library.caveats.capability-caveats.round-trips-through-compact-token]

- GIVEN a capability with an application caveat payload
- WHEN the library issues, parses, and validates a compact token containing that capability
- THEN the caveat payload MUST be preserved for shell-side policy evaluation
- AND `ucan-core` MUST remain free of JSON, filesystem, network, and clock dependencies

#### Scenario: Malformed caveat payload is rejected
r[library.caveats.capability-caveats.malformed-caveat-is-rejected]

- GIVEN a compact token with malformed caveat data for the configured codec
- WHEN the library parses or validates the token
- THEN the library MUST return a structured error
- AND the library MUST NOT panic

### Requirement: Caveat policies fail closed

Caveat evaluation MUST use explicit caller-provided policy hooks and MUST fail closed when caveats are unknown or unevaluated.
r[library.caveats.policy-hooks]

#### Scenario: Unknown caveat denies authorization
r[library.caveats.policy-hooks.unknown-caveat-denies]

- GIVEN a verified token whose matched capability contains a caveat unknown to the supplied policy
- WHEN an authorization or invocation check evaluates that capability
- THEN the decision MUST be denied with an unknown-caveat reason

#### Scenario: Child caveats must attenuate parent caveats
r[library.caveats.policy-hooks.child-caveat-attenuates-parent]

- GIVEN a parent capability caveat and a child capability caveat for the same domain
- WHEN proof-chain attenuation is checked with a caveat policy
- THEN the child caveat MUST be accepted only when the policy says it is no broader than the parent caveat

### Requirement: Caveat-aware authorization decisions are structured

The existing authorization decision API MUST distinguish caveat-specific denials from no-capability-match denials when caveat policy evaluation is requested.
r[library.caveats.authorization-decisions]

#### Scenario: Authorization denied by unknown caveat reports caveat reason
r[library.caveats.authorization-decisions.unknown-caveat-reason]

- GIVEN a verified token whose matched capability contains a caveat unknown to the supplied policy
- WHEN a consumer evaluates a caveat-aware authorization request
- THEN the decision MUST be denied with an unknown-caveat reason
- AND the denial MUST NOT be reported as no-matching-capability

### Requirement: Invocation authorization verifies concrete operations
The library MUST provide an invocation workflow that verifies token/proof validity, capability coverage, and caveat satisfaction for one concrete requested operation. For allowed invocations, effective constraints MUST include the effective delegation time bounds, the matched effective capability, and the caveat-policy output or effective caveat payloads used to authorize the request. Concrete matched-capability invocation admission MUST pass through the vendored verified invocation bridge without replacing wildcard delegation or caveat policy semantics. The invocation workflow MUST also expose verified-logic-backed deterministic receipt execution checks for caller-provided receipt fields without adding ambient clocks, persistence, replay stores, or network behavior.
r[library.invocations.workflow]

#### Scenario: Invocation allowed by valid delegated capability
r[library.invocations.workflow.valid-invocation-is-allowed]

- GIVEN a token and proof chain that delegate a capability to the invoker
- AND request facts that satisfy all caveats on the matched capability
- WHEN the consumer verifies the invocation
- THEN the invocation MUST be allowed
- AND the result MUST expose issuer, invoker, audience, matched capability, and effective constraints

#### Scenario: Invocation denied when request facts violate caveat
r[library.invocations.workflow.caveat-violation-denies-invocation]

- GIVEN a token and proof chain whose matched capability contains a caveat
- AND request facts that do not satisfy that caveat under the supplied policy
- WHEN the consumer verifies the invocation
- THEN the invocation MUST be denied with a caveat-violation reason

#### Scenario: Concrete invocation admission uses verified invocation semantics [r[library.invocations.workflow.concrete-admission-uses-verified-invocation]]

- GIVEN a verified token whose matched effective capability is concrete
- WHEN invocation authorization admits a concrete requested operation
- THEN the shell MUST check the invoker/audience, resource refinement, and ability equality through the verified invocation bridge helper
- AND wildcard matched capabilities MUST continue to use verified capability containment and caveat policy evaluation rather than the exact-ability invocation helper

#### Scenario: Receipt execution check uses verified invocation receipt semantics [r[library.invocations.workflow.receipt-execution-verified]]

- GIVEN caller-provided invocation invoker, receipt executor, invocation timestamp, and receipt timestamp
- WHEN the public receipt execution helper evaluates the fields
- THEN it MUST route the executor equality and timestamp ordering decision through the verified invocation receipt bridge
- AND it MUST accept matching executors with non-decreasing timestamps while rejecting mismatched executors or earlier receipt timestamps

### Requirement: Caveat and invocation APIs preserve the core/shell boundary

Caveat payload preservation in `ucan-core` MUST remain codec-neutral, and policy evaluation, invocation request facts, JSON decoding, clocks, resolvers, storage, and network concerns MUST remain in the `ucan` std shell.
r[library.caveats.fcis-boundary]

#### Scenario: Core remains independent of caveat policy implementations
r[library.caveats.fcis-boundary.core-independent-of-caveat-policy]

- GIVEN caveat and invocation support
- WHEN `ucan-core` is built and audited
- THEN it MUST remain free of policy, JSON, filesystem, network, clock, resolver, storage, and compact-token codec dependencies

### Requirement: Caveat and invocation onboarding is documented

The repository MUST provide runnable onboarding for caveat-aware invocation authorization and document fail-closed caveat behavior.
r[library.invocations.consumer-onboarding]

#### Scenario: Invocation example uses deterministic caveat policy
r[library.invocations.consumer-onboarding.deterministic-caveat-policy-example]

- GIVEN the invocation example
- WHEN it runs through the public crate API
- THEN it MUST verify a request using a deterministic caveat policy
- AND it MUST not use private crate modules

### Requirement: Public wrappers cross string and JSON boundaries ergonomically

Public semantic wrapper types MUST implement standard parsing, formatting, and serde traits where the wrapper trait matrix marks the trait/type pair as included, and MUST NOT implement those traits where doing so exposes secret material or weakens validation.
r[library.ergonomics.wrapper-traits]

#### Scenario: Compact token parses from string
r[library.ergonomics.wrapper-traits.compact-token-from-str]

- GIVEN a trimmed compact token string
- WHEN a consumer parses it with `FromStr`
- THEN the result MUST be a validated `CompactToken` wrapper or a structured parse error

#### Scenario: DID wrappers deserialize with validation
r[library.ergonomics.wrapper-traits.did-serde-validates]

- GIVEN JSON containing issuer or audience DID strings
- WHEN the JSON is deserialized into public DID wrapper types
- THEN valid DID values MUST deserialize successfully
- AND empty or untrimmed DID values MUST fail with structured validation errors

#### Scenario: Public wrappers serialize with canonical string values
r[library.ergonomics.wrapper-traits.serde-serializes-canonical-strings]

- GIVEN a non-secret public wrapper with a canonical string form
- WHEN the wrapper is serialized through serde
- THEN the serialized value SHOULD use that canonical string form
- AND deserializing it MUST validate through the same constructor path

#### Scenario: Display round-trips through validated parsing
r[library.ergonomics.wrapper-traits.display-round-trips]

- GIVEN a non-secret public wrapper with `Display` and `FromStr` implementations
- WHEN a consumer formats the wrapper and parses the formatted value
- THEN the parsed wrapper MUST equal the original value
- AND secret-bearing types MUST NOT gain cleartext formatting through this requirement

### Requirement: Public workflows provide builders

Token issue and verify workflows MUST provide builders or named-argument style constructors that reduce positional argument mistakes. Authorization, resolver/proof-store, and invocation builders are handled by their feature-specific changes.
r[library.ergonomics.builders]

#### Scenario: Issue builder constructs valid request
r[library.ergonomics.builders.issue-builder-valid-request]

- GIVEN a signer, audience, capability, proof collection, and time bounds supplied through named builder methods
- WHEN the builder is finalized
- THEN it MUST produce the same valid issue request as the positional constructor

#### Scenario: Builder reports missing required field
r[library.ergonomics.builders.builder-missing-field]

- GIVEN an issue or verify builder missing a required field
- WHEN the builder is finalized
- THEN it MUST fail with a structured missing-field error naming the absent field

### Requirement: Std shell provides safe time helpers

The std shell MUST provide `SystemTime` and `Duration` helpers while preserving explicit deterministic times in the core verifier.
r[library.ergonomics.time-helpers]

#### Scenario: Verification time can be built from SystemTime
r[library.ergonomics.time-helpers.system-time-verification]

- GIVEN a `SystemTime` value
- WHEN a consumer constructs `VerificationTime` through the std helper
- THEN the resulting timestamp MUST match the Unix-seconds conversion or fail with a structured time-conversion error

#### Scenario: Token bounds can be built from Duration
r[library.ergonomics.time-helpers.duration-token-bounds]

- GIVEN a start time and a positive duration
- WHEN a consumer constructs token time bounds through the std helper
- THEN the resulting bounds MUST have the expected Unix-second interval
- AND duration overflow or invalid non-positive bounds MUST fail with a structured error

### Requirement: Reusable integration examples are runnable

The repository MUST include runnable examples that demonstrate realistic downstream use beyond smoke-token issuance.
r[library.ergonomics.integration-examples]

#### Scenario: HTTP bearer example parses and verifies
r[library.ergonomics.integration-examples.http-bearer-verifies]

- GIVEN an HTTP-style bearer token string and explicit verification context
- WHEN the example parses and verifies the token
- THEN the example MUST produce a verified token or structured verification failure without using private crate modules

#### Scenario: Failure-handling example maps structured errors
r[library.ergonomics.integration-examples.failure-handling-maps-errors]

- GIVEN malformed, expired, missing-proof, and missing-key token cases
- WHEN the example evaluates them
- THEN it MUST show stable application-level handling for parse and verification failures

### Requirement: Verification accepts explicit revocation checkers [r[library.revocation.explicit-checker]]
The library MUST let callers inject revocation state through explicit checker objects without process-global registries, implicit network fetches, persistence layers, or ambient default stores. The deterministic in-memory revocation-list helper MUST perform finite proof-reference membership through the vendored verified revocation-set bridge rather than a shell-local membership scan, including both denial checks and duplicate insertion admission.

#### Scenario: No-op checker preserves current verification [r[library.revocation.explicit-checker.noop-preserves-behavior]]
- GIVEN a compact token and proof chain that verifies successfully with the existing verification API
- WHEN the same token is verified with the no-op revocation checker
- THEN verification MUST produce the same verified issuer, audience, proof list, and effective delegation constraints

#### Scenario: Revocation backend errors fail closed [r[library.revocation.explicit-checker.backend-error-fails-closed]]
- GIVEN a revocation checker that returns a backend error for a token reference
- WHEN verification reaches that reference
- THEN verification MUST fail with a structured revocation backend error instead of allowing the token

#### Scenario: In-memory revocation list uses verified set semantics [r[library.revocation.verified-set-membership]]
- GIVEN a proof reference and an in-memory revocation list
- WHEN the revocation list evaluates membership
- THEN the lookup MUST pass through the verified revocation-set bridge helper
- AND listed references MUST deny verification while unlisted references remain allowed

#### Scenario: RevocationList duplicate insertion uses verified set semantics [r[library.revocation.explicit-checker.dedupe-uses-verified-set]]
- GIVEN an in-memory `RevocationList` containing a proof reference
- WHEN the same proof reference is revoked again
- THEN the helper MUST consult the verified finite revocation-set bridge for membership
- AND the list MUST remain idempotent without adding a duplicate reference

### Requirement: Revocation covers the full proof chain [r[library.revocation.chain-denial]]
The library MUST reject a token when the leaf token or any recursively resolved proof-chain token is revoked by the caller-supplied checker.

#### Scenario: Leaf token is revoked [r[library.revocation.chain-denial.leaf-revoked]]
- GIVEN a valid compact token whose proof reference is present in the caller-supplied revocation list
- WHEN revocation-aware verification is run
- THEN verification MUST fail before returning a verified token

#### Scenario: Parent proof token is revoked [r[library.revocation.chain-denial.parent-revoked]]
- GIVEN a child token whose parent proof token is otherwise valid but whose proof reference is revoked
- WHEN revocation-aware verification walks the delegation chain
- THEN verification MUST fail and MUST NOT authorize the child through the revoked parent

### Requirement: Revocation example onboards consumers [r[library.revocation.consumer-example]]
The repository MUST include a runnable example that demonstrates explicit caller-supplied revocation checks and fail-closed revocation backend errors without implying built-in registries, network fetches, persistence, replay stores, or credential-status formats.

#### Scenario: Example shows proof-chain revocation denial [r[library.revocation.consumer-example.parent-proof-denied]]
- GIVEN a child token with a valid parent proof and a caller-supplied in-memory revocation list containing the parent proof reference
- WHEN a consumer runs the revocation example
- THEN the example MUST first show successful verification with no revocations
- AND it MUST then show structured revocation denial for the revoked parent proof reference
- AND it MUST NOT print compact UCAN token values

#### Scenario: Example shows revocation backend errors fail closed [r[library.revocation.consumer-example.backend-error-fails-closed]]
- GIVEN a caller-supplied revocation checker that cannot answer for a token reference
- WHEN a consumer runs the revocation example
- THEN the example MUST show structured backend-error handling as a verification failure
- AND it MUST NOT treat an unavailable revocation backend as an allowed token
- AND it MUST NOT print compact UCAN token values

### Requirement: Verified structural chain bridge [r[library.verified-bridges.structural-chain]]

The library MUST expose a structural chain bridge that accepts caller-supplied resolved UCAN chain entries and routes finite issuer/audience linkage, caller-provided signature-valid flags, exact attenuation narrowing, and temporal validity through the vendored verified chain checker.

#### Scenario: Structural chain bridge accepts a linked exact-attenuation chain [r[library.verified-bridges.structural-chain.accepts-linked-exact-chain]]

- GIVEN two caller-supplied chain entries whose parent audience equals the child issuer
- AND every entry is marked signature-valid by the caller
- AND the child capability narrows the parent capability with exact ability equality
- AND both entries are temporally valid at the supplied verification time
- WHEN the structural chain bridge is evaluated
- THEN it MUST return an allowed result from the verified chain checker.

#### Scenario: Structural chain bridge rejects broken links and attenuation escalation [r[library.verified-bridges.structural-chain.rejects-invalid-structure]]

- GIVEN caller-supplied chain entries with a broken issuer/audience link or exact attenuation escalation
- WHEN the structural chain bridge is evaluated
- THEN it MUST return a rejected result from the verified chain checker without invoking proof resolution, network lookup, revocation registries, caveat policy, or cryptographic signature verification.

### Requirement: Verified non-revoked structural chain bridge [r[library.verified-bridges.nonrevoked-structural-chain]]

The library MUST expose a focused bridge that accepts caller-supplied resolved UCAN chain entries, aligned proof-reference bytes, and finite revoked-reference bytes, then routes structural chain validity plus non-revocation admission through the vendored verified revocation-chain checker.

#### Scenario: Non-revoked structural chain bridge accepts an aligned clean chain [r[library.verified-bridges.nonrevoked-structural-chain.accepts-clean-chain]]

- GIVEN caller-supplied chain entries that are structurally valid at the supplied verification time
- AND the proof-reference vector has exactly one reference for each chain entry
- AND none of those references is present in the finite revoked-reference set
- WHEN the composed non-revoked-chain bridge is evaluated
- THEN it MUST return an allowed result from the verified revocation-chain checker.

#### Scenario: Non-revoked structural chain bridge rejects revoked, misaligned, or invalid chains [r[library.verified-bridges.nonrevoked-structural-chain.rejects-invalid-chain]]

- GIVEN caller-supplied chain entries with a revoked reference, mismatched reference count, or invalid structure
- WHEN the composed non-revoked-chain bridge is evaluated
- THEN it MUST return a rejected result from the verified revocation-chain checker
- AND it MUST NOT invoke proof resolution, network lookup, revocation registries, backend availability checks, caveat policy, or cryptographic signature verification.

### Requirement: Verified invocation-chain authorization bridge [r[library.verified-bridges.invocation-chain]]

The library MUST expose a deterministic public helper that delegates caller-supplied resolved invocation-chain authorization data to the vendored verified invocation-chain composition primitive.

#### Scenario: Resolved chain authorizes concrete invocation [r[library.verified-bridges.invocation-chain.authorized]]

- GIVEN caller-supplied resolved chain entries, aligned proof-reference bytes, no matching revoked references, an invocation authorization reference equal to the leaf proof reference, a valid leaf capability index, and deterministic time inputs
- WHEN the helper is called with an invoker matching the leaf audience and a request whose resource refines the leaf resource with the same ability
- THEN the helper MUST return true through the verified invocation-chain checker

#### Scenario: Revoked or unbound invocation denies [r[library.verified-bridges.invocation-chain.denied]]

- GIVEN caller-supplied resolved chain entries and aligned proof-reference bytes
- WHEN any aligned proof reference is listed as revoked, the chain is structurally invalid, the invocation authorization reference differs from the leaf proof reference, the leaf capability index is out of bounds, or the request escalates resource or ability
- THEN the helper MUST return false through the verified invocation-chain checker

#### Scenario: Advanced bridge preserves shell-owned behavior [r[library.verified-bridges.invocation-chain.boundary]]

- GIVEN production verification requires proof resolution, cryptographic signature verification, fail-closed revocation backends, wildcard containment, and caveat policy evaluation
- WHEN the invocation-chain bridge is used
- THEN the helper MUST remain limited to caller-supplied finite data and MUST NOT perform proof fetching, compact-token verification, cryptography, DID/key lookup, revocation backend or freshness checks, caveat policy evaluation, wildcard containment replacement, registry/storage/network access, persistence, replay checks, or ambient clock reads

### Requirement: Verified Web-of-Trust UCAN authorizer bridge [r[library.verified-bridges.wot-ucan-authorizer]]

The library MUST expose a deterministic public helper that delegates caller-supplied finite Web-of-Trust UCAN authorization data to the vendored verified Web-of-Trust UCAN authorizer primitive.

#### Scenario: Rooted trust authorizes UCAN [r[library.verified-bridges.wot-ucan-authorizer.authorized]]

- GIVEN a structurally valid UCAN payload, caller-supplied positive ability/caveat/DID-CID linkage facts, satisfied active caveats, root principals, active attestations, no effective matching revocation, and a threshold that the roots satisfy
- WHEN the helper is called with deterministic token and trust evaluation times
- THEN it MUST return an authorized result through the vendored Web-of-Trust UCAN authorizer

#### Scenario: Missing trust facts deny UCAN [r[library.verified-bridges.wot-ucan-authorizer.denied]]

- GIVEN otherwise finite caller-supplied Web-of-Trust UCAN authorization data
- WHEN the token envelope is invalid, any caller-supplied ability/caveat/DID-CID fact is false, active caveats are unsatisfied, trust resolution fails, threshold policy fails, or an effective matching revocation applies
- THEN the helper MUST return a denied result through the vendored Web-of-Trust UCAN authorizer

#### Scenario: Advanced bridge preserves production boundaries [r[library.verified-bridges.wot-ucan-authorizer.boundary]]

- GIVEN production UCAN verification depends on cryptography, DID/CID decoding, resolver/proof-store traversal, caveat policy evaluation, revocation backend behavior, and application trust stores
- WHEN the Web-of-Trust UCAN bridge is used
- THEN the helper MUST remain limited to caller-supplied finite data and explicit caller-supplied facts and MUST NOT perform compact-token verification, cryptographic signature verification, DID/CID decoding, proof fetching, key lookup, revocation backend/freshness checks, caveat policy evaluation, registry/storage/network access, persistence, replay checks, or ambient clock reads

### Requirement: Verified DID-key decode bridge [r[lib.verified.did-key-decode]]

The library MUST expose a public advanced helper that decodes caller-supplied `did:key` bytes through the vendored verified DID-key decoder and returns only public decoded key bytes, the multicodec value, and the original encoded bytes when structural decoding succeeds.

#### Scenario: Decode accepted DID key [r[lib.verified.did-key-decode.accepted]]

- GIVEN DID-key bytes previously produced by the verified encoder
- WHEN an advanced caller invokes the decode bridge
- THEN the helper returns decoded public-key bytes, codec, and original encoded bytes from the vendored decoder

#### Scenario: Reject malformed DID key [r[lib.verified.did-key-decode.reject-malformed]]

- GIVEN bytes without the required DID-key prefix, valid base58btc payload, or multicodec structure
- WHEN an advanced caller invokes the decode bridge
- THEN the helper returns no decoded key and does not perform fallback resolution

#### Scenario: Preserve structural-only boundary [r[lib.verified.did-key-decode.boundary]]

- GIVEN any caller-supplied DID-key bytes
- WHEN the decode bridge runs
- THEN the helper MUST NOT perform remote DID resolution, key lookup, cryptographic signature verification, trust-chain checks, proof fetching, filesystem/network fallback, persistence, or ambient clock reads

### Requirement: Verified capability-set authorization bridge [r[lib.verified.capability-set-authorizer]]

The library MUST expose a public advanced helper that delegates finite caller-supplied capability-set authorization to the vendored verified capability-merge authorizer.

#### Scenario: Accept contained exact request [r[lib.verified.capability-set-authorizer.accepted]]

- GIVEN a finite capability set containing a capability whose resource is a byte prefix of a requested resource and whose ability exactly equals the requested ability
- WHEN an advanced caller invokes the capability-set authorization bridge
- THEN the helper returns true from the vendored verified capability-set authorizer

#### Scenario: Deny resource or ability escalation [r[lib.verified.capability-set-authorizer.denied]]

- GIVEN a finite capability set without any entry whose resource prefixes the requested resource and whose ability exactly equals the requested ability
- WHEN an advanced caller invokes the capability-set authorization bridge
- THEN the helper returns false from the vendored verified capability-set authorizer

#### Scenario: Preserve exact data-only boundary [r[lib.verified.capability-set-authorizer.boundary]]

- GIVEN caller-supplied public capability documents and a requested resource/ability pair
- WHEN the capability-set authorization bridge runs
- THEN the helper MUST NOT perform wildcard ability subsumption, compact-token verification, proof resolution, cryptographic signature verification, caveat policy evaluation, revocation backend checks, networking, persistence, replay protection, or ambient clock reads

### Requirement: Verified WOT principal derivation bridge [r[library.verified-wot-principal-derivation]]

The library MUST expose a deterministic, data-only Web-of-Trust principal digest helper that derives fixed-width principal digest bytes from caller-supplied public key bytes through vendored verified-logic primitives.

#### Scenario: Deterministic fixed-width digest [r[library.verified-wot-principal-derivation.scenario.deterministic-fixed-width]]

- GIVEN public key bytes supplied by an advanced caller
- WHEN the caller derives a Web-of-Trust principal digest through the public verified bridge
- THEN the returned digest is deterministic for the same input and has the vendored principal digest width

#### Scenario: Boundary excludes trust and resolution [r[library.verified-wot-principal-derivation.scenario.boundary-excludes-trust-resolution]]

- GIVEN public key bytes and no caller-supplied Web-of-Trust evidence
- WHEN the caller derives a Web-of-Trust principal digest through the public verified bridge
- THEN the helper only returns deterministic public principal bytes and MUST NOT resolve identities, fetch trust records, validate attestations, check revocations, authorize UCANs, access storage or network backends, or read an ambient clock

### Requirement: Verified WOT principal digest admission bridge [r[library.verified-wot-principal-digest-admission]]

The library MUST expose a deterministic, data-only Web-of-Trust principal digest admission helper that validates raw caller-supplied principal digest bytes through vendored verified-logic primitives.

#### Scenario: Full-width digest is admitted [r[library.verified-wot-principal-digest-admission.scenario.full-width-admitted]]

- GIVEN raw principal digest bytes with the vendored principal digest width
- WHEN the caller checks the bytes through the public verified bridge
- THEN the helper returns true

#### Scenario: Non-full-width digest is rejected [r[library.verified-wot-principal-digest-admission.scenario.invalid-width-rejected]]

- GIVEN raw principal digest bytes that are shorter or longer than the vendored principal digest width
- WHEN the caller checks the bytes through the public verified bridge
- THEN the helper returns false

#### Scenario: Boundary excludes WOT evidence validation [r[library.verified-wot-principal-digest-admission.scenario.boundary-excludes-evidence-validation]]

- GIVEN raw digest bytes and no caller-supplied Web-of-Trust evidence
- WHEN the caller checks the bytes through the public verified bridge
- THEN the helper only validates fixed-width digest admission and MUST NOT resolve identities, fetch or validate trust records, validate attestations, check revocation freshness, authorize UCANs, access storage or network backends, sign, replay-protect, or read an ambient clock

### Requirement: Verified WOT evidence helper bridges [r[library.verified-wot-evidence-helpers]]

The library MUST expose deterministic, finite, data-only Web-of-Trust evidence helper bridges only when each helper routes through an exact vendored verified-logic attestation, revocation, or trust-threshold primitive.

#### Scenario: Attestation evidence helper uses vendored semantics [r[library.verified-wot-evidence-helpers.scenario.attestation-vendored-semantics]]

- GIVEN caller-supplied public WOT attestation evidence fields and explicit validation inputs
- WHEN the caller invokes a public attestation evidence helper
- THEN the helper MUST route through the corresponding vendored `web_of_trust_attestation` primitive
- AND semantic denial or malformed public evidence MUST be returned as a structured false/error outcome without panicking

#### Scenario: Revocation evidence helper uses vendored semantics [r[library.verified-wot-evidence-helpers.scenario.revocation-vendored-semantics]]

- GIVEN caller-supplied public WOT revocation and attestation evidence fields plus explicit time inputs
- WHEN the caller invokes a public revocation evidence helper
- THEN the helper MUST route through the corresponding vendored `web_of_trust_revocation` primitive
- AND non-matching, inactive, or invalid public evidence MUST be returned as a structured false/error outcome without panicking

#### Scenario: Evidence helpers preserve shell boundaries [r[library.verified-wot-evidence-helpers.scenario.boundary-preserved]]

- GIVEN public WOT evidence bytes and no caller-supplied resolver, store, registry, signer, or clock
- WHEN the caller invokes any WOT evidence helper
- THEN the helper MUST NOT resolve identities, fetch proofs, fetch trust records, perform hidden registry freshness checks, access storage or network backends, sign, persist state, replay-protect, or read an ambient clock

### Requirement: Verified typed caveat helper bridges [r[library.verified-typed-caveat-helpers]]

The library MUST expose opt-in deterministic typed caveat helper bridges only for caveat semantics that route through exact vendored `ucan_caveat` primitives, while preserving caller-supplied shell caveat policy as the production authorization boundary.

#### Scenario: Typed caveat helper admits supported context [r[library.verified-typed-caveat-helpers.scenario.supported-context]]

- GIVEN a supported typed caveat and explicit caller-supplied context values
- WHEN the caller invokes the public typed caveat helper
- THEN the helper MUST route through the corresponding vendored `ucan_caveat` primitive
- AND the helper MUST return the vendored semantic allow/deny outcome without panicking

#### Scenario: Shell policy remains caller supplied [r[library.verified-typed-caveat-helpers.scenario.shell-policy-remains-caller-supplied]]

- GIVEN a token containing opaque caveat payloads
- WHEN the production shell verifies authorization with a caller-supplied caveat policy set
- THEN verification MUST continue to require explicit caller policy acceptance
- AND the typed caveat helpers MUST NOT automatically allow unknown or unsupported caveats

#### Scenario: Typed caveat helpers preserve runtime boundaries [r[library.verified-typed-caveat-helpers.scenario.boundary-preserved]]

- GIVEN typed caveat inputs and no caller-supplied backend or clock
- WHEN any typed caveat helper runs
- THEN the helper MUST NOT access storage, network, process-global registries, sign data, persist state, replay-protect, or read an ambient clock

### Requirement: Verified proof traversal model [r[library.verified-proof-traversal-model]]

The library MUST preserve the existing caller-injected proof traversal behavior while defining any future verified traversal bridge over finite resolved proof data and traversal transcripts rather than hidden resolver, proof-store, network, filesystem, cryptographic, revocation-backend, or ambient-clock side effects.

#### Scenario: Resolved traversal model preserves success semantics [r[library.verified-proof-traversal-model.scenario.success-semantics]]

- GIVEN a finite resolved proof chain whose references, parent-child issuer/audience links, temporal bounds, capability attenuation, caveat preservation, traversal budgets, and revocation facts are valid
- WHEN the shell routes matching traversal admission through verified traversal primitives
- THEN verification MUST still succeed for the same chain
- AND the resulting effective delegation and authorization decision MUST match the shell's existing semantics

#### Scenario: Backend boundaries remain shell owned [r[library.verified-proof-traversal-model.scenario.backend-boundaries]]

- GIVEN resolver, proof-store, revocation, parsing, cryptographic signature, compact-codec, or caller caveat-policy failures from shell dependencies
- WHEN proof traversal verification runs
- THEN those failures MUST remain fail-closed shell errors
- AND verified traversal primitives MUST NOT fetch proofs, resolve keys, verify signatures, access storage or network backends, persist state, replay-protect, sign, or read an ambient clock

### Requirement: Verified compact-token codec boundary [r[library.verified-compact-token-codec-boundary]]

The library MUST expose and use a verified compact-token framing bridge for already-encoded compact token parts while continuing to distinguish trusted runtime codec, hash, and cryptographic boundaries from verified structural admission. The bridge MUST NOT claim base64url, serde JSON, BLAKE3, Ed25519, resolver, proof-store, revocation-backend, caveat-policy, filesystem, network, signing, persistence, or ambient-clock behavior is formally verified.

#### Scenario: Structural compact-token admission is explicit [r[library.verified-compact-token-codec-boundary.scenario.structural-admission]]

- GIVEN malformed compact token strings with missing parts, extra parts, empty components, invalid encodings, or invalid JSON claims
- WHEN the shell parses or verifies those strings
- THEN it MUST return structured errors without panicking
- AND the verified compact framing helper MUST document that it proves only exact byte framing over already-encoded parts

#### Scenario: Signing input stability remains deterministic [r[library.verified-compact-token-codec-boundary.scenario.signing-input-stability]]

- GIVEN validated public header and claims data or already-split encoded compact parts
- WHEN the shell constructs signing input or proof-reference bytes
- THEN signing input construction MUST be deterministic for the same encoded header and payload bytes
- AND tests or verified helpers MUST avoid printing compact UCAN token values, bearer values, signing secrets, private keys, or credential-like logs

#### Scenario: Runtime trust boundaries are not hidden [r[library.verified-compact-token-codec-boundary.scenario.trust-boundaries]]

- GIVEN compact-token verification that uses runtime codec, hash, and cryptographic libraries
- WHEN documentation or guard scripts describe verification coverage
- THEN they MUST state that codec/hash/crypto internals remain trusted boundaries unless replaced by exact verified primitives
- AND the compact framing bridge MUST remain data-only and side-effect free

#### Scenario: Compact envelope bridge rejects mismatched bytes [r[library.verified-compact-token-codec-boundary.scenario.compact-envelope-bridge]]

- GIVEN already-split encoded header, payload, and signature parts plus caller-supplied compact and signing-input bytes
- WHEN either the compact bytes differ from `header.payload.signature` or the signing input bytes differ from `header.payload`
- THEN the verified bridge MUST reject the envelope
- AND parse-time integration MUST fail closed with a structured compact-token error rather than continuing to decode or verify the token

### Requirement: Caveat-preserving attenuation invariant [r[library.verified-caveat-preserving-attenuation]]

The library MUST preserve the invariant that a child capability is authorized by a parent capability only when the same parent both contains the child resource/ability and has every opaque parent caveat preserved by the child capability.

#### Scenario: Same parent supplies containment and caveat preservation [r[library.verified-caveat-preserving-attenuation.scenario.same-parent-required]]

- GIVEN multiple parent capabilities where one parent contains the child resource/ability and another parent has matching caveats
- WHEN the shell computes effective delegation for the child capability
- THEN authorization MUST fail unless a single parent capability satisfies both containment and caveat-preservation requirements

#### Scenario: Missing parent caveat is rejected [r[library.verified-caveat-preserving-attenuation.scenario.missing-caveat-rejected]]

- GIVEN a parent capability with opaque caveats and a child capability that omits one or more of those caveats
- WHEN the shell verifies delegation attenuation
- THEN verification MUST fail with a structured attenuation or caveat-preservation error
- AND the child token MUST NOT be treated as authorized

#### Scenario: Future verified bridge must be exact [r[library.verified-caveat-preserving-attenuation.scenario.verified-bridge-exactness]]

- GIVEN an implementation that claims caveat-preserving attenuation is routed through vendored verified-logic
- WHEN bridge guards and documentation are checked
- THEN they MUST show that the bridge enforces same-parent resource/ability containment plus opaque caveat preservation
- AND the implementation MUST NOT replace the shell check with a non-equivalent helper

### Requirement: Finite verified proof traversal primitives [r[library.verified-proof-traversal-primitives]]

The library MUST define future proof traversal verification in terms of finite, deterministic, data-only primitives that consume already-resolved structural inputs or shell-produced traversal transcripts, rather than resolver, proof-store, parser, cryptographic, storage, network, signing, persistence, replay, or ambient-clock side effects.

#### Scenario: Proof graph well-formedness is data-only [r[library.verified-proof-traversal-primitives.scenario.graph-well-formedness]]

- GIVEN finite parent and child proof entries with issuer, audience, proof reference, capability, temporal, and caveat-preservation fields
- WHEN the proof graph well-formedness primitive checks an edge
- THEN it MUST accept only edges whose child issuer matches the parent audience under verified proof-link semantics
- AND it MUST NOT fetch, parse, resolve, verify signatures, read storage, access a network, or consult an ambient clock

#### Scenario: Traversal budgets and cycles are checked over finite traces [r[library.verified-proof-traversal-primitives.scenario.bounded-traversal]]

- GIVEN a finite traversal trace with visited proof references, depth counters, proof counters, and input-byte counters
- WHEN the bounded traversal primitive checks the trace
- THEN it MUST reject cycles, duplicate visited references where they would create unsafe traversal, and exceeded depth, proof-count, or input-byte budgets
- AND it MUST preserve the shell requirement that limit violations fail closed

#### Scenario: Effective delegation folding preserves attenuation [r[library.verified-proof-traversal-primitives.scenario.effective-delegation-folding]]

- GIVEN an ordered finite proof chain from root through leaf
- WHEN the effective delegation folding primitive computes or checks the chain result
- THEN the result MUST preserve capability attenuation, temporal narrowing, and parent caveat payload preservation constraints at every step
- AND any over-broad resource, ability, time window, or missing preserved caveat MUST make the fold invalid

#### Scenario: Proof-chain authorization consumes folded results [r[library.verified-proof-traversal-primitives.scenario.chain-authorization]]

- GIVEN a finite proof chain, a folded effective delegation, and a requested invocation resource and ability
- WHEN the proof-chain authorization primitive decides whether the request is authorized
- THEN it MUST allow only requests contained by the effective delegated capability set and valid temporal window
- AND it MUST reject malformed, over-broad, expired, not-yet-valid, or disconnected chains

#### Scenario: Revocation-aware traversal denies from supplied facts [r[library.verified-proof-traversal-primitives.scenario.revocation-aware-chain]]

- GIVEN a finite proof chain and caller-supplied revocation facts for the leaf and proof-chain references
- WHEN the revocation-aware traversal primitive checks the chain
- THEN any supplied revoked fact MUST make the chain invalid
- AND the primitive MUST NOT query a revocation backend or convert unknown/backend-error states into allow decisions

#### Scenario: Traversal transcript consistency is checked canonically [r[library.verified-proof-traversal-primitives.scenario.transcript-consistency]]

- GIVEN a shell-produced traversal transcript containing requested proof references, resolved entries, parent-child links, fold steps, budget counters, revocation facts, and the final authorization target
- WHEN the transcript consistency primitive checks the transcript
- THEN it MUST reject transcripts whose visited references, edge order, counters, fold steps, revocation facts, or final decision are internally inconsistent
- AND a valid transcript MUST be sufficient for the UCAN shell to route matching traversal admission through verified logic without moving resolver, parser, proof-store, revocation-backend, crypto, or caveat-policy behavior into the primitive

### Requirement: Live linear proof traversal transcript checking [r[library.live-linear-proof-traversal-transcript]]

The UCAN shell MUST emit and verify an internal finite proof traversal transcript for compact-token verification paths whose proof graph is empty or exactly one parent per token and whose edges match the current primitive's resource-prefix and UCAN wildcard ability-containment model, using the vendored verified proof-traversal bridge before returning a verified token.

#### Scenario: Eligible linear chain is bridge checked [r[library.live-linear-proof-traversal-transcript.eligible-linear-chain-bridge-checked]]

- GIVEN a compact token verification path with no proof or a single-parent proof chain whose attenuation uses exact ability equality or verified wildcard ability containment and resource-prefix containment
- WHEN the shell has parsed, structurally validated, signature-verified, revocation-checked, and authorized the involved tokens
- THEN the shell MUST adapt the already available token facts into a parent-to-child transcript
- AND the shell MUST call the vendored proof traversal transcript bridge before returning success

#### Scenario: Multi-parent DAG remains explicit boundary [r[library.live-linear-proof-traversal-transcript.multi-parent-boundary]]

- GIVEN a token with multiple direct parent proofs
- WHEN the current linear transcript primitive cannot represent the proof graph exactly
- THEN the shell MUST leave that DAG on existing shell validation semantics
- AND documentation MUST state that a future verified DAG primitive is required before claiming bridge coverage for multi-parent proof graphs

#### Scenario: Bridge rejection fails closed [r[library.live-linear-proof-traversal-transcript.bridge-rejection-fails-closed]]

- GIVEN an eligible linear proof chain whose shell-produced transcript is rejected by the verified bridge
- WHEN verification reaches transcript checking
- THEN verification MUST fail with a proof-chain error
- AND the token MUST NOT be returned as verified

#### Scenario: Shell boundaries are preserved [r[library.live-linear-proof-traversal-transcript.boundary-preserved]]

- GIVEN live transcript checking is enabled for an eligible chain
- WHEN the shell builds the transcript
- THEN the builder MUST NOT fetch proofs, parse compact tokens, verify signatures, query revocation backends, evaluate arbitrary caveat policies, persist state, access the network or filesystem, sign data, or read an ambient clock
- AND those effects MUST remain in the existing caller-injected shell boundaries

### Requirement: Verified DAG Proof Traversal Transcript [r[ucan.verified-dag-proof-traversal-transcript]]

The library MUST expose a finite DAG proof traversal transcript bridge that validates caller-supplied entries, topologically ordered parent indices, budgets, capability attenuation, caveat preservation, leaf authorization, and revocation facts without performing token parsing, proof fetching, signature verification, clock reads, network I/O, filesystem I/O, or backend lookup.

#### Scenario: Multi-parent DAG accepts attenuated leaf [r[ucan.verified-dag-proof-traversal-transcript.scenario.accepts-attenuated-leaf]]

- GIVEN a caller-supplied DAG transcript whose parent indices point only to earlier entries
- AND every parent link narrows issuer/audience, time, capabilities, and caveats
- AND the leaf capability authorizes the requested target
- WHEN the bridge validates the transcript against caller-supplied budgets
- THEN the transcript is accepted.

#### Scenario: DAG rejects cycles and escalation [r[ucan.verified-dag-proof-traversal-transcript.scenario.rejects-cycles-escalation]]

- GIVEN a caller-supplied DAG transcript with a self/forward parent index or an edge that escalates authorization
- WHEN the bridge validates the transcript
- THEN the transcript is rejected without consulting external proof or revocation backends.

### Requirement: Verified verification-stage transcript boundary [r[library.verified-verification-stage-transcript-boundary]]

The library MUST expose a data-only verified transcript boundary for finite UCAN verification stage facts, and MUST accept a transcript only when every required stage fact is successful. The bridge MUST NOT claim that parser internals, base64url, JSON serde/canonicalization, Ed25519, BLAKE3, resolver/proof-store/revocation backend correctness, proof freshness, filesystem/network behavior, caveat policies, signing, persistence, replay protection, or ambient clocks are formally verified.

#### Scenario: Accepted transcript requires every stage [r[library.verified-verification-stage-transcript-boundary.scenario.accepts-all-stages]]

- GIVEN a transcript whose parse, structural, key-resolution, signature, envelope, revocation, proof-load, proof-chain, and authorization facts all pass
- WHEN the verified stage transcript bridge evaluates it
- THEN the bridge MUST accept it
- AND the first-failure stage MUST be the accepted sentinel

#### Scenario: Rejected transcript reports first failed stage [r[library.verified-verification-stage-transcript-boundary.scenario.rejects-first-failure]]

- GIVEN a transcript with one or more failed stage facts
- WHEN the verified stage transcript bridge evaluates it
- THEN the bridge MUST reject it
- AND the first-failure stage MUST identify the earliest failed stage in fixed shell order without exposing token bytes or backend payloads

#### Scenario: Runtime trust boundaries remain explicit [r[library.verified-verification-stage-transcript-boundary.scenario.trust-boundaries]]

- GIVEN shell verification uses runtime codec, cryptographic, resolver, proof-store, revocation, and caveat-policy code
- WHEN documentation or guard scripts describe stage transcript coverage
- THEN they MUST state that the transcript bridge consumes caller-supplied facts only
- AND they MUST NOT describe backend correctness, cryptographic validity, parsing semantics, proof freshness, or caveat policy satisfaction as verified by this bridge

### Requirement: Live DAG proof traversal transcripts

The library MUST route live multi-parent proof traversal transcripts through the verified DAG traversal bridge when recursive proof verification successfully resolves a representable finite proof DAG.

#### Scenario: Multi-parent proof verification emits checked DAG transcript

- GIVEN a compact UCAN whose direct proofs verify successfully through caller-supplied key resolver and proof store facts
- AND the resolved proof facts form a finite topologically ordered proof DAG representable by the live transcript model
- WHEN the shell returns a verified token
- THEN the emitted proof transcript MUST have been accepted by `proof_traversal_dag_transcript_is_valid`
- AND the transcript MUST preserve explicit budgets, visited proof references, parent indices, temporal validity, non-revocation facts, and capability attenuation facts.

#### Scenario: Runtime trust boundaries remain external

- GIVEN the shell emits and checks a live proof-DAG transcript
- WHEN documentation describes the verified boundary
- THEN it MUST state that compact decoding, JSON canonicalization, signature cryptography, proof-reference hashing, proof-store/resolver/revocation backend truth or freshness, and arbitrary caveat policies remain outside formal verification.

### Requirement: Backend failure transcripts
The library SHALL expose and use a verified finite backend-operation transcript boundary for key resolution, proof loading, and revocation checks.

#### Scenario: Accepts only successful backend operations
- **WHEN** every operation fact in the transcript reports success
- **THEN** the backend transcript outcome is accepted

#### Scenario: Reports first failed backend operation
- **WHEN** one or more operation facts in the transcript report failure
- **THEN** the backend transcript outcome is rejected and identifies the first failed operation in transcript order

#### Scenario: Live verification fails closed on backend errors
- **WHEN** a caller-injected key resolver, proof store, or revocation checker returns a missing-data or backend error
- **THEN** verification returns the corresponding typed failure rather than authorizing the token
- **AND** the transcript boundary does not claim backend correctness, freshness, provenance, parsing, cryptography, hashing, I/O, or ambient runtime behavior

### Requirement: Verified typed caveat policy bridge
The library SHALL provide a first-party caveat policy set for the exact finite typed caveat subset backed by vendored verified logic, covering time-bound and rate-limit caveats over caller-supplied runtime facts.

#### Scenario: Satisfied typed caveats admit authorization
- **WHEN** a matching capability carries recognized typed caveats whose parsed facts are satisfied by the caller-supplied caveat context
- **THEN** authorization through the typed policy set SHALL allow that capability when resource and ability attenuation also match

#### Scenario: Unsatisfied or malformed typed caveats deny authorization
- **WHEN** a matching capability carries a recognized typed caveat whose parsed facts are unsatisfied or malformed
- **THEN** authorization through the typed policy set SHALL fail closed with a caveat rejection

#### Scenario: Unknown caveats remain caller controlled
- **WHEN** a matching capability carries a caveat outside the typed policy identities
- **THEN** the typed policy set SHALL NOT silently satisfy it and SHALL preserve the existing missing-policy/deny-by-default behavior unless another caller-supplied policy handles it

#### Scenario: Runtime facts remain trusted shell inputs
- **WHEN** the typed policy set evaluates time or rate-limit caveats
- **THEN** it SHALL document that current time, use counts, and external quota/freshness/provenance are caller-supplied runtime facts outside the verified primitive
