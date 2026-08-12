# Integration Support Profile Specification

## ADDED Requirements

### Requirement: The Rust readiness catalog owns actual support

r[ucan.integration_support_profiles.support_catalog] UCAN MUST derive a deterministic versioned support catalog from `production_readiness_report()` and MUST bind its machine JSON and generated Nickel vocabulary projections to canonical catalog bytes with BLAKE3.

#### Scenario: Machine report differs from the Rust API

- GIVEN `docs/production-readiness.json` adds, removes, renames, or relabels a surface without the same canonical Rust catalog change
- WHEN readiness freshness validation runs
- THEN validation MUST fail with a structural catalog/projection mismatch before release.

### Requirement: Support-level promotion is explicit

r[ucan.integration_support_profiles.support_levels] Supported, preview, unsupported, and any future production support levels MUST be closed catalog values, and promotion to a stronger level MUST require explicit evidence and migration review rather than documentation-only relabeling.

#### Scenario: Unsupported surface is promoted in a projection

- GIVEN remote DID resolution, proof transport, registry revocation, replay persistence, or a non-admitted key algorithm is relabeled without the Rust catalog and required evidence changing
- WHEN support validation runs
- THEN validation MUST reject the promotion and preserve the prior fail-closed classification.

### Requirement: Integration profiles are typed and catalog-bound

r[ucan.integration_support_profiles.profile_contract] A Nickel integration profile MUST declare exact schema/id, bound support-catalog identity, unique required and preview surface sets, admitted DID/signature/key classes, finite verification limits, caller-owned integration modes, fail-closed behavior, and explicit non-claims.

#### Scenario: Required integration input is omitted

- GIVEN a profile omits key resolution, proof loading, revocation, replay, verification time/limits, caveat policy, or signer custody while selecting a surface that requires it
- WHEN Nickel validates the whole profile
- THEN export MUST fail and MUST NOT infer an ambient default integration.

### Requirement: Profile admission is a pure subset decision

r[ucan.integration_support_profiles.subset_admission] UCAN MUST validate profile intent against the bound Rust support catalog in a pure deterministic core, rejecting absent or unsupported required surfaces, implicit preview use, stale catalog identity, invalid limits, and weakened non-claims.

#### Scenario: Profile requests unsupported transport

- GIVEN a well-shaped profile requires a built-in network, filesystem, database, IPFS, registry, or replay-persistence surface classified as unsupported
- WHEN subset admission runs
- THEN admission MUST fail with the requested surface and support level
- AND no token verification or authorization operation may be inferred.

### Requirement: Fixture manifests contain public bounded metadata only

r[ucan.integration_support_profiles.fixture_manifests] Integration fixture manifests MUST bind fixture id, profile id, public input/reference BLAKE3, expected result class, required support surfaces, and non-claims, and MUST reject live private keys, credentials, bearer tokens, secret payloads, and ambient backend authority.

#### Scenario: Secret-like fixture field is added

- GIVEN a manifest includes live private key material, bearer credentials, a secret backend locator, or an unbounded token payload
- WHEN the fixture contract is evaluated
- THEN validation MUST fail before fixture execution or artifact publication.

### Requirement: Positive and negative profile evidence is maintained

r[ucan.integration_support_profiles.fixtures] The integration-profile suite MUST include positive supported and explicitly admitted preview profiles plus negative unsupported-surface, missing-integration, invalid-limit, stale-identity, duplicate, secret-field, and overclaim cases.

#### Scenario: New profile field has no failure case

- GIVEN a profile change adds a support, authority, identity, limit, or claim field
- WHEN fixture coverage is checked
- THEN the change MUST include a valid case and at least one deterministic rejecting case for the new invariant.

### Requirement: Support artifacts and documentation stay fresh

r[ucan.integration_support_profiles.freshness] A Rust-owned readiness rail MUST structurally compare the canonical catalog, generated machine report, generated Nickel vocabulary, reviewed profiles, fixture manifests, and operator documentation and MUST fail on stale identities or contradictory support claims.

#### Scenario: Documentation overstates a profile

- GIVEN prose claims built-in backend, production, algorithm, DID method, or persistence support absent from the bound catalog/profile
- WHEN readiness validation runs
- THEN validation MUST fail with the contradictory surface and source document.

### Requirement: Integration profiles do not become authorization policy

r[ucan.integration_support_profiles.runtime_boundary] UCAN MUST keep profile generation/checking outside issue, parse, verify, invocation, caveat, revocation, replay, and authorization hot paths, and runtime APIs MUST continue to receive explicit typed inputs without implicit Nickel discovery or evaluation.

#### Scenario: Profile conformance passes

- GIVEN a profile and fixture manifest satisfy their contracts and subset checks
- WHEN the result is summarized
- THEN it MUST state that resolver truth, key custody, cryptographic correctness, revocation/replay freshness, backend durability, and application authorization completeness remain unproven and caller-owned.
