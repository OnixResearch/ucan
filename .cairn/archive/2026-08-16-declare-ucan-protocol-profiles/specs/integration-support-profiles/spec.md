# Declare UCAN Protocol Profiles

## ADDED Requirements

### Requirement: Protocol profiles are nominal and closed

r[ucan.protocol_profiles.catalog] UCAN MUST define closed nominal protocol-profile IDs with explicit support states. The local compact profile and final UCAN `1.0.0` profile MUST have different IDs and MUST NOT imply compatibility with each other.

#### Scenario: Known local profile is inspected

r[ucan.protocol_profiles.catalog.local]
- GIVEN an operator inspects the support catalog
- WHEN the local compact profile is selected
- THEN the catalog MUST identify its three-part JWT, Ed25519, JSON-claim, and BLAKE3 proof-reference behavior
- AND it MUST NOT label that behavior as final UCAN `1.0.0`

#### Scenario: Unknown profile is supplied

r[ucan.protocol_profiles.catalog.unknown]
- GIVEN a caller or profile artifact supplies an unknown protocol-profile ID
- WHEN profile admission runs
- THEN admission MUST fail closed
- AND no token decoder or authority evaluator MUST be selected

### Requirement: Existing compact behavior is explicitly bound

r[ucan.protocol_profiles.compact] Existing compact issue, parse, verify, proof, and authorization APIs MUST remain bound to the local compact protocol profile without changing signed token bytes.

#### Scenario: Existing compact token round trip runs

r[ucan.protocol_profiles.compact.roundtrip]
- GIVEN a token accepted before this change
- WHEN the same compact API verifies it after this change
- THEN verification MUST preserve the existing behavior
- AND the reported protocol profile MUST be the local compact profile

#### Scenario: UCAN 1.0 token reaches compact input

r[ucan.protocol_profiles.compact.reject]
- GIVEN DAG-CBOR UCAN `1.0.0` bytes are supplied to a compact-token API
- WHEN the compact parser evaluates the input
- THEN it MUST reject the input
- AND it MUST NOT infer or dispatch to a UCAN `1.0.0` parser

### Requirement: Integration profiles select an exact protocol

r[ucan.protocol_profiles.selection] Every reviewed integration support profile MUST select one exact supported protocol-profile ID bound to the current support-catalog BLAKE3 identity.

#### Scenario: Supported local profile is complete

r[ucan.protocol_profiles.selection.complete]
- GIVEN a reviewed profile selects the local compact profile and all required caller-owned integrations
- WHEN subset admission runs
- THEN admission MUST accept the protocol-profile selection

#### Scenario: Unsupported final profile is selected

r[ucan.protocol_profiles.selection.unsupported]
- GIVEN a reviewed profile selects `ucan-wg-1.0.0` before implementation evidence exists
- WHEN subset admission runs
- THEN admission MUST reject the profile as unsupported
- AND documentation or fixtures MUST NOT promote it

### Requirement: Protocol sources are pinned by role

r[ucan.protocol_profiles.sources] The protocol evidence MUST pin the final UCAN overview, Delegation, Invocation, fixture, and selected Rust reference revisions. Each source MUST declare whether it is normative, fixture evidence, or a non-authoritative implementation reference.

#### Scenario: Reference and specification disagree

r[ucan.protocol_profiles.sources.disagree]
- GIVEN `rs-ucan` or another implementation reference differs from a final normative specification
- WHEN support behavior is selected
- THEN the final normative specification MUST control the protocol requirement
- AND the disagreement MUST remain visible in the conformance report

#### Scenario: A moving source is proposed

r[ucan.protocol_profiles.sources.moving]
- GIVEN a source uses a branch, latest release page, or unpinned documentation URL
- WHEN protocol evidence validation runs
- THEN validation MUST reject it as non-reproducible

### Requirement: Fixture manifests preserve exact source identity

r[ucan.protocol_profiles.fixtures] A UCAN `1.0.0` fixture manifest MUST bind each selected file to its source repository, full Git revision, safe relative path, source blob identity, BLAKE3 byte identity, case class, and expected local status.

#### Scenario: Pinned fixture matches

r[ucan.protocol_profiles.fixtures.matches]
- GIVEN a selected fixture matches its declared source revision, path, blob, and BLAKE3 identity
- WHEN fixture validation runs
- THEN the fixture MUST enter the conformance inventory

#### Scenario: Fixture identity drifts

r[ucan.protocol_profiles.fixtures.drift]
- GIVEN a fixture has a stale revision, unsafe path, duplicate ID, wrong blob, or wrong BLAKE3 identity
- WHEN fixture validation runs
- THEN validation MUST fail before executing the fixture

### Requirement: Conformance reports preserve non-success

r[ucan.protocol_profiles.report] The conformance checker MUST classify every selected case as `pass`, `fail`, `unsupported`, or `untested`. It MUST bind the implementation profile, implementation revision, upstream revision, fixture identity, stage, reason code, and non-claims.

#### Scenario: Codec is not implemented

r[ucan.protocol_profiles.report.unsupported]
- GIVEN a valid UCAN `1.0.0` fixture requires an unavailable codec
- WHEN the conformance checker runs
- THEN the case MUST report `unsupported`
- AND it MUST NOT report `pass`, omit the case, or treat fixture import as interoperability

#### Scenario: Invalid fixture is accepted

r[ucan.protocol_profiles.report.fail]
- GIVEN a negative fixture reaches an implemented profile and the implementation accepts it
- WHEN the checker compares the expected result
- THEN the case MUST report `fail`
- AND the profile MUST remain ineligible for a stronger support label

### Requirement: Protocol claims remain bounded

r[ucan.protocol_profiles.docs] Documentation MUST distinguish the local compact profile, final UCAN `1.0.0`, legacy JWT references, and separate session protocols such as AWAKE.

#### Scenario: Operator reads compatibility status

r[ucan.protocol_profiles.docs.operator]
- GIVEN the operator reads the support report or README
- WHEN protocol compatibility is described
- THEN the text MUST state the exact implemented profile
- AND it MUST exclude complete UCAN `1.0.0`, AWAKE, Promise, Revocation, transport, resolver, and storage claims unless separate evidence supports them

### Requirement: Profile evidence has positive and negative validation

r[ucan.protocol_profiles.validation] The profile and fixture rail MUST test accepted local declarations and rejected missing, unknown, unsupported, stale, malformed, duplicate, unsafe-path, and digest-mismatch declarations.

#### Scenario: Validation rail completes

r[ucan.protocol_profiles.validation.rail]
- GIVEN profile artifacts, fixture manifests, reports, and documentation are current
- WHEN the focused and repository checks run
- THEN all positive cases MUST pass
- AND all negative cases MUST fail with stable typed reasons
