# Track Dependency Posture Specification

## Purpose

Defines the `track-dependency-posture` capability.

## Requirements

### Requirement: Advisory policy is checked

r[ucan.deps.advisory] The repository MUST carry a checked advisory configuration that runs against the locked dependency set and fails on unapproved advisories.

#### Scenario: CI runs the advisory check

r[ucan.deps.advisory.run]
- GIVEN the advisory configuration is committed
- WHEN the focused Nix check runs
- THEN the advisory check MUST complete against `Cargo.lock`
- AND an unapproved advisory MUST fail the check

#### Scenario: Approved advisory appears

r[ucan.deps.advisory.appears]
- GIVEN an advisory is approved with a recorded rationale
- WHEN the advisory check runs
- THEN the check MUST pass
- AND the rationale MUST state why the advisory does not apply

### Requirement: Non-exploitable advisories are pinned with rationale

r[ucan.deps.ignored] The two currently applicable advisories (`paste` and the `anyhow` downcast unsoundness) MUST be pinned with a BLAKE3-referenced or textual rationale that names why each is not exploitable in this repo.

#### Scenario: Reviewer audits the pins

r[ucan.deps.ignored.audit]
- GIVEN a reviewer opens the advisory configuration
- WHEN the reviewer reads each pin
- THEN each pin MUST explain the non-exploitable basis
- AND no pin MUST cover a vulnerability without a reason

### Requirement: Posture is recorded in the support report

r[ucan.deps.report] The production-readiness report MUST record the audited dependency posture and the date and revision of the assessment.

#### Scenario: Operator reads the support report

r[ucan.deps.report.read]
- GIVEN an operator reads the production-readiness report
- WHEN the operator looks for dependency posture
- THEN the report MUST name the audit revision and date
- AND the report MUST state the zero-exploitable-vulnerability result

### Requirement: Locked set stays the check input

r[ucan.deps.locked] The advisory check MUST run against the locked dependency set and MUST NOT resolve a fresh set at check time.

#### Scenario: Check uses the lockfile

r[ucan.deps.locked.lock]
- GIVEN `Cargo.lock` is the committed dependency set
- WHEN the advisory check runs
- THEN the check MUST use `Cargo.lock`
- AND a drifted lockfile MUST fail the check

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

### Requirement: Implementation identities bind the reviewed BLAKE3 cohort

r[track_dependency_posture.blake3_implementation_identity] UCAN implementation-identity inputs MUST name the same reviewed BLAKE3 version as the exact peer-authentication and Nostr manifest requirements and the resolved workspace lock.

#### Scenario: Reviewed cohort is aligned

- GIVEN both exact BLAKE3 consumers and the lock resolve version `1.8.5`
- WHEN peer-authentication and Nostr implementation identities are derived
- THEN both identity inputs MUST name BLAKE3 `1.8.5`

#### Scenario: Identity label is stale

- GIVEN a manifest resolves the reviewed BLAKE3 cohort
- WHEN its implementation-identity input names another BLAKE3 version
- THEN the dependency-posture rail MUST fail before publication
