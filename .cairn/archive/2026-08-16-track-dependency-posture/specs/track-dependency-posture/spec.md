# Dependency Posture Tracking

## ADDED Requirements

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
