# UCAN License Boundary Specification

## Purpose

Keep the reusable protocol core and verified primitive snapshot under file-level copyleft while retaining AGPL reciprocity for the std shell.

## Requirements

### Requirement: Core and shell licenses are separated

r[ucan.packaging.license_boundary.package_split] `ucan-core` MUST declare `MPL-2.0`, and the root `ucan` std shell MUST declare `AGPL-3.0-or-later`.

#### Scenario: A protocol consumer selects only the core

- GIVEN an application embeds `ucan-core` without the std shell
- WHEN Cargo metadata is inspected
- THEN the core MUST report MPL-2.0 without inheriting the shell's AGPL expression.

### Requirement: Vendored Trellis preserves source licensing

r[ucan.packaging.license_boundary.trellis_snapshot] The vendored `verified-logic` snapshot MUST be imported from a recorded committed Trellis revision, MUST preserve MPL-2.0 metadata and license artifacts, and MUST pass the repository's snapshot synchronization check.

#### Scenario: Trellis and the snapshot drift

- GIVEN the recorded Trellis revision contains different package license metadata or covered bytes than the vendored snapshot
- WHEN synchronization validation runs
- THEN validation MUST fail before the snapshot is treated as aligned.

### Requirement: Complete license artifacts accompany source

r[ucan.packaging.license_boundary.artifacts] UCAN MUST ship complete MPL-2.0 and AGPL-3.0-or-later texts and MUST map root, core, and vendored package surfaces explicitly.

#### Scenario: A source archive is reviewed offline

- GIVEN a recipient receives all UCAN packages and the snapshot
- WHEN license artifacts are inspected
- THEN both complete texts and package mappings MUST be available without an external fetch.

### Requirement: Documentation keeps claims bounded

r[ucan.packaging.license_boundary.documentation] UCAN documentation MUST state that prior grants remain valid, third-party terms remain intact, and Trellis source/proof alignment does not certify UCAN shell behavior or external interoperability.

#### Scenario: Snapshot alignment passes

- GIVEN the vendored verified primitives match Trellis
- WHEN the result is documented
- THEN UCAN MUST NOT promote that fact into a whole-token, policy, resolver, revocation, replay, or network correctness claim.

### Requirement: License validation fails closed

r[ucan.packaging.license_boundary.validation] Focused validation MUST accept the intended core/shell/snapshot mapping and MUST reject reversed package expressions, stale Trellis metadata, or missing complete license artifacts.

#### Scenario: The core remains AGPL accidentally

- GIVEN `ucan-core` retains the old expression after the split
- WHEN license-boundary validation runs
- THEN validation MUST fail with a core-specific mismatch.

### Requirement: Focused verification proves packaging consistency

r[ucan.packaging.license_boundary.final_validation] The change MUST verify Cargo metadata, vendored snapshot identity, complete license artifacts, current documentation, and Cairn conformance.

#### Scenario: The final repository is checked

- GIVEN manifests, snapshot metadata, revision evidence, and license files agree
- WHEN focused checks and Cairn gates run
- THEN the boundary MUST pass without claiming release readiness beyond those checks.
