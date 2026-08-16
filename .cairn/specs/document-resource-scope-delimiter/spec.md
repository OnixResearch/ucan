# Document Resource Scope Delimiter Specification

## Purpose

Defines the `document-resource-scope-delimiter` capability.

## Requirements

### Requirement: Prefix semantics are documented

r[ucan.scope.prefix] The authorization reference MUST document that resource containment is byte-prefix matching, and that a scope covers every string that starts with its bytes.

#### Scenario: Consumer reads the containment rule

r[ucan.scope.prefix.containment]
- GIVEN a consumer reads the authorization reference
- WHEN the consumer plans resource namespaces
- THEN the byte-prefix rule MUST be explicit
- AND the shared-prefix overmatch behavior MUST be explicit

### Requirement: Delimiter guidance exists

r[ucan.scope.delimiter] The documentation MUST recommend explicit segment delimiters in resource construction so sibling resources do not share a prefix accidentally.

#### Scenario: Consumer constructs a resource

r[ucan.scope.delimiter.guidance]
- GIVEN a consumer concatenates namespace parts into a resource
- WHEN the consumer follows the documentation
- THEN the documentation MUST show a delimited construction
- AND the documentation MUST warn against delimiter-free concatenation

### Requirement: Prefix behavior is pinned by fixtures

r[ucan.scope.fixtures] The change MUST add coverage fixtures that record the sibling-prefix admission so future changes cannot silently alter the containment rule.

#### Scenario: Sibling prefix is exercised

r[ucan.scope.fixtures.sibling]
- GIVEN a capability scoped to `did:key:z6Mkresource`
- WHEN a consumer authorizes `did:key:z6MkresourceX`
- THEN the fixture MUST record the prefix admission result
- AND the fixture MUST name the semantics it pins
