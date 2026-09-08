# Holder Authorization Recheck Specification

## Purpose

Defines the `holder-authorization-recheck` capability.

## Requirements

### Requirement: Bind an observation to an existing admission
r[ucan.holder_recheck.binding] The recheck MUST require an existing live holder authorization and the same bounded compact token. It MUST reject observation time before initial verification. These checks MUST precede external verification service calls.

#### Scenario: Another token or earlier time
GIVEN a live holder authorization
WHEN a recheck supplies another token or an earlier observation time
THEN it MUST reject without consulting external verification services or changing replay state.

### Requirement: Observe without another invocation
r[ucan.holder_recheck.observation] The recheck MUST reuse current token/proof verification and non-consuming profile/caveat observation for the original operation. It SHALL expose no replay port. Its result MUST borrow the existing authorization and MUST NOT construct another holder authorization or dispatch permission.

#### Scenario: Current direct or delegated authority
GIVEN an admitted holder invocation and current successful services
WHEN the same token is rechecked
THEN it MUST return a borrowed observation and leave replay admission counts unchanged.

#### Scenario: Authority is no longer acceptable
GIVEN a previously admitted invocation
WHEN time, revocation, profile, caveat, proof, or key services deny or cannot answer
THEN the recheck MUST fail without another replay admission or a success observation.

#### Scenario: A caller tries to reuse the observation as dispatch authority
GIVEN a successful borrowed observation
WHEN the caller requires a new HolderInvocationAuthorized value
THEN the observation MUST provide no constructor or conversion that satisfies that requirement.

### Requirement: Retain scoped evidence
r[ucan.holder_recheck.evidence] Documentation and evidence MUST distinguish supplied-service observations from continuous authority, persistent custody, and safe release. Default and minimal feature profiles MUST retain the same denial semantics.

#### Scenario: A backend changes after the observation
GIVEN a successful recheck followed by changed backend state
WHEN the consumer considers a protected effect
THEN the earlier observation MUST NOT replace its current atomic authority check.
