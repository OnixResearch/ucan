# Fix Caveat Payload Leak Specification

## Purpose

Defines the `fix-caveat-payload-leak` capability.

## Requirements

### Requirement: Verification no longer leaks caveat inputs

r[ucan.leak.verify] `verify_compact_token` and every entry in the live proof traversal MUST NOT permanently retain the caveat payload bytes or capability input boxes of a token after verification returns.

#### Scenario: Repeated verification of a caveated token

r[ucan.leak.verify.repeated]
- GIVEN a verifier calls `verify_compact_token` on a token that carries a large caveat payload
- WHEN the verifier repeats the call many times
- THEN the resident memory MUST NOT grow with the number of completed calls
- AND the allocator MUST reclaim the per-call caveat buffers

#### Scenario: Proof traversal with caveated parents

r[ucan.leak.verify.traversal]
- GIVEN a child token whose proof parents carry caveats
- WHEN the live proof traversal verifies every parent
- THEN no parent caveat buffer MUST be permanently retained
- AND the traversal result MUST equal the current behavior

### Requirement: Issuance no longer leaks caveat inputs

r[ucan.leak.issue] `issue_token_with_signer` and its structural self-check MUST NOT permanently retain caveat payload bytes for an issued token.

#### Scenario: Repeated issuance of a caveated token

r[ucan.leak.issue.repeated]
- GIVEN a signer issues tokens that carry caveats
- WHEN the signer issues many tokens through the same process
- THEN the resident memory MUST NOT grow with the number of issued tokens
- AND the issued compact-token bytes MUST NOT change

### Requirement: The core contract stays borrowed

r[ucan.leak.core] `ucan-core` MUST keep accepting borrowed `CaveatInput` and `CapabilityInput` values. The shell MUST own any lifetime resolution required for those values.

#### Scenario: Core API stability

r[ucan.leak.core.stable]
- GIVEN a consumer builds against `ucan-core` at the audited revision
- WHEN the fix is applied
- THEN the consumer MUST compile without source changes
- AND the core MUST NOT allocate leaked storage on behalf of callers

### Requirement: The regression is measured

r[ucan.leak.regression] The change MUST add a reproducible memory regression test that fails when the leak returns.

#### Scenario: Leak regression is exercised

r[ucan.leak.regression.exercised]
- GIVEN the memory regression test runs
- WHEN a token with a large caveat payload is verified many times
- THEN the test MUST fail when retained memory per call exceeds a fixed bound
- AND the test MUST pass when the leak is absent
