# Root Issuer Admission Specification

## Purpose

Defines the `root-issuer-admission` capability: separating "this key signed it" from "this key may originate authority" in compact-token verification.

## Requirements

### Requirement: Verified tokens report their root issuers

r[ucan.root_issuer.report] Compact-token verification MUST record the issuer of every proof-less token reached in the verified delegation graph and expose them through `VerifiedToken::root_issuers`. A token without proofs MUST report itself as its only root issuer.

#### Scenario: Delegated chain

r[ucan.root_issuer.report.delegated]
- GIVEN a token whose proof chain ends in one proof-less token
- WHEN verification succeeds
- THEN `root_issuers` MUST contain exactly that token's issuer

### Requirement: Holder admission requires trusted roots

r[ucan.root_issuer.holder] `verify_holder_signed_invocation` MUST require a caller-supplied `RootIssuerAdmission` and MUST admit every root issuer of the verified token before holder signature verification, profile admission, caveat policy, and replay. Key resolvability MUST NOT imply root authority, because the same resolver resolves holder keys.

#### Scenario: Resolvable non-root key signs a proof-less token

r[ucan.root_issuer.holder.forged]
- GIVEN a resolvable key that is not an admitted root signs a proof-less token for a holder
- WHEN the holder submits a correctly signed invocation
- THEN verification MUST fail with a root-issuer error
- AND profile admission and replay MUST NOT be called

### Requirement: Rechecks observe current root trust

r[ucan.root_issuer.recheck] `recheck_holder_authorization` MUST admit the token's root issuers against the supplied current `RootIssuerAdmission`.

#### Scenario: Root trust is withdrawn

r[ucan.root_issuer.recheck.withdrawn]
- GIVEN an admitted holder invocation
- WHEN its root issuer is no longer admitted
- THEN the recheck MUST fail without another replay admission
