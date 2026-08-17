# UCAN 1.0 Authorization Specification

## ADDED Requirements

### Requirement: Commands use final-profile hierarchy

r[ucan.v1_authorization.command] Final UCAN `1.0.0` commands MUST use a separate slash-command type and MUST attenuate only by exact equality or complete descendant segments. Compact ability wildcard semantics MUST NOT enter this comparison.

#### Scenario: Parent command proves a child

- GIVEN a Delegation command is `/crud` and an Invocation command is `/crud/create`
- WHEN command attenuation runs
- THEN the Delegation command MUST prove the Invocation command

#### Scenario: Lexical prefix is not a parent

- GIVEN a Delegation command is `/crypto` and an Invocation command is `/cryptocurrency`
- WHEN command attenuation runs
- THEN attenuation MUST fail

### Requirement: Delegation policy is bounded and exact

r[ucan.v1_authorization.policy] UCAN MUST parse and evaluate only the final Delegation policy operators, selectors, connectives, negation, and quantifiers over bounded Invocation arguments. Unknown or malformed syntax MUST fail closed.

#### Scenario: Policy matches arguments

- GIVEN every top-level policy statement evaluates true over the exact Invocation arguments
- WHEN policy evaluation completes within limits
- THEN the policy MUST be satisfied

#### Scenario: Selector cannot resolve

- GIVEN a required selector cannot resolve against the Invocation arguments
- WHEN its statement is evaluated
- THEN the statement MUST evaluate false as specified
- AND evaluation MUST NOT panic or authorize the Invocation

#### Scenario: Unsupported jq feature is supplied

- GIVEN a selector or statement uses pipes, arithmetic, regex, assignment, recursive descent, or another unsupported feature
- WHEN policy parsing runs
- THEN parsing MUST reject the policy with a stable reason

### Requirement: Ordered Delegation chains preserve authority

r[ucan.v1_authorization.chain] UCAN MUST compose Invocation proof chains in declared root-to-invoker order. It MUST validate principal alignment, subject continuity, Powerline substitution, command attenuation, policy applicability, time validity, proof uniqueness, and configured limits.

#### Scenario: Direct chain is valid

- GIVEN the root Delegation issuer controls the declared subject, the final audience is the Invoker, and all bounds match
- WHEN chain composition runs
- THEN it MUST return the exact effective authority facts

#### Scenario: Proof order is changed

- GIVEN valid Delegations are supplied in an order that breaks adjacent audience and issuer alignment
- WHEN chain composition runs
- THEN it MUST fail
- AND it MUST NOT reorder the proofs

#### Scenario: Root uses Powerline

- GIVEN the root Delegation has a null subject
- WHEN chain composition runs
- THEN it MUST reject the chain

### Requirement: Proof stores bind returned Delegations

r[ucan.v1_authorization.proof_store] The shell MUST request Delegations by typed CID and MUST recompute and compare each returned token CID before using it. Resolution MUST remain caller-owned and bounded.

#### Scenario: Store returns the requested token

- GIVEN a store returns canonical bytes whose CID equals the requested proof CID
- WHEN proof loading runs
- THEN the verified Delegation MAY enter chain composition

#### Scenario: Store substitutes another valid token

- GIVEN a store returns a valid signed Delegation with a different CID
- WHEN proof loading runs
- THEN loading MUST fail with a deterministic binding error
- AND the substituted Delegation MUST NOT enter authority evaluation

### Requirement: Invocation admission binds all authority facts

r[ucan.v1_authorization.invocation] UCAN MUST admit an Invocation only when its verified wire envelope, issuer, subject, executor, command, arguments, proof chain, policies, time, revocation observations, and configured limits all pass.

#### Scenario: Valid Invocation is admitted

- GIVEN a verified Invocation and ordered verified Delegation chain establish the exact requested authority
- WHEN the pure admission core evaluates complete explicit facts
- THEN it MUST produce a prospective authorization plan for that exact Invocation

#### Scenario: One required fact fails

- GIVEN any required signature, chain, subject, executor, command, policy, time, revocation, or limit fact fails
- WHEN admission runs
- THEN it MUST deny with a stable reason
- AND it MUST NOT produce a prospective authorization plan

### Requirement: Replay is the final consuming commit

r[ucan.v1_authorization.replay] The shell MUST complete all fallible wire, proof, authority, policy, consumer-preflight, revocation, allocation, and receipt preparation before it calls caller-owned replay admission exactly once.

#### Scenario: Preflight denies

- GIVEN any preflight stage denies or fails
- WHEN Invocation verification returns
- THEN replay admission MUST receive zero calls

#### Scenario: Replay accepts

- GIVEN all preflight work passes and replay admission accepts
- WHEN the shell constructs live authorization
- THEN only infallible moves MUST occur after replay

### Requirement: Live authorization is not forgeable from evidence

r[ucan.v1_authorization.live] Successful state-consuming admission MUST return a private-construction, non-clone, non-serde live authorization value borrowing the exact Invocation request.

#### Scenario: Persisted receipt is replayed

- GIVEN a caller stores an allowed receipt or copies verified facts
- WHEN it tries to recreate live authorization
- THEN the public API MUST provide no constructor or deserializer that recreates it

### Requirement: Authorization tests cover failure classes

r[ucan.v1_authorization.tests] The focused suite MUST admit valid direct and delegated Invocations and MUST reject command, policy, chain, issuer, subject, executor, time, proof-store, revocation, replay, limit, and backend failures.

#### Scenario: Negative matrix runs

- GIVEN one fixture for each required failure class
- WHEN the focused suite runs
- THEN every fixture MUST fail closed with its expected stable reason
- AND no denied fixture MUST expose live authorization

### Requirement: Authorization receipts are redacted evidence

r[ucan.v1_authorization.receipt] Every Invocation outcome MUST produce deterministic BLAKE3-bound evidence for the exact protocol profile, implementation and specification cohort, public token identities, ordered proof identities, decision classes, limits, reason, and non-claims. It MUST omit raw credentials, proofs, arguments, metadata, keys, and policy payloads.

#### Scenario: Receipt is serialized

- GIVEN evaluation handled bearer and request data
- WHEN the receipt is serialized
- THEN secret and payload data MUST be absent
- AND the receipt MUST remain evidence rather than authority

### Requirement: Authorization claims retain caller boundaries

r[ucan.v1_authorization.docs] Documentation MUST state that authorization depends on supplied key, resource, executor, time, revocation, replay, and backend facts. Passing admission MUST NOT prove transport security, global freshness, durable replay storage, external resource ownership, policy completeness, or effect correctness.

#### Scenario: Operator reads an allow claim

- GIVEN a live authorization result exists
- WHEN the operator reads the supported claim
- THEN the claim MUST apply only to the exact Invocation and explicit observations
- AND retained caller authority MUST remain visible

### Requirement: Authorization validation is complete

r[ucan.v1_authorization.validation] The change MUST pass positive and negative fixtures, policy properties, no-std checks, workspace tests, strict lint gates, Cairn gates, and the repository Nix check before archive.

#### Scenario: Validation rail completes

- GIVEN implementation, fixtures, reports, and documentation are current
- WHEN the full validation rail runs
- THEN every required check MUST pass or record one exact bounded blocker
