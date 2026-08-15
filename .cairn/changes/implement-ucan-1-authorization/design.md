## Context

The wire profile can establish typed signed Delegation and Invocation envelopes. Final authority evaluation remains a separate domain problem.

The final Delegation specification defines one capability per Delegation through `sub`, `cmd`, and `pol`. Commands use slash-path hierarchy. Policies are trees over Invocation arguments. Invocation carries an ordered array of Delegation CIDs from root to invoker and must bind an exact command, arguments, subject, executor, nonce, and expiry.

## Decisions

### Decision: Keep authority semantics in the pure core

**Choice:** Add pure deterministic components for:

- ordered proof-chain composition;
- subject and Powerline substitution;
- principal alignment without DID fragments;
- command parsing and prefix attenuation by complete slash segments;
- time-range admission over explicit evaluation time and clock-skew policy;
- policy parsing, selector resolution, and predicate evaluation;
- exact Invocation admission over verified Delegations and explicit external observations.

The core returns typed allow or deny results, selected proof facts, diagnostics, and an effect-free authorization plan.

**Rationale:** These rules define UCAN authority and must not depend on storage, networks, clocks, or frameworks.

### Decision: Use caller-owned proof resolution

**Choice:** The std shell exposes a narrow CID-addressed Delegation store port. It requests each proof in Invocation order, enforces count and byte limits, recalculates the returned token's CID, rejects substitution, verifies the wire envelope, and then passes plain verified values into the core.

**Rationale:** Resolution is an external capability. CID binding and safe orchestration remain library obligations.

### Decision: Preserve strict linear proof order

**Choice:** Invocation proof arrays must start with root authority and end at the Invoker. Every adjacent audience and issuer must align after the specified DID-fragment treatment. Duplicate CIDs and cycles fail closed.

Alternative valid authority paths are evaluated as separate candidate chains. One invalid path does not erase another supplied valid path, but the API must never silently reorder or splice paths.

**Rationale:** The final Invocation proof field has sequence meaning.

### Decision: Implement command hierarchy independently

**Choice:** Add a final-profile `Command` type. Commands begin with `/`, use lowercase path syntax as required by the normative profile, have no trailing slash except `/`, and compare by complete segments.

A shorter Delegation command proves the same command or a descendant. It does not prove a lexical prefix with a different segment.

The compact ability wildcard bridge remains unchanged and is not reused.

**Rationale:** Final commands and compact abilities have incompatible containment rules.

### Decision: Give policy one narrow component

**Choice:** Add a bounded policy AST and evaluator for the final Delegation language. It supports only the specified equality, inequality, `like`, connective, quantifier, and selector forms.

Parsing rejects unknown operators and unsupported jq features. Evaluation over type mismatch or unresolved selection returns the specified false or null behavior, not a panic. Nesting, statement count, selector length, collection size, and glob work are bounded.

**Rationale:** Policy is deterministic domain meaning with substantial adversarial input risk. It needs independent tests and ownership.

### Decision: Keep external semantic conditions outside policy

**Choice:** Resource ownership, day-of-week checks, mutable external facts, and command-specific effect safety remain consumer-owned. The core receives any required admitted semantic facts explicitly and does not call external services.

**Rationale:** The normative policy language cannot prove dynamic external truth.

### Decision: Separate preflight from state-consuming replay

**Choice:** Wire verification, proof resolution, authority composition, policy evaluation, executor checks, limits, and all fallible allocations occur before replay admission. The shell then calls a caller-owned Invocation replay port once as the final consuming commit.

After replay accepts, only infallible moves construct a private, non-clone, non-serde live authorization value borrowing the exact Invocation request.

**Rationale:** A denied request must not spend replay state, and replay success must not be followed by a fallible authority step.

### Decision: Treat revocation as supplied observation in this slice

**Choice:** Before final Revocation-token support exists, callers supply a revocation observation for each proof CID under a fail-closed port. Unknown or unavailable observations deny.

This change does not parse or authorize the separate UCAN Revocation protocol.

**Rationale:** Invocation validation must account for revocation without expanding this change into another token protocol.

### Decision: Emit redacted bounded evidence

**Choice:** Receipts bind the protocol profile, implementation and specification cohort, Invocation CID, ordered proof CID identities, command and policy result identities, executor decision, revocation and replay disposition classes, reason, limits, and non-claims.

Receipts contain no raw token, proof, argument, metadata, key, policy payload, or private subject text unless a separate public-data contract admits it. Persisted evidence cannot recreate the live authorization value.

**Rationale:** Evidence must remain useful without becoming a bearer capability or leaking request data.

## Flow

```text
bounded Invocation bytes
  -> wire decoder and signature adapter
  -> ordered CID proof-store adapter
  -> verified Delegation values
  -> pure chain + command + policy authority core
  -> prospective authorization plan
  -> Basalt or consumer policy preflight, when configured
  -> caller-owned revocation observations
  -> one caller-owned replay commit
  -> live borrowed authorization + redacted receipt
```

## Risks and trade-offs

- The policy language is large and parser-sensitive. Property, mutation, and differential tests are required, but differential agreement does not override the specification.
- Powerline is broad authority. Root Powerline and invalid substitution must fail exactly as specified.
- Multiple proof paths can increase work. All candidate count, depth, bytes, and policy effort must be bounded.
- A passing authorization result still depends on supplied key, resource, revocation, replay, clock, and executor facts.
