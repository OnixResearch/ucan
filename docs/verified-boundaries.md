# Verified UCAN boundary audit

This document records the current verified-logic bridge boundaries after the UCAN audit OpenSpec drain. "Verified" means routed through the vendored `verified-logic` primitives; ordinary Rust shell orchestration remains tested and bounded, but not formally verified in this crate.

## Newly exposed exact bridge seams

- `typed_caveat_is_satisfied` and `typed_caveat_set_is_satisfied` expose the vendored finite typed caveat predicates for `VerifiedWebOfTrustCaveat::{TimeBound, RateLimit}` with explicit `VerifiedWebOfTrustCaveatContext`.
- `web_of_trust_attestation_payload_bytes`, `web_of_trust_attestation_signature_is_valid`, and `web_of_trust_attestation_is_active_at` expose deterministic public WOT attestation evidence helpers.
- `web_of_trust_revocation_payload_bytes`, `web_of_trust_revocation_signature_is_valid`, `web_of_trust_revocation_matches_attestation`, and `web_of_trust_revocation_is_effective_at` expose deterministic public WOT revocation evidence helpers.
- `web_of_trust_threshold_accepts` exposes the finite WOT threshold policy predicate over caller-supplied roots, attestations, revocations, subject digest, threshold, depth, and explicit time.
- `proof_traversal_transcript_is_valid` exposes the vendored finite proof traversal transcript predicate over already-resolved entries, visited proof-reference bytes, explicit budgets, target operation, time, and supplied revocation facts.
- `proof_traversal_dag_transcript_is_valid` exposes the vendored finite multi-parent proof DAG transcript predicate over already-resolved entries, topological parent indices, visited proof-reference bytes, explicit budgets, target operation, time, and supplied revocation facts.

These helpers do not fetch evidence, resolve DIDs, sign, persist data, consult registries, provide replay protection, install default caveat policies, or read ambient clocks.

## Shell-local boundaries retained intentionally

- Compact-token splitting, base64url decoding, JSON serde, signing-input construction, BLAKE3 proof-reference derivation, and Ed25519 runtime crypto remain trusted runtime boundaries. The shell has focused regressions for malformed shape, invalid base64/JSON, signing-input stability, proof-reference stability, and redacted output, but no vendored primitive currently replaces this codec pipeline.
- Live recursive proof traversal remains ordinary Rust orchestration. The current shell preserves caller-injected `KeyResolver`, `ProofStore`, and `RevocationChecker`, bounded proof depth/count/input bytes, cycle rejection, fail-closed backend errors, proof-link verification through `proof_link_is_valid`, proof-depth admission through `proof_depth_within_budget`, and structural/helper bridges for callers with already-resolved finite chains, linear traversal transcripts, or topologically ordered multi-parent DAG transcripts. The verified traversal transcript bridge checks finite resolved-data consistency, and the live shell emits/checks this transcript for no-proof tokens plus single-parent linear proof chains whose resource, caveat-preservation, and exact or wildcard-segment ability attenuation are representable by the vendored predicate. It still does not model the live resolver/proof-store state machine, backend freshness, compact-token parsing, signature byte verification, proof-reference hashing, revocation backend correctness, or recursive runtime orchestration outside caller/shell-supplied transcripts.
- Opaque shell caveat preservation remains shell-local. Capability containment routes through verified `VerifiedCapability`, but the exact rule that a child capability must preserve each parent caveat payload for the same parent capability has no exact vendored primitive because shell caveats are opaque bytes and application semantics are caller-defined.

## Implementation guidance

Future changes should only claim a shell behavior is verified when the public helper or internal path delegates the exact same predicate to `vendor/verified-logic`. If the available vendored primitive only covers a lower-level or typed subset, document it as an opt-in bridge and keep caller-injected shell boundaries explicit.
