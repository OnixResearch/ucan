# Bind ProofStore Result to Reference: Implementation Evidence

Date: 2026-08-15

## Implementation

- `src/token.rs`:
  - Added `ProofStoreError::ReferenceMismatch { expected, actual }` with a
    deterministic `Display` that names both digests and is distinct from
    missing, stale, malformed, and backend failures.
  - Added `bind_proof_to_reference`, called from `verify_parent_tokens` after
    the compact-token size enforcement and before delegation evaluation. It
    recomputes the bounded-token BLAKE3 digest and rejects a mismatch with
    `TokenError::ProofStore` referencing the typed error.
  - Documented the reference-binding contract and enforcement boundary on the
    `ProofStore` trait.
  - `ucan-core` and vendored `verified-logic` were not modified.

## Tests (positive and negative)

- `substituting_proof_store_is_rejected_as_reference_mismatch`: a custom store
  returns a different valid token; verification fails with
  `ProofStoreError::ReferenceMismatch`; the error names the requested parent
  reference and the returned child digest.
- `reference_respecting_store_verifies_child_chain`: a custom store that
  returns the token matching the requested reference preserves successful
  verification.
- `reject_cycle_contains_repeated_proof_reference`: direct trail-detection
  unit coverage retained (the previous cycle test relied on a mismatching
  store, which is now correctly classified as a substitution).
- Existing proof-store fixtures remain green, including
  `resolved_proof_size_limit_precedes_parsing` (binding follows the size
  limit) and all `ProofCollection` delegation-chain compatibility tests.

## Checks

- Baseline before edits: `cargo test -p ucan --lib` -> 192 passed, 0 failed.
- After edits: `cargo test -p ucan --lib` -> 194 passed, 0 failed.
- `cargo test --workspace --lib` -> all members' lib tests pass (the Hegel
  `prop_capability_validation` integration suite is long-running and
  pre-existing; it was excluded from the quick closeout and is unaffected by
  this shell-local change).
- `cargo clippy -p ucan --lib --tests -- -D warnings` -> exit 0.
- `cairn gate proposal|design|tasks bind-proof-store-result-to-reference` ->
  all exit 0 with no issues.

## Non-claims

No proof semantics, reference scheme, `ucan-core` API, or authorization
outcome changed. The binding is shell-enforced defense in depth on the
documented caller-owned `ProofStore` boundary.
