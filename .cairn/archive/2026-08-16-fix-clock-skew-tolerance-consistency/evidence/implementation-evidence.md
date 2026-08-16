# Fix Clock-Skew Tolerance Consistency: Implementation Evidence

Date: 2026-08-15

## Implementation

- `src/verified.rs`:
  - `DEFAULT_CLOCK_SKEW_SECONDS` is now `pub const` (value 60, unchanged).
  - `validate_token_envelope` accepts an explicit `tolerance_seconds` so the
    envelope gate no longer owns the default independently.
- `src/token.rs`:
  - `VerificationLimits` carries `clock_skew_tolerance_seconds`, defaulting to
    the documented 60-second value in `new()` and `Default`.
  - `VerificationLimits::strict()` and
    `with_clock_skew_tolerance_seconds(seconds)` expose the zero-tolerance
    opt-in surface without changing the default.
  - `verify_live_dag_proof_transcript` now uses
    `limits.clock_skew_tolerance_seconds()` instead of the hardcoded zero.
  - `validate_envelope_for_token` threads the same limits-derived tolerance
    into the envelope gate, so both gates use one value for one verification.
  - `ucan-core` and vendored `verified-logic` were not modified.

## Boundary fixtures

- `clock_skew_default_grace_admits_documented_boundaries` (positive):
  `nbf-1`, `nbf`, `exp`, and `exp+60` are admitted under the default surface.
- `clock_skew_out_of_grace_reports_temporal_error` (negative): before `nbf-60`
  and at `exp+61` are rejected as `TokenError::Temporal` (honest class, not
  `ProofChain`).
- `clock_skew_strict_opt_in_rejects_in_grace_token` (negative): the strict
  opt-in rejects an in-grace time as `TokenError::Temporal` while the default
  surface admits the same time.
- `examples/pentest_chain.rs` section A is now a regression matrix: it prints
  and asserts the AUTH/TEMPORAL outcome at every declared boundary plus the
  strict-opt-in rejection.

## Checks

- Baseline before edits: `cargo test -p ucan --lib` -> 194 passed, 0 failed.
- After edits: `cargo test -p ucan --lib` -> 197 passed, 0 failed.
- `cargo run --example pentest_chain` -> exit 0; the boundary matrix prints
  AUTH at 999/1000/1200/1260, TEMPORAL at 939/1261, and TEMPORAL under strict
  at 1250.
- `cargo clippy -p ucan --lib --tests -- -D warnings` -> exit 0.
- `cargo clippy -p ucan --example pentest_chain -- -D warnings` -> exit 0.
- `cargo clippy -p ucan --example replay_baseline -- -D warnings` -> exit 0.
- The changed source files are `rustfmt` clean (pre-existing `examples/pentest_*.rs`
  committed drift is out of scope and carries local fixes in the primary worktree).

## Non-claims

The default tolerance value and the strict valid window are unchanged. No
token that previously verified becomes rejected; only in-grace tokens are
admitted and boundary failures are reclassified to the temporal error class.
No equivalence, crypto, or release-readiness claim is added.
