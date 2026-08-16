# Fix Caveat Payload Heap Leak: Implementation Evidence

Date: 2026-08-16

## Implementation

- `src/token.rs`:
  - `CapabilitySet::new` no longer calls the leaked-input helper. It builds
    the caveat `CaveatInput` holders and the `CapabilityInput` values inside a
    block whose lifetime covers the core `Claims::from_input` validation, so
    every temporary is reclaimed when the block ends. The `capability_inputs`
    helper (with its `Vec::leak()` permanent retention) was removed.
  - The same code path served verification (`claims_capability_set`) and any
    issuance self-check call, so both entry surfaces are covered by one
    lifetime fix.
  - `ucan-core` and vendored `verified-logic` were not modified. All
    `CaveatInput`/`CapabilityInput` APIs remain borrowed.

## Regression gate

- A test-only counting allocator (`CountingAllocator`) installs itself as the
  test-binary global allocator and tracks exact live bytes.
- `assert_repeated_verification_retains_bounded_memory` measures live-byte
  growth across a fixed repetition count and fails when growth exceeds 64 KiB.
- `repeated_caveated_verification_retains_bounded_memory` (positive): 4,096
  verifications of a token carrying a 4,096-byte caveat payload. A per-call
  payload or input-box leak would exceed the bound by orders of magnitude.
- `repeated_caveat_free_verification_retains_bounded_memory` (control).
- `repeated_single_parent_traversal_retains_bounded_memory` and
  `repeated_multi_parent_traversal_retains_bounded_memory`: live proof
  traversal over caveated parents (caveat preservation satisfied by a shared
  caveat identifier).
- `repeated_caveated_issuance_retains_bounded_memory`: 1,024 caveated
  issuances via `issue_token_with_signer` with bounded retained memory.

## Checks

- Baseline before edits: `cargo test -p ucan --lib` -> 197 passed, 0 failed.
- After edits: `cargo test -p ucan --lib` -> 202 passed, 0 failed (five
  regression tests added).
- `cargo clippy -p ucan --lib --tests -- -D warnings` -> exit 0.
- `cargo fmt --check` -> whole crate clean. This change also repairs
  pre-existing committed formatting drift in `src/token.rs` and the
  `examples/pentest_*.rs` files that was introduced or surfaced before this
  change; the committed tree is now rustfmt-clean.

## Non-claims

Token bytes, receipts, formats, and authorization outcomes are unchanged.
The measured bound is a regression gate, not a proof of peak-memory
optimality. No JSON, crypto, or release-readiness claim is added.
