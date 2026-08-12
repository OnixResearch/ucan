## Goals

- Stop permanent heap growth in verification and issuance.
- Preserve token bytes, semantics, and the `ucan-core` borrowed-input contract.
- Give the fix a measurable regression gate.

## Package boundary

The change is shell-local (`src/token.rs`). `ucan-core` receives the same
borrowed-input APIs and stays `#![no_std]`.

## Lifetime strategy

Today the shell calls `Box::leak` / `payload.leak` to obtain references that
outlive the decoded token. Replace that with owned lifetime resolution:

1. Collect caveat inputs in a per-call owned structure that lives exactly as
   long as core claim construction.
2. Borrow from that owned structure instead of leaking.
3. Route the owned structure through internal helpers so `ClaimsInput` never
   outlives the borrowed references.

If the borrow checker makes a fully owned pass impossible within this package,
fall back to a minimal reference-counted ownership wrapper inside the shell.
The fallback MUST reclaim all per-call caveat buffers when verification
returns.

## Verification plan

- Keep `cargo test --workspace` green at the audited revision before edits
  as the baseline.
- Add `examples/pentest_memory.rs` behavior as an internal regression test
  with a fixed retained-memory bound.
- Run `cargo test`, Clippy, and the repo Nix checks after the change.

## Measured baseline

Audited revision (pre-merge), leak scales with attacker-controlled payload:

- 260-byte payload: ~461 bytes per verification.
- 4,096-byte payload: ~4,352 bytes per verification.

Merged mainline (post-upstream bounded-token refactor), 2,048-byte payload,
50,000 iterations: ~84 bytes per verification (4.2 MiB growth). The
payload-proportional component is gone; a fixed residual remains. The residual
comes from `capability_inputs` calling `caveats.leak()` on the
`CapabilitySet::new` validation path (shell-only, unchanged upstream).

The regression bound uses one of these scales and tolerates allocator noise.
