## Goals

- Bind every store-resolved proof token to its requested BLAKE3 reference.
- Reject substitution with a deterministic typed error.
- Keep the built-in `ProofCollection` behavior unchanged.

## Package boundary

The change is shell-local (`src/token.rs`, `direct_proofs`). `ucan-core` and
the vendored verified-logic are untouched.

## Binding contract

1. The shell records the requested `ProofReference` for each proof in the
   child claim.
2. After `ProofStore::resolve_proof` returns a compact token, the shell
   recomputes `proof_reference_for_token(&returned)`.
3. The shell rejects the resolution when the computed reference differs from
   the requested reference.
4. The typed error names the requested reference and the returned digest.

## Store compatibility

The binding is enforced at resolution time. The built-in `ProofCollection`
already selects tokens by digest equality, so it satisfies the binding by
construction. Document the obligation on the trait so custom stores agree.

## Verification plan

- Keep the audited-revision `cargo test --workspace` baseline green.
- Add positive cases for correct store resolution.
- Add negative cases with a store that returns a different valid token,
  asserting the typed mismatch error.
- Add cases that keep `ProofCollection` behavior unchanged.
- Run package, workspace, Clippy, Cairn, and Nix checks.
