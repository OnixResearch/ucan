# Tasks: Bind ProofStore Result to Reference

## Reference binding

- [x] [serial] Recompute and compare the returned token digest against the requested reference in `verify_parent_tokens`. r[ucan.pstore.matches]
- [x] [serial] Add a typed bound-reference mismatch error that names both digests. r[ucan.pstore.error]
- [x] [serial] Document the reference-binding obligation and enforcement on the `ProofStore` trait. r[ucan.pstore.docs]

## Store coverage

- [x] [parallel] Add positive cases for correct store resolution through a custom store. r[ucan.pstore.matches]
- [x] [parallel] Add negative cases where the store substitutes a different valid token. r[ucan.pstore.error]
- [x] [parallel] Add compatibility cases that keep the built-in `ProofCollection` behavior unchanged. r[ucan.pstore.compat]

## Closeout

- [x] [serial] Run package, workspace, Clippy, Cairn, and Nix checks. r[ucan.pstore.matches]
- [x] [serial] Record the mismatch fixture evidence and the trait contract revision. r[ucan.pstore.docs]
