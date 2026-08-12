## Reference binding

- [ ] [serial] Recompute and compare the returned token digest against the requested reference in `direct_proofs`. r[ucan.pstore.matches]
- [ ] [serial] Add a typed bound-reference mismatch error that names both digests. r[ucan.pstore.error]
- [ ] [serial] Document the reference-binding obligation and enforcement on the `ProofStore` trait. r[ucan.pstore.docs]

## Store coverage

- [ ] [parallel] Add positive cases for correct store resolution through a custom store. r[ucan.pstore.matches]
- [ ] [parallel] Add negative cases where the store substitutes a different valid token. r[ucan.pstore.error]
- [ ] [parallel] Add compatibility cases that keep the built-in `ProofCollection` behavior unchanged. r[ucan.pstore.compat]

## Closeout

- [ ] [serial] Run package, workspace, Clippy, Cairn, and Nix checks. r[ucan.pstore.matches]
- [ ] [serial] Record the mismatch fixture evidence and the trait contract revision. r[ucan.pstore.docs]
