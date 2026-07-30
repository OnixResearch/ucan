# Tasks: Harden compact-token secret ownership

## Audit and ownership core

- [ ] [serial] Record all compact-token, proof-token, decoded-byte, signing-input, signature, error, debug, and clone allocation paths. r[ucan.compact_token_secret_ownership.audit]
- [ ] [serial] Add non-cloneable zeroizing owners and exact-capacity construction primitives. r[ucan.compact_token_secret_ownership.owners]
- [ ] [serial] Remove secret formatting, serde, cloning, and ordinary reconstruction surfaces. r[ucan.compact_token_secret_ownership.public_surface]

## Borrowed verification and traversal

- [ ] [serial] Bound and verify borrowed leaf input before token-derived allocation or hashing. r[ucan.compact_token_secret_ownership.borrowed_verification]
- [ ] [serial] Replace proof-store token cloning with borrowed or zeroizing proof-token resolution. r[ucan.compact_token_secret_ownership.proof_traversal]
- [ ] [serial] Expose only complete-input fixed-width BLAKE3 proof references after bounds pass. r[ucan.compact_token_secret_ownership.public_evidence]

## Codec and issuance

- [ ] [serial] Decode base64 into exact non-growing zeroizing buffers and borrow JSON fields. r[ucan.compact_token_secret_ownership.codec]
- [ ] [serial] Add the serde escape guard and pin the reviewed dependency behavior. r[ucan.compact_token_secret_ownership.codec]
- [ ] [serial] Build JSON, base64 segments, signing input, signatures, and final compact output without bearer-bearing reallocation. r[ucan.compact_token_secret_ownership.issuance]

## Tests and closeout

- [ ] [parallel] Add positive borrowed verification and proof-chain tests. r[ucan.compact_token_secret_ownership.tests]
- [ ] [parallel] Add malformed, oversized, cleanup, exact-capacity, formatting, serde, clone, and compatibility negative tests. r[ucan.compact_token_secret_ownership.tests]
- [ ] [serial] Update examples and documentation without widening resolver, proof, revocation, replay, time, limit, or authority claims. r[ucan.compact_token_secret_ownership.compatibility]
- [ ] [serial] Run focused, workspace, format, Clippy, readiness, Nix, and Cairn validation rails. r[ucan.compact_token_secret_ownership.final_validation]
