# Tasks: Fix Caveat Payload Heap Leak

## Leak elimination

- [x] [serial] Establish the baseline: run `cargo test --workspace` and record the memory regression harness output at the audited revision. r[ucan.leak.verify]
- [x] [serial] Replace the permanent caveat-input retention in `CapabilitySet::new` with owned per-call lifetime resolution inside the calling frame. r[ucan.leak.verify]
- [x] [serial] Remove the permanent leak from the issuance self-check path. r[ucan.leak.issue]

## Regression gate

- [x] [parallel] Add a memory regression test that reproduces the caveated-token verification with a fixed retained-memory bound. r[ucan.leak.regression]
- [x] [parallel] Add positive and negative lifetime tests: caveated and caveat-free tokens, single and multi-parent proof traversal. r[ucan.leak.verify]
- [x] [parallel] Verify `ucan-core` public APIs compile unchanged for downstream consumers. r[ucan.leak.core]

## Closeout

- [x] [serial] Run package, workspace, Clippy, Cairn, and Nix checks. r[ucan.leak.verify]
- [x] [serial] Record the memory regression evidence and the measured per-call retention. r[ucan.leak.regression]
