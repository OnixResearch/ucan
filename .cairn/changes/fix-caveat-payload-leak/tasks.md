## Leak elimination

- [ ] [serial] Establish the baseline: run `cargo test --workspace` and record the memory regression harness output at the audited revision. r[ucan.leak.verify]
- [ ] [serial] Replace `Box::leak` and `payload.leak` in `decoded_caveat_inputs`, `decoded_capability_inputs`, and `capability_inputs` with owned per-call lifetime resolution. r[ucan.leak.verify]
- [ ] [serial] Remove the permanent leak from the issuance self-check path. r[ucan.leak.issue]

## Regression gate

- [ ] [parallel] Add a memory regression test that reproduces `examples/pentest_memory.rs` with a fixed retained-memory bound. r[ucan.leak.regression]
- [ ] [parallel] Add positive and negative lifetime tests: caveated and caveat-free tokens, single and multi-parent proof traversal. r[ucan.leak.verify]
- [ ] [parallel] Verify `ucan-core` public APIs compile unchanged for downstream consumers. r[ucan.leak.core]

## Closeout

- [ ] [serial] Run package, workspace, Clippy, Cairn, and Nix checks. r[ucan.leak.verify]
- [ ] [serial] Record the memory regression evidence and the measured per-call retention. r[ucan.leak.regression]
