## Documentation

- [ ] [serial] Document the admission-key definition and indistinguishability behavior in the invocation reference. r[ucan.replay.identity]
- [ ] [serial] Document the accept-everything default posture and the store requirement. r[ucan.replay.posture]
- [ ] [serial] Update the README replay section to match the invocation reference. r[ucan.replay.posture]

## Baseline example

- [ ] [parallel] Add `examples/replay_baseline.rs` with a store-backed exactly-once admission hook. r[ucan.replay.example]
- [ ] [parallel] Add positive and negative example behavior: first admission allowed, second rejected as duplicate. r[ucan.replay.example]
- [ ] [parallel] Document the durable-storage extension point in the example. r[ucan.replay.example]

## Closeout

- [ ] [serial] Verify existing invocation and replay tests pass unchanged. r[ucan.replay.stable]
- [ ] [serial] Run package, workspace, Clippy, Cairn, and Nix checks. r[ucan.replay.example]
