## Implementation

- [x] [serial] Require exact `k256 0.14.0` in the Nostr adapter and convert verifying-key bytes to `FieldBytes`, matching Basalt `1c142e2` up to UCAN formatting. r[track_dependency_posture.k256_advisory_closure]
- [x] [serial] Update `Cargo.lock` with `cargo update -p k256 --precise 0.14.0` and confirm no `crypto-bigint` below `0.7.6` remains. r[track_dependency_posture.k256_advisory_closure]
- [x] [serial] Rename the Nostr implementation-identity input to `k256@0.14.0` and recompute the identity from the adapter. r[track_dependency_posture.k256_advisory_closure]
- [x] [serial] Extend the posture checker and posture tests with the locked `k256` and `crypto-bigint` closure and the identity label, including drifted manifest, identity, and lock cases. r[track_dependency_posture.k256_advisory_closure]
- [x] [serial] Re-run the advisory audit and update the posture record, the support report, and the Nostr dependency table. r[track_dependency_posture.k256_advisory_closure]
- [x] [serial] Run all 19 published BIP-340 verification vectors against the adapter on `k256 0.14.0`, asserting each published result and typed rejection. r[track_dependency_posture.k256_advisory_closure]
- [x] [serial] Rewrite the posture record and support report with the per-advisory status from the 2026-11-22 audit. r[track_dependency_posture.k256_advisory_closure]

## Verification

- [x] [serial] Run workspace tests, the `issue_and_verify` example, scoped formatting, strict Clippy, the posture checker, and Cairn validation; record the evidence. r[track_dependency_posture.k256_advisory_closure]
- [x] [serial] Run the `nix develop` and `nix flake check` rails at integration, then sync the accepted spec and archive the change. r[track_dependency_posture.k256_advisory_closure]
