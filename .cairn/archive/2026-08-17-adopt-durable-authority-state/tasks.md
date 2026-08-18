## Phase 1: Source and boundary

- [x] [serial] [task:source] Pin both separate cores to the canonical Radicle adapter and exact reviewed object with no fallback. r[ucan.durable_authority.source]
- [x] [serial] [task:map] [after:source] Record the exact UCAN-to-component identity, error, authority, and non-claim mapping. r[ucan.durable_authority.claims]

## Phase 2: Adapters

- [x] [serial] [task:replay] [after:map] Implement the shell-owned holder replay adapter with complete explicit scope and compare-and-swap reservation. r[ucan.durable_authority.replay_adapter]
- [x] [parallel] [task:revocation] [after:map] Implement the shell-owned current revocation adapter over caller-supplied source, time, generation, and storage. r[ucan.durable_authority.revocation_adapter]
- [x] [serial] [task:ordering] [after:replay] Prove replay remains the final UCAN state-consuming boundary and that denied paths do not mutate state. r[ucan.durable_authority.ordering]

## Phase 3: Verification and closeout

- [x] [parallel] [task:negative] [after:replay] [after:revocation] Add positive and negative tests for first use, duplicates, conflicts, stale state, incomplete views, and backend failures. r[ucan.durable_authority.validation]
- [x] [serial] [task:gates] [after:ordering] [after:negative] Run focused baselines again, Cargo source checks, formatting, Clippy, Cairn gates, traceability, and `nix flake check -L`. r[ucan.durable_authority.validation]
- [x] [serial] [task:archive] [after:gates] Sync, archive, push the verified branch, fast-forward `main`, and verify `origin/main`. r[ucan.durable_authority.lifecycle]
