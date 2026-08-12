## Gate unification

- [ ] [serial] Replace the hardcoded zero tolerance in `verify_live_dag_proof_transcript` with the shared shell tolerance. r[ucan.skew.consistent]
- [ ] [serial] Route temporal boundary rejection through the temporal error class. r[ucan.skew.honest]
- [ ] [serial] Add the documented strict-opt-in surface with zero tolerance. r[ucan.skew.strict]

## Boundary coverage

- [ ] [parallel] Add positive fixtures at `nbf-1`, `nbf`, `exp`, and `exp+60`. r[ucan.skew.coverage]
- [ ] [parallel] Add negative fixtures at `exp+61` and before `nbf-60`. r[ucan.skew.coverage]
- [ ] [parallel] Add fixtures that verify the strict-opt-in surface rejects in-grace tokens. r[ucan.skew.strict]
- [ ] [parallel] Convert the `examples/pentest_chain.rs` time sweep into a regression matrix. r[ucan.skew.coverage]

## Closeout

- [ ] [serial] Run package, workspace, Clippy, Cairn, and Nix checks. r[ucan.skew.coverage]
- [ ] [serial] Record the boundary matrix evidence and the error-class mapping. r[ucan.skew.honest]
