## Goals

- Honor the documented clock-skew tolerance at every verification gate.
- Report temporal boundary failures honestly.
- Keep a strict opt-in surface for zero-tolerance callers.

## Package boundary

The change is shell-local (`src/token.rs`). The vendored verified-logic
traversal predicate already accepts a tolerance field on its target; the shell
currently hardcodes 0. The shell passes one consistent value to both gates.

## Tolerance contract

- Default tolerance: 60 seconds, unchanged.
- The envelope gate and the DAG traversal target receive the same value for the
  same verification.
- Strict callers select a documented zero-tolerance context.

## Error classification

Temporal boundary rejection is mapped to `TokenError::Temporal` or the
equivalent explicit temporal failure. Proof-graph errors remain reserved for
structure, linkage, attenuation, and budget failures.

## Verification plan

- Extend `examples/pentest_chain.rs` boundary sweep into the fixture matrix.
- Add positive fixtures at `nbf-1` and `exp+60`.
- Add negative fixtures at `exp+61` and before `nbf-60`.
- Add the strict-opt-in fixture set.
- Run the focused package, workspace, Clippy, Cairn, and Nix checks.
