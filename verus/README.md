# Verus specifications

This directory contains formal [Verus](https://verus-lang.github.io/verus/guide/) specifications for UCAN.

Each `*_spec.rs` file defines invariants, preconditions, and postconditions. The Verus verifier checks these properties.

## Run verification

```bash
# If verus is in your devShell:
verus verus/example_spec.rs
```
