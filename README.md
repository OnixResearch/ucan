# ucan

## Architecture

- `crates/ucan-core`: `#![no_std]` functional core. Keep parsing, validation, and other deterministic UCAN logic here.
- `ucan` (repo root): `std` shell. Keep file I/O, process integration, networking, clocks, and other side effects here.

The boundary is FCIS-first: the shell gathers bytes and environment state, then hands plain strings and values into `ucan-core`.

## Development

```bash
nix develop -c cargo test --workspace
nix develop -c cargo fmt --check
nix develop -c cargo clippy --workspace --all-targets -- -D warnings
nix flake check
```

## Verification

```bash
verus verus/example_spec.rs
```
