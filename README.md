# ucan

## Architecture

- `crates/ucan-core`: `#![no_std]` functional core. Keep parsing, structural validation, and other deterministic UCAN logic here.
- `ucan` (repo root): `std` shell. Keep file I/O, process integration, networking, clocks, crypto, and other side effects here.
- `../verified-logic`: sibling verified library used by the `std` shell for UCAN ability subsumption, attenuation checks, token-time validation, Ed25519 signing/verification, and `did:key` encoding.

The boundary is FCIS-first: the shell gathers bytes and environment state, then hands plain strings and values into `ucan-core`. When a primitive needs verified semantics, the shell bridges validated core values into `verified-logic` instead of reimplementing the logic locally.

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
