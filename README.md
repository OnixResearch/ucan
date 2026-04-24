# ucan

## Architecture

- `crates/ucan-core`: `#![no_std]` functional core. Keep parsing, structural validation, and other deterministic UCAN logic here.
- `ucan` (repo root): `std` shell. Keep file I/O, process integration, networking, clocks, crypto, and other side effects here.
- `vendor/verified-logic`: vendored snapshot of the verified library used by the `std` shell for UCAN ability subsumption, attenuation checks, token-time validation, Ed25519 signing/verification, and `did:key` encoding.

The boundary is FCIS-first: the shell gathers bytes and environment state, then hands plain strings and values into `ucan-core`. When a primitive needs verified semantics, the shell bridges validated core values into `verified-logic` instead of reimplementing the logic locally.

## Development

```bash
nix develop -c cargo test --workspace
nix develop -c cargo fmt --manifest-path Cargo.toml -p ucan -p ucan-core --check
nix develop -c cargo clippy --manifest-path Cargo.toml -p ucan -p ucan-core --all-targets --no-deps -- -D warnings
nix flake check
```

`vendor/verified-logic` is a checked-in upstream snapshot. Keep it byte-for-byte aligned with upstream and exclude it from this repo's local `fmt`/`clippy` policy; refresh it with the sync script instead of reformatting or relinting it in place.

Refresh the vendored `verified-logic` snapshot from the sibling source repo with:

```bash
./scripts/sync-verified-logic.sh
```

That script imports the committed `HEAD` revision from `../verified-logic`, ignores uncommitted sibling changes, and records the imported revision in `vendor/verified-logic-revision.txt`.

## Verification

```bash
verus verus/example_spec.rs
```
