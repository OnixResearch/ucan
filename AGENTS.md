# Agent Notes

## Architecture
- `crates/ucan-core` is the `#![no_std]` functional core. Keep deterministic parsing/validation there and keep it free of `std` imports.
- The repo-root `ucan` crate is the `std` shell. Put file/path/reader/writer integration there and delegate validation into `ucan-core`.
- UCAN semantic primitives in the shell should bridge into the sibling `../verified-logic` crate instead of reimplementing ability, temporal, signature, or DID logic locally.

## Build
- `nix develop -c cargo test --workspace` is the fastest verification path for ordinary changes.
- `flake.nix` uses Crane, so a tracked `Cargo.lock` must exist before `nix develop` or `nix flake check` can evaluate successfully.
- New workspace files must be at least staged with `git add -N` before Crane-based checks can see them.
- `flake.nix` builds from a synthetic source tree that copies the repo at the root and the sibling `verified-logic/` underneath it; `postPatch` then symlinks `../verified-logic` back to that copied subtree so the committed Cargo path dependency still resolves inside the Nix sandbox.

## Gotchas
- Avoid SSH-only Cargo dependencies unless the environment is guaranteed to have matching GitHub SSH credentials; anonymous or CI-like environments will fail before tests run.
- Keep wildcard abilities aligned with `verified-logic::ucan_ability`: `*` is valid only as a full path segment, not inside another segment.
