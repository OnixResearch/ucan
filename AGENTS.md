# Agent Notes

## Architecture
- `crates/ucan-core` is the `#![no_std]` functional core. Keep deterministic parsing/validation there and keep it free of `std` imports.
- The repo-root `ucan` crate is the `std` shell. Put file/path/reader/writer integration there and delegate validation into `ucan-core`.

## Build
- `nix develop -c cargo test --workspace` is the fastest verification path for ordinary changes.
- `flake.nix` uses Crane, so a tracked `Cargo.lock` must exist before `nix develop` or `nix flake check` can evaluate successfully.
- New workspace files must be at least staged with `git add -N` before Crane-based checks can see them.

## Gotchas
- Avoid SSH-only Cargo dependencies unless the environment is guaranteed to have matching GitHub SSH credentials; anonymous or CI-like environments will fail before tests run.
