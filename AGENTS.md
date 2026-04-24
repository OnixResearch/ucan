# Agent Notes

## Architecture
- `crates/ucan-core` is the `#![no_std]` functional core. Keep deterministic parsing/validation there and keep it free of `std` imports.
- The repo-root `ucan` crate is the `std` shell. Put file/path/reader/writer integration there and delegate validation into `ucan-core`.
- UCAN semantic primitives in the shell should bridge into the vendored `vendor/verified-logic` crate instead of reimplementing ability, temporal, signature, or DID logic locally.
- Current public surface is still primitive-heavy: it validates capability documents and wraps verified helpers, but it does not yet provide end-to-end token issuance/parsing/proof-chain APIs. Treat “make it usable” work as adding real token workflows, not just polishing the existing helper exports.

## Build
- `nix develop -c cargo test --workspace` is the fastest verification path for ordinary changes.
- The dev shell now includes `cargo-mutants`, `cargo-fuzz`, and `uv`; Hegel property tests install into `.hegel/` on first run, so keep that directory gitignored.
- `flake.nix` uses Crane, so a tracked `Cargo.lock` must exist before `nix develop` or `nix flake check` can evaluate successfully.
- New workspace files must be at least staged with `git add -N` before Crane-based checks can see them.
- `flake.nix` now builds directly from the repo's cleaned Cargo source because `vendor/verified-logic` is checked in alongside the root manifest.
- Full `nix flake check` now scopes `cargo fmt` and `cargo clippy` to `ucan`/`ucan-core`; otherwise the vendored `verified-logic` snapshot gets reformatted or linted against this repo's policy instead of upstream's.
- Refresh `vendor/verified-logic` with `./scripts/sync-verified-logic.sh`; the script imports the committed `HEAD` revision from the sibling `../verified-logic` checkout and records the imported revision in `vendor/verified-logic-revision.txt`.

## Gotchas
- Avoid SSH-only Cargo dependencies unless the environment is guaranteed to have matching GitHub SSH credentials; anonymous or CI-like environments will fail before tests run.
- Keep wildcard abilities aligned with `verified-logic::ucan_ability`: `*` is valid only as a full path segment, not inside another segment.
- Nix `path:` flake inputs cannot point outside the current flake tree, so `path:../verified-logic` was not a drop-in replacement for the old `git+file:../verified-logic` input. The repo now avoids that constraint by vendoring `verified-logic` in-tree.
- `.gitignore`'s `result*` pattern will also ignore `vendor/verified-logic/src/result.rs` unless that path is explicitly unignored; without it, Crane's cleaned source misses the module and full Nix builds fail.
- While `flake.nix` is changing, repo-local `direnv` reevaluations can stall shell commands. For verification commands, prefer invoking Nix from outside the repo root (for example from `/tmp` with an explicit flake path) to avoid hanging on `nix print-dev-env`.
