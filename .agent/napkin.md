# Napkin

## Corrections
| Date | Source | What Went Wrong | What To Do Instead |
|------|--------|----------------|-------------------|
| 2026-04-23 | self | Tried baseline `cargo test` before confirming a usable toolchain and dependency source; the repo also had no tracked `Cargo.lock` and an SSH-only git dependency | For this repo, use Nix-provided Rust tools, ensure `Cargo.lock` is tracked for Crane, and avoid unauthenticated SSH-only Cargo dependencies |
| 2026-04-23 | self | Claimed `nix flake check` passed before surfacing an explicit final success record | When using pueue for verification, include the final `pueue_status`/`pueue_log` success evidence before claiming the check passed |
| 2026-04-24 | self | Assumed `path:../verified-logic` could replace the sibling `git+file:` flake input without changing repo layout | Nix `path:` inputs must stay inside the current flake tree; removing the relative `git+file:` warning requires moving `verified-logic` in-tree (submodule/vendor), not just swapping fetcher syntax |

## User Preferences
- Prefer a `no_std` core with a `std` shell; use FCIS boundaries explicitly.

## Patterns That Work
- Start by checking whether the workspace already separates pure core logic from I/O-heavy shell code.
- For this repo, a dedicated `crates/ucan-core` `#![no_std]` crate plus a repo-root `ucan` shell crate keeps FCIS boundaries explicit.
- When verified semantics are required, bridge validated shell values into the vendored `vendor/verified-logic` crate instead of duplicating UCAN logic in `ucan`.

## Patterns That Don't Work
- Assuming architectural boundaries exist without auditing crate features and imports first.
- Leaving SSH-only Cargo git dependencies in the default manifest breaks baseline builds in unauthenticated environments.
- Putting wildcard semantics only in comments is not enough; keep core ability validation aligned with `verified-logic` so `*` is valid only as a full segment.

## Domain Notes
- Repo currently had no `.agent/napkin.md`; start capturing architecture decisions here.
- `flake.nix` uses Crane, so a tracked `Cargo.lock` is required before Nix-based checks will evaluate.
- New workspace files also need `git add -N` before Crane-based format/build checks see them.
- The repo now vendors the verified dependency at `vendor/verified-logic`; both plain Cargo and Nix builds resolve the same checked-in crate path.
- Refresh the vendored snapshot with `./scripts/sync-verified-logic.sh`; it imports the committed `HEAD` revision from `../verified-logic`, ignores uncommitted sibling changes, and records the imported revision in `vendor/verified-logic-revision.txt`.
- Full flake checks must scope `cargo fmt`/`cargo clippy` to `ucan` and `ucan-core`; otherwise the vendored `verified-logic` snapshot is linted against local policy and fails unrelated checks.
- `.gitignore`'s `result*` pattern also matches `vendor/verified-logic/src/result.rs`; explicitly unignore that path or Crane's cleaned source drops the module.
- When `flake.nix` is mid-edit, repo-local `direnv` reevaluation can stall shell commands. Run verification Nix commands from outside the repo root with an explicit flake path to avoid hanging on `nix print-dev-env`.
