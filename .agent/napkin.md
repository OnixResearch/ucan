# Napkin

## Corrections
| Date | Source | What Went Wrong | What To Do Instead |
|------|--------|----------------|-------------------|
| 2026-04-23 | self | Tried baseline `cargo test` before confirming a usable toolchain and dependency source; the repo also had no tracked `Cargo.lock` and an SSH-only git dependency | For this repo, use Nix-provided Rust tools, ensure `Cargo.lock` is tracked for Crane, and avoid unauthenticated SSH-only Cargo dependencies |
| 2026-04-23 | self | Claimed `nix flake check` passed before surfacing an explicit final success record | When using pueue for verification, include the final `pueue_status`/`pueue_log` success evidence before claiming the check passed |

## User Preferences
- Prefer a `no_std` core with a `std` shell; use FCIS boundaries explicitly.

## Patterns That Work
- Start by checking whether the workspace already separates pure core logic from I/O-heavy shell code.
- For this repo, a dedicated `crates/ucan-core` `#![no_std]` crate plus a repo-root `ucan` shell crate keeps FCIS boundaries explicit.
- When verified semantics are required, bridge validated shell values into the sibling `../verified-logic` crate instead of duplicating UCAN logic in `ucan`.

## Patterns That Don't Work
- Assuming architectural boundaries exist without auditing crate features and imports first.
- Leaving SSH-only Cargo git dependencies in the default manifest breaks baseline builds in unauthenticated environments.
- Putting wildcard semantics only in comments is not enough; keep core ability validation aligned with `verified-logic` so `*` is valid only as a full segment.

## Domain Notes
- Repo currently had no `.agent/napkin.md`; start capturing architecture decisions here.
- `flake.nix` uses Crane, so a tracked `Cargo.lock` is required before Nix-based checks will evaluate.
- New workspace files also need `git add -N` before Crane-based format/build checks see them.
- The Nix build now needs a synthetic source tree containing the repo root plus a copied `verified-logic/` subtree, then a `postPatch` symlink from `../verified-logic` back into that subtree so the committed Cargo path dependency resolves inside the sandbox.
