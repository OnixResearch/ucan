## Goals

- Add a checked, locked advisory policy for the workspace.
- Pin the two non-exploitable advisories with explicit rationale.
- Record the audited posture in the production-readiness report.

## Package boundary

The change adds tooling configuration (`deny.toml` or equivalent), a focused
Nix check, report text, and validation fixtures. No runtime code changes.

## Advisory policy

Add a checked cargo-deny configuration at the repo root that:

1. runs against `Cargo.lock` (frozen resolution);
2. treats a known insecure advisory as an error;
3. allows only pinned advisories that carry an explicit non-exploitable
   rationale;
4. keeps the license policy aligned with `license-policy.tsv`.

Pins:

- `RUSTSEC-2024-0436` `paste`: dev-only via `hegeltest`; no runtime impact.
- `RUSTSEC-2026-0190` `anyhow`: reaches only the vendored `repo_index`
  module, which uses `chain()` and never calls `downcast_mut`.

## Check wiring

Add the advisory/deny invocation to an existing focused Nix check so CI keeps
the posture. The check uses `--locked`/frozen behavior only.

## Report

Record in `docs/production-readiness.md`:

- assessment revision and date;
- zero-exploitable-vulnerability result;
- the two pinned advisories and their basis.

## Verification plan

- Run the pinned advisory check and confirm it passes.
- Add a positive fixture with an unapproved advisory and a negative fixture
  with a pin.
- Regenerate the production-readiness report and confirm the posture text.
- Run the repo Nix checks.
