## Why

The audited dependency set has zero known vulnerabilities. Two advisories
apply but are not exploitable in this repo's usage: `paste` is unmaintained
(dev-only, via `hegeltest`), and the `anyhow::downcast_mut` unsoundness
(RUSTSEC-2026-0190) reaches only the vendored `repo_index` tooling module,
which never calls `downcast_mut`. There is no standing guard that keeps this
posture checked, so a future dependency bump could silently reintroduce a
vulnerability or a violation without CI notice.

## What Changes

- Add a checked advisory policy (cargo-deny configuration) at the repo root.
- Pin the two non-exploitable advisories with their rationale.
- Wire the advisory and license checks into an existing focused Nix check.
- Record the audited dependency posture in the production-readiness report.

## Impact

Dependency regressions are caught in CI. The recorded posture stays
reproducible. No runtime dependency changes.

## Dependencies

This change depends only on the audited revision. It does not change token,
proof, capability, or authorization semantics.

## Non-goals

- Do not bump or vendor any dependency version.
- Do not fork `paste` or `anyhow`.
- Do not change the license policy for verified-logic or vendored code.
