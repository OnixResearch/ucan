# Tasks: Track Dependency Posture

## Advisory policy

- [x] [serial] Add the checked cargo-deny configuration at the repo root. r[ucan.deps.advisory]
- [x] [serial] Pin `RUSTSEC-2024-0436` and `RUSTSEC-2026-0190` with their non-exploitable rationale. r[ucan.deps.ignored]
- [x] [serial] Add a `deny.toml`-style fixture set with positive and negative cases. r[ucan.deps.advisory]

## Check and report wiring

- [x] [parallel] Wire the locked advisory check into an existing focused Nix check. r[ucan.deps.locked]
- [x] [parallel] Record the audited posture, revision, and date in the production-readiness report. r[ucan.deps.report]
- [x] [parallel] Regenerate any machine-readable readiness output that exposes the posture. r[ucan.deps.report]

## Closeout

- [x] [serial] Run the locked advisory check and confirm the pins pass. r[ucan.deps.advisory]
- [x] [serial] Run package, workspace, Clippy, Cairn, and Nix checks. r[ucan.deps.locked]
- [x] [serial] Record the check evidence and report revision. r[ucan.deps.report]
