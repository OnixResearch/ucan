## Phase 1: Spec Foundation

- [x] [serial] Write proposal, design, delta spec, and implementation task plan for `add-verified-replay-admission-transcript` ✅ 0h 10m (started: 2026-05-06T20:33:53Z → completed: 2026-05-06T20:33:53Z)

## Phase 2: Verified Primitive Implementation

- [ ] [serial] Add the focused verified-logic primitive(s), proof contracts, and exported helpers for this seam.
- [ ] [depends:verified-primitives] Sync the vendored `verified-logic` snapshot into `ucan` with `./scripts/sync-verified-logic.sh` and record the imported revision.

## Phase 3: Shell Integration

- [ ] [depends:vendored-snapshot] Route the `ucan` shell/core path through the new verified bridge without adding consumer-specific adapters.
- [ ] [parallel] Update README, public API, verified-boundary, and production-readiness docs to describe the new verified claim and retained boundaries.
- [ ] [parallel] Add positive, negative, and boundary tests/examples for the routed behavior.

## Phase 4: Verification and Archive

- [ ] [depends:shell-integration] Run focused cargo tests, readiness/bridge checks, OpenSpec validation, whitespace checks, and full `nix flake check`.
- [ ] [depends:verification] Capture implementation verification evidence under this change.
- [ ] [depends:evidence] Archive the OpenSpec after all implementation and verification tasks are complete.
