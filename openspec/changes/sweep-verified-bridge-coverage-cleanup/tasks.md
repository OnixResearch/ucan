## Phase 1: Specification

- [x] [serial] Create focused OpenSpec for one-sweep verified bridge coverage cleanup.

## Phase 2: Inventory

- [ ] [serial] Inventory every public verified export, every live verifier bridge call, and every vendored UCAN verified-logic module; classify each as live-path, public-helper, documented-boundary, or candidate.
- [ ] [depends:inventory] Record the classification in docs and/or guard-readable form without preserving secret source repo metadata.

## Phase 3: Cleanup

- [ ] [depends:inventory] Route any candidate exact executable bridge into the live path, or explicitly document why no candidate remains.
- [ ] [depends:inventory] Update `docs/verified-boundaries.md`, canonical library spec text, and public API notes so public-helper-only bridges are not described as live verifier guarantees.
- [ ] [depends:docs] Strengthen `scripts/check-ucan-bridge.sh` or equivalent guard coverage for required bridge names and boundary documentation.

## Phase 4: Validation and Archive

- [ ] [depends:cleanup] Run focused Rust checks for changed bridge/live-path code, `./scripts/check-ucan-bridge.sh`, OpenSpec validation, `git diff --check`, and full UCAN gates when implementation changed.
- [ ] [depends:validation] Archive the OpenSpec, commit, push, and verify clean `main` / `origin/main`.
