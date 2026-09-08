# Tasks

Evidence: [source-bound qualification](../../../research/current/holder-authorization-recheck/REPORT.md).

- [x] [serial] Add pure digest/time-floor admission and direct boundary controls. r[ucan.holder_recheck.binding] Evidence: source `12a6687`, 7 core holder tests passed.
- [x] [serial] Add borrowed non-consuming holder observation through existing verifiers. r[ucan.holder_recheck.observation] Evidence: source `12a6687`, 24 shell holder tests passed in each feature profile.
- [x] [serial] Cover success, changed services, revocation, expiry, replay preservation, and type separation. r[ucan.holder_recheck.observation] Evidence: 6 new shell controls and 6 independent compile-fail controls passed in each profile.
- [x] [serial] Document the API, run default/minimal/full owner gates, and retain source-bound evidence. r[ucan.holder_recheck.evidence] Evidence: complete workspace tests, strict Clippy, no_std check, and 13 Nix checks passed; see the qualification report.
