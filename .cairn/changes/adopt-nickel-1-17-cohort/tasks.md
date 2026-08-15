# Tasks: Adopt Nickel 1.17 for UCAN policy and evidence

## Pin and authority boundary

- [ ] [serial] Add an exact Nickel `1.17.0` source input at commit `1320a983e6c3d1e2fb53dd2464b084b4903b1426`. r[ucan.nickel_toolchain.cohort]
- [ ] [serial] Replace policy, proof, readiness, fixture, and developer-tool uses of the older evaluator. r[ucan.nickel_toolchain.cohort]
- [ ] [serial] Regenerate `flake.lock` only with a Nix lock command. r[ucan.nickel_toolchain.cohort]
- [ ] [parallel] Add a guard for older, floating, ambient, or mixed evaluators. r[ucan.nickel_toolchain.cohort]
- [ ] [parallel] Prove policy acceptance does not replace UCAN authority checks. r[ucan.nickel_toolchain.boundary]

## Compatibility and evidence

- [ ] [parallel] Run valid policy, proof-profile, readiness, import, contract, and evidence fixtures. r[ucan.nickel_toolchain.compatibility]
- [ ] [parallel] Add malformed, missing-import, contract, unknown-field, stale, identity-mismatch, and cohort negative fixtures. r[ucan.nickel_toolchain.compatibility]
- [ ] [serial] Record the exact evaluator identity in Nickel-dependent release evidence. r[ucan.nickel_toolchain.evidence]
- [ ] [parallel] Add evaluator-substitution, freshness-overclaim, and authority-overclaim evidence failures. r[ucan.nickel_toolchain.evidence]

## Validation

- [ ] [serial] Run policy fixtures, proof checks, readiness checks, formatting, Clippy, Cairn gates, and relevant Nix checks. r[ucan.nickel_toolchain.validation]
