# Proposal: Adopt Nickel 1.17 for UCAN policy and evidence

## Why

UCAN configuration checks currently resolve to Nickel `1.16.0`. Policy, proof, and release configuration must use the stack Nickel `1.17.0` cohort.

## What Changes

- Pin Nickel `1.17.0` at upstream commit `1320a983e6c3d1e2fb53dd2464b084b4903b1426`.
- Use the pin for policy, proof profiles, readiness checks, fixtures, and Nix checks.
- Add positive and negative compatibility fixtures for contracts, imports, merges, exports, and diagnostics.
- Record the exact evaluator identity in release evidence where applicable.

## Impact

UCAN configuration will use the stack Nickel cohort. UCAN retains token, proof-chain, caveat, revocation, replay, and authority semantics.

## Dependencies

This change uses the upstream Nickel `1.17.0` release.

## Non-goals

- Do not change UCAN protocol or authority semantics.
- Do not update unrelated dependencies only to obtain Nickel.
- Do not claim trust or freshness from configuration acceptance.
