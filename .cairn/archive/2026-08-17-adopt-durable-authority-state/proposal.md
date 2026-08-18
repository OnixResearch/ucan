## Why

UCAN exposes replay and revocation injection points but leaves durable state to applications.
The published Durable Authority State component now provides matching product-neutral mechanisms.
A checked pilot can remove example-only storage logic without moving UCAN policy or authority into the component.

## What Changes

- Pin the canonical Radicle source at exact object `a0de79303f3f45c18a34fff535b690a85cb3cf59`.
- Add a UCAN shell adapter for `HolderInvocationReplayAdmission` over `replay-ledger-core`.
- Add a UCAN shell adapter for `RevocationChecker` over `revocation-view-core`.
- Keep persistence ports, time, tenant, generation, namespace, attempt, authenticity, and outage policy caller-owned.
- Preserve holder replay as the final state-consuming UCAN boundary.
- Add positive and negative adapter tests for duplicates, conflicts, stale state, incomplete snapshots, and backend failures.
- Record source, authority, and evidence non-claims.

## Impact

- **Crates**: the root `ucan` shell gains adapters; `ucan-core` remains unchanged
- **Dependencies**: exact Radicle revisions for the two separate semantic cores
- **Authority**: UCAN retains token, signature, profile, capability, caveat, and final-commit ordering
- **Testing**: focused adapter tests, existing holder and revocation suites, Cargo and Nix source checks, Cairn gates, and full repository checks
