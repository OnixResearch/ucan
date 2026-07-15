## Why

UCAN correctly keeps token parsing, cryptography, proof traversal, caveat evaluation, revocation, replay, and authorization semantics in Rust and vendored verified logic. Nickel should not replace those boundaries.

There is nevertheless a strong authoring-time contract gap around integration support. `production_readiness_report()` and `docs/production-readiness.json` describe supported, preview, and unsupported surfaces plus caller-owned resolver, proof-store, revocation, replay, clock, limit, caveat, and signer inputs. The machine report, Rust constants, documentation, consumer profile choices, and interoperability fixtures are maintained through separate literals and a Python guard rather than one typed, identity-bound compatibility workflow.

Consumers therefore cannot compose a reviewed profile and prove that it is a subset of the current crate support declaration before wiring their shell integrations. This is a configuration and compatibility problem, not an authorization-semantics problem.

## What Changes

- Add Nickel contracts for human-authored UCAN integration support profiles and interoperability fixture manifests.
- Generate the crate support catalog from the Rust-owned `production_readiness_report()` and bind its JSON/Nickel projections by BLAKE3.
- Validate each reviewed profile as a subset of the Rust-declared support catalog, with explicit verification limits, required caller-owned integrations, fail-closed behavior, preview admission, and non-claims.
- Replace the ad hoc readiness guard with a Rust functional core plus thin filesystem shell that checks report, profile, fixture, and documentation parity.
- Add positive and negative profiles/fixtures for supported combinations, unsupported DID/signature/proof transports, missing resolver/revocation/replay policy, invalid limits, stale catalog identity, and overclaiming support labels.
- Keep generated profiles out of token verification and authorization hot paths; no runtime Nickel evaluation is introduced.

## Impact

- **New authoring surfaces**: `contracts/integration-profiles/` and checked generated projections.
- **Existing authority**: `src/readiness.rs::production_readiness_report()` remains the source of actual crate support; `ucan-core`, token verification, and verified-logic semantics are unchanged.
- **Documentation**: `docs/production-readiness.json` becomes a deterministic Rust-generated artifact checked against the profile contract and operator docs.
- **Fixtures**: manifests may identify public test vectors and expected result classes but must not carry live private keys, credentials, bearer tokens, or backend secrets.
- **Lifecycle**: this is a native Cairn package; the existing OpenSpec archive remains historical migration input and is not rewritten.
- **Claims**: a valid profile proves declared compatibility with the selected crate support catalog only, not resolver truth, key custody, cryptographic correctness, revocation/replay freshness, backend durability, or application authorization completeness.
