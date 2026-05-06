# Production Readiness

This crate is **controlled-integration ready**, not a turnkey production UCAN platform.

A controlled integration is one where the consuming application wires all external truth explicitly: key resolution, proof lookup, revocation, verification time, verification limits, caveat policy, signer custody, and replay/persistence policy. The crate supplies deterministic Rust APIs and fail-closed boundaries for those inputs; it does not install ambient network, storage, registry, clock, or key-custody behavior.

The machine-readable support report lives at [`docs/production-readiness.json`](production-readiness.json). The Rust API exposes the same classification through `production_readiness_report()`.

## Current support labels

| Surface ID | Surface | Label | Boundary |
| --- | --- | --- | --- |
| `ed25519-did-key-compact-token` | Ed25519 `did:key` compact token issue/parse/verify | `controlled-integration-ready` | Caller owns key custody, key provenance, request policy, and deployment hardening. |
| `caller-supplied-key-resolution` | Caller-supplied key resolution | `controlled-integration-ready` | Remote DID method support, trust roots, freshness, and cache behavior are application-owned. |
| `caller-supplied-proof-store` | Caller-supplied proof store | `controlled-integration-ready` | Network, filesystem, database, IPFS, content-addressed freshness, and proof provenance are application-owned. |
| `caller-supplied-revocation` | Caller-supplied revocation | `controlled-integration-ready` | Registry truth, persistence, duplicate semantics, freshness, and backend availability are application-owned. |
| `generic-consumer-integration-hooks` | Generic consumer integration hook traits | `controlled-integration-ready` | Consumer-specific resource, ability, identity, envelope, backend, freshness, retry, and persistence semantics are application-owned. |
| `caller-supplied-replay-admission` | Caller-supplied replay/nonce admission hook | `controlled-integration-ready` | Durable replay detection, crash recovery, backend corruption handling, and cross-process freshness are application-owned. |
| `verified-replay-admission-transcript` | Verified replay-admission transcript | `controlled-integration-ready` | Nonce uniqueness truth, request identity provenance, durable replay storage, crash consistency, backend freshness, and consumer envelope semantics are application-owned. |
| `opaque-caveat-policy-evaluation` | Opaque caveat policy evaluation | `controlled-integration-ready` | Arbitrary caveat semantics, clocks, counters, and external policy truth are application-owned. |
| `finite-typed-caveat-helpers` | Finite typed caveat helpers | `preview` | Production use needs integration-specific policy and provenance evidence. |
| `web-of-trust-helpers` | Web-of-Trust helpers | `preview` | DID/CID decoding, evidence fetching, trust-store discovery, revocation freshness, and persistence are not supplied. |
| `remote-did-resolution` | Remote DID resolution | `unsupported` | Integrators must supply resolver trust, method admission, freshness, cache, and fail-closed behavior. |
| `proof-transport-backends` | Proof transport backends | `unsupported` | Integrators must supply proof provenance, freshness, bounds, and reference matching. |
| `registry-backed-revocation` | Registry-backed revocation | `unsupported` | Integrators must supply registry truth, freshness, duplicate handling, and outage behavior. |
| `replay-persistence-store` | Replay/persistence store | `unsupported` | Integrators must supply durable replay detection, recovery, corruption handling, and freshness policy. |
| `non-ed25519-key-algorithms` | Non-Ed25519 key algorithms | `unsupported` | Future algorithms need parsing, admission, mismatch, signature, and unsupported-algorithm evidence. |

No current surface is labeled `production-supported`. A future promotion to `production-supported` must add positive tests, negative fail-closed tests, operator-facing evidence, and matching updates to README, public API docs, boundary docs, and the machine-readable report.

## Required integration profile

A production consumer MUST wire these inputs explicitly:

- `KeyResolver` or `KeyResolutionContext`
- `ProofStore` or `ProofCollection`
- `RevocationChecker` or `NoRevocations`
- `VerificationTime`
- `VerificationLimits`
- `CaveatPolicySet`
- `TokenSigner` and caller-owned key custody

The integration MUST fail closed for resolver errors, missing/stale/oversized/cyclic proof material, revocation denials or backend failures, replay duplicates/stale/malformed/denied/backend failures, missing/rejected caveat policies, unsupported DID methods or algorithms, and verification-limit overflow. Backend truth, freshness, persistence, provenance, and retry policy remain application-owned.

For Aspen specifically, this means Aspen should consume `ucan` as a library and implement its own Aspen-side mapping from UCAN resource/ability/caveats into Aspen capabilities, operations, identity, revocation, replay, and RPC envelopes. For Clankers specifically, Clankers should implement its own agent/tool/session permission mapping and storage/enforcement semantics. No Aspen or Clankers adapter belongs in this crate.
