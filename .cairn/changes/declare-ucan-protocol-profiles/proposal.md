## Why

This crate presents its three-part EdDSA/JWT token as UCAN, but it does not name an exact protocol profile. The final UCAN `1.0.0` specification uses DAG-CBOR, Varsig envelopes, CIDv1 proof references, and separate Delegation and Invocation payloads.

Without explicit profiles, consumers can mistake the current compact format for UCAN `1.0.0`. That ambiguity can cause unsafe parser dispatch, false interoperability claims, and invalid fixture conclusions.

## What Changes

- Add a closed protocol-profile catalog that names the current compact format without claiming an upstream version.
- Record UCAN `1.0.0` as a separate unsupported target profile.
- Pin the reviewed overview, Delegation, Invocation, fixture, and `rs-ucan` source revisions.
- Add a reproducible fixture inventory and conformance report for the pinned UCAN `1.0.0` fixtures.
- Reject implicit, unknown, stale, and mismatched protocol-profile declarations.
- Keep protocol-profile selection outside the existing token hot path until a new profile-specific API exists.

## Impact

Consumers can identify the exact format that produced a token or receipt. The current compact API and token bytes remain unchanged.

The report will show unsupported or untested UCAN `1.0.0` cases honestly. A fixture inventory is evidence about selected files, not proof of complete conformance.

## Dependencies

This change extends the accepted integration-support-profile boundary. It does not depend on another active local change.

## Non-goals

- Do not parse, issue, verify, or authorize UCAN `1.0.0` tokens.
- Do not relabel the current compact format as UCAN `0.8`, `0.9`, `1.0`, or another upstream version.
- Do not silently dispatch untrusted bytes between profiles.
- Do not import the legacy TypeScript fixture generator or the unaudited `rs-ucan` crate.
- Do not implement AWAKE, Promise, Revocation, transport, storage, or remote resolution.
