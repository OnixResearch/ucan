## Why

`direct_proofs` resolves a proof reference through a caller-supplied
`ProofStore`, then verifies whatever token the store returns. It never
recomputes the BLAKE3 digest of the returned token and compares it to the
requested reference. A store that returns a different valid token changes the
delegation that is evaluated.

The built-in `ProofCollection` matches by digest and is unaffected. A mismatch
cannot bypass attenuation because the returned token must still satisfy
issuer/audience linkage, capability containment, and time narrowing.
The gap is defense-in-depth on a documented caller-owned boundary.

## What Changes

- Bind every store-resolved proof token to its requested reference by digest
  before verification uses it.
- Reject a reference mismatch with a deterministic proof-store error.
- Keep the built-in `ProofCollection` behavior unchanged.
- Document the binding on the `ProofStore` trait contract.

## Impact

A wrong, stale, or substituted proof token cannot silently change the
delegation graph. Caller-owned stores get a checked guarantee from the
library instead of an implicit contract.

## Dependencies

This change depends only on the audited revision. It does not change token,
proof, capability, or authorization semantics.

## Non-goals

- Do not change the BLAKE3 reference scheme.
- Do not fetch, cache, or resolve proofs inside the crate.
- Do not change `ucan-core` or vendored verified-logic.
- Do not alter the built-in `ProofCollection` matching behavior.
