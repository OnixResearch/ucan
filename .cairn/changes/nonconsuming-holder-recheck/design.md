# Recheck boundary

## Ownership

The no_std core admits exact token-digest binding and a time floor over ordinary
values. The shell obtains the candidate digest and invokes that admission before
external verification services. Existing UCAN primitives still own signatures,
time windows, proof-chain validation, profile admission, and capability caveats.
No verifier implementation is copied into a consumer.

## API

The original HolderInvocationAuthorized stores its initial verification time
before the existing final replay commit. It remains private-construction and
non-Clone. A separate recheck function borrows that value, the same compact token,
and explicit verification/profile/caveat services. Its context has no replay port.

The shell rejects oversized tokens before hashing. Core admission rejects a
substituted token or a time earlier than initial verification. Existing token
verification rechecks the leaf and complete required proof chain, including
revocation. Existing profile and caveat observation then rechecks the original
operation, resource, and ability. The shell does not verify a new holder request
or reserve another nonce.

The result borrows the original authorization and records the supplied observation
time. It has no public constructor, Clone, serde, or conversion into a new holder
authorization. It proves only that the existing checks passed against the supplied
services and time. It is not another one-shot dispatch capability.

## Failure and non-claims

Failures do not change the original authorization or replay state. The caller must
stop or quarantine affected work. Success does not extend token bounds, change
UCAN's inclusive temporal rules, or replace a consumer's stricter deadline.
The caller owns monotonic time across successive checks, authenticated service
snapshots, atomic release-time checks, crash recovery, and continuing key custody.
A borrowed result can outlive the observed backend snapshot, so it cannot serve
as a persistent current-authority receipt or authorize later effects by itself.

## Verification

Direct and delegated controls must show successful rechecks with replay calls
unchanged. Negatives cover token substitution, time regression, expiry, revoked
leaf/ancestor, unavailable revocation, rejected profile, and rejected caveat.
Compile-fail examples protect construction, cloning, lifetime, and dispatch-type
separation. Default and no-default profiles must pass without weaker services.
