## Goals

- Verify an authenticated peer message at an optional, reusable boundary.
- Keep verification logic deterministic and free of ambient effects.
- Separate message authentication from capability, subject, and authorization logic.
- Preserve BLAKE3 identities and reject digest-role confusion.

## Package boundary

Add the authenticated-message framing to `ucan-core`. Existing `ucan-core` and `ucan` APIs remain source-compatible.

The pure core accepts already-built message bytes, a key, a clock timestamp, and a replay disposition as values. It does not read a clock, a key store, or a durable replay store.

The shell performs bounded input reads and output writes. Transport, key custody, clock, and durable replay integration stay consumer-owned.

The framing does not enter UCAN issue, parse, proof, invocation, caveat, revocation, or authorization paths.

## Message contract

The core verifies these facts over a single message:

1. The protocol version matches the negotiated version.
2. The body-bound signature binds the exact body bytes.
3. The HMAC authenticates the message with the supplied key.
4. The timestamp is within the accepted clock bound.
5. The replay disposition admits the message exactly once within the caller policy.

The caller supplies the expected version, key, current timestamp, accepted skew, and replay disposition. Message content cannot widen the caller policy.

## Verified output

Only successful verification constructs the authenticated-message verdict.

The output contains public, bounded fields:

- negotiated protocol version;
- message BLAKE3 identity;
- body-bound signature reference;
- explicit freshness disposition;
- explicit replay disposition;
- implementation identity;
- required non-claims.

The output excludes private keys, raw shared secrets, transport state, and any capability or subject fact.

A verified message proves only the checked authenticated-message statement for one bound message. It does not grant authority or authenticate an end user.

## Functional core and shell

The pure core receives current time, accepted skew, version, key, and replay disposition as values.

The shell owns input reads, output writes, and integration with the caller transport.

## Reference

The Celld peer-protocol design is a bounded reference input. It is a comparison source, not a UCAN requirement, parity claim, or equivalence claim.

## Verification

Positive coverage includes official vectors, matching version, valid body-bound signature, valid HMAC, in-bound clock, and exactly-once replay admission.

Negative coverage includes wrong version, altered body, bad HMAC, stale timestamp, out-of-bound skew, replay denial, and secret-field leakage.

Boundary coverage rejects digest-role substitution, empty-message drift, ambient clock or key reads, capability promotion, and UCAN hot-path coupling.
