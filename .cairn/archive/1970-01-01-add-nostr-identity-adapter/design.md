# Design: Add a bounded Nostr identity adapter

## Goals

- Verify exact Nostr protocol identity at an optional boundary.
- Keep verification logic deterministic and free of ambient effects.
- Keep authentication separate from subject resolution and authorization.
- Preserve distinct SHA-256 and BLAKE3 digest roles.

## Package boundary

Add `ucan-nostr` as an optional in-tree adapter package. The existing `ucan-core` and `ucan` APIs remain source-compatible.

The new package contains a pure core and a thin shell boundary. The pure core accepts already-loaded values and explicit observations.

The shell can read event and challenge bytes. Consumers retain relay access, DNS, NIP-46 sessions, clocks, nonce storage, and private-key custody.

The package does not enter UCAN issue, parse, proof, invocation, caveat, revocation, replay, or authorization paths.

## Canonical Nostr key

The canonical credential key is the raw 32-byte x-only secp256k1 public key. Lowercase hexadecimal is the canonical text form.

An `npub` value is presentation data only. A NIP-05 name is discovery metadata only.

The parser rejects malformed length, non-hex text, invalid curve points, mixed digest roles, and noncanonical text where the profile requires canonical text.

## Protocol verification

The pure core performs these steps:

1. Parse the closed NIP-01 event shape.
2. Recreate the required canonical serialization.
3. Compute the protocol SHA-256 event ID.
4. Compare the computed and supplied event IDs.
5. Verify the BIP-340 signature against the x-only public key.
6. Verify the selected authentication profile.
7. Apply caller-supplied freshness and replay observations.

The implementation uses reviewed Rust cryptography and official vectors. It does not implement elliptic-curve arithmetic locally.

## Authentication profiles

The adapter uses a closed profile enum:

- `nip42-relay` binds the relay URL and relay challenge.
- `nip98-http` binds the absolute URL, method, optional payload hash, and freshness policy.
- `application-v1` binds a domain, audience, purpose, challenge, request identity, event kind, and freshness policy.

The application profile does not claim NIP standardization. Each consumer owns its event kind and schema registration.

The caller supplies the expected values. Event tags cannot select or widen the expected audience, purpose, request, or time policy.

## Verified output

Only successful verification constructs `VerifiedNostrCredential`.

The output contains public, bounded fields:

- canonical Nostr public key;
- Nostr event SHA-256 identity;
- authentication profile;
- audience and purpose identities;
- challenge or request BLAKE3 reference;
- explicit freshness disposition;
- explicit replay disposition;
- adapter profile and implementation identities;
- required non-claims.

The output excludes private keys, NIP-46 secrets, relay credentials, encrypted payloads, raw HTTP bodies, and ambient backend state.

A verified output proves only the checked key-control statement for one bound request. It does not identify a person or grant authority.

## Functional core and shell

The pure core receives current time, accepted skew, expected request fields, and replay disposition as values. It does not read a clock or replay store.

The shell performs bounded input reads and output writes. Network, relay, DNS, signer, and durable replay integrations stay consumer-owned.

## Support catalog

Add a preview `nostr-identity-adapter` surface to `production_readiness_report()` and the generated integration support projections.

The catalog identifies supported profiles, accepted key form, protocol digest role, caller-owned effects, and explicit non-claims.

## Verification

Positive coverage includes each profile, canonical keys, official signature vectors, and stable output identities.

Negative coverage includes malformed keys, wrong IDs, bad signatures, wrong profiles, mismatched request fields, stale events, and replay denial.

Boundary coverage rejects NIP-05 authority, `npub` canonicalization drift, SHA-256 and BLAKE3 substitution, secret fields, and accidental UCAN hot-path coupling.
