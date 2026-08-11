# Proposal: Add a bounded Nostr identity adapter

## Why

UCAN accepts explicit key, proof, revocation, replay, and time inputs. It does not verify Nostr identities or signed Nostr authentication events.

Nostr uses BIP-340 Schnorr signatures over secp256k1. NIP-01 also requires SHA-256 event identities and canonical JSON serialization.

The stack needs an optional adapter that verifies Nostr key control without changing UCAN token algorithms, DID support, or authorization semantics.

## What Changes

- Add an optional in-tree `ucan-nostr` adapter package.
- Verify NIP-01 event identity and signature rules over already-loaded events.
- Verify explicit challenge, audience, purpose, freshness, and replay facts.
- Support NIP-42, NIP-98, and a domain-separated application challenge profile.
- Produce an opaque `VerifiedNostrCredential` for downstream subject resolution.
- Add a preview surface to the Rust-owned integration support catalog.
- Add official-vector, positive, negative, boundary, and dependency-isolation coverage.

## Impact

The adapter gives consumers a typed proof of Nostr key control. It does not grant a UCAN capability or define a human identity.

The Nostr event ID remains SHA-256 because NIP-01 requires it. Adapter-owned receipts and policy identities remain BLAKE3.

## Dependencies

This change has no downstream prerequisite. Basalt, Valence, and OnixOS changes consume its reviewed output contract after this change stabilizes.

## Non-goals

- Do not add secp256k1 as a UCAN compact-token signing algorithm.
- Do not add a new DID method.
- Do not treat NIP-05, profile metadata, relay acceptance, or relay presence as identity proof.
- Do not provide relay discovery, DNS lookup, private-key storage, or a built-in replay database.
- Do not convert a verified Nostr credential into authorization.
