# Proposal: Harden compact-token secret ownership

## Why

A compact UCAN token is a bearer credential. The current shell copies compact tokens into ordinary `String` and `Vec` allocations during parsing, proof lookup, cloning, and verified framing checks.

Those allocations are not wiped. Reallocation can also leave stale copies after the live value moves.

Basalt needs a verification path that borrows request input and does not create ordinary owned bearer copies. Resolved proof tokens need the same ownership rule.

## What Changes

- Add a borrowed compact-token verification path with explicit time, key resolver, proof store, revocation checker, and verification limits.
- Bound each complete compact token before hashing, base64 decoding, JSON decoding, or proof traversal.
- Replace ordinary compact-token owners with zeroizing owners that do not implement secret-revealing traits.
- Let proof stores return borrowed or zeroizing proof-token values without cloning bearer bytes.
- Decode token-derived bytes into exact, non-growing, zeroizing buffers.
- Build issuance JSON, base64 segments, signing input, signature buffers, and final compact tokens without bearer-bearing reallocation.
- Publish only fixed-width BLAKE3 references for bounded complete compact inputs.
- Add source and runtime tests for positive paths, negative paths, cleanup, capacity, and compatibility boundaries.

## Impact

The change intentionally removes formatting, serde, cloning, and ordinary reconstruction from compact-token owners. Callers must pass borrowed bearer text or move a zeroizing owner.

Proof-store implementations must return a borrowed or zeroizing proof-token value. Verified results expose proof references, not proof-token owners.

The no-stale-copy claim is conditional on the reviewed `base64`, `serde_json`, and `zeroize` dependency versions. The implementation must stop if their source behavior does not support the claim.

## Non-goals

- Do not claim process memory locking, swap exclusion, crash-time wiping, allocator clearing, or protection from a hostile process.
- Do not add ambient key, proof, revocation, replay, time, or limit inputs.
- Do not change UCAN authorization, attenuation, caveat, signature, or DID semantics.
- Do not claim that BLAKE3 references prove token validity, backend truth, freshness, or authority.
