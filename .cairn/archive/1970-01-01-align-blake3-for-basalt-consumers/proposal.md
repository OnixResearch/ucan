## Why

Basalt vendors UCAN and enables `ucan-core` peer authentication. UCAN pins BLAKE3 `1.8.4`, while current Onix consumers require exact `1.8.5`. Cargo cannot resolve both exact requirements in one graph.

## What Changes

- Align `ucan-core` and `ucan-nostr` with exact BLAKE3 `1.8.5`.
- Regenerate the Cargo lock with Cargo.
- Prove core, Nostr, workspace, Clippy, and Nix compatibility.
- Preserve UCAN authority, wire, identity, and evidence boundaries.

## Impact

This is a dependency-cohort compatibility change. It does not change hash framing, token meaning, key authority, revocation, replay, or release claims.
