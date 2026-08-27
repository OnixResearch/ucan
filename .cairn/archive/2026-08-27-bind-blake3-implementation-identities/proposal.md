## Why

The reviewed Cargo manifests resolve BLAKE3 `1.8.5`, but two implementation-identity inputs still name `1.8.4`. This stale label can make a receipt bind the wrong reviewed dependency cohort.

## What Changes

- Align the peer-authentication and Nostr implementation-identity inputs with BLAKE3 `1.8.5`.
- Extend the dependency-posture rail to reject a manifest and identity-label mismatch.
- Re-run focused, workspace, Clippy, formatting, Nix, and Cairn checks.

## Impact

The corrected identity inputs produce new implementation identities. Existing receipts remain bound to their original source revision and identity. This change does not alter BLAKE3 framing, token meaning, cryptographic authority, replay, revocation, or downstream policy.
