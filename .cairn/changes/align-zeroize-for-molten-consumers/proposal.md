## Why

UCAN pins `zeroize 1.8.2`, while Molten's Iroh graph requires `zeroize ^1.9`. Cargo cannot select both semver-compatible `1.x` versions, so the reviewed Basalt consumer graph does not resolve.

## What Changes

- Align the root and `ucan-core` exact Zeroize requirements to `1.9.0`.
- Update the peer-authentication implementation identity and dependency review table.
- Extend the dependency-posture rail with positive and drifted Zeroize cases.
- Verify UCAN and the patched Molten consumer graph.

## Impact

The peer-authentication implementation identity changes. Existing receipts remain bound to their original identity and source revision.

This change does not alter secret ownership, erasure timing, BLAKE3 framing, token meaning, cryptographic authority, replay, or revocation policy.
