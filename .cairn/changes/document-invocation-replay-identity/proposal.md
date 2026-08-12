## Why

The invocation replay key is the BLAKE3 digest of the entire compact token.
The token format carries no invocation-specific nonce claim, so two
invocations that present the same token bytes and the same resource/ability
are indistinguishable to the admission hook. The default
`AllowAllReplayAdmission` accepts every replay.

This is acknowledged in the README as a caller-owned boundary. It is a design
note, not a defect. The hazard is that downstream consumers can deploy
`verify_invocation` with no replay store and receive no replay protection.

## What Changes

- Document the replay-identity contract explicitly: the token digest is the
  admission key and identical token bytes are indistinguishable.
- Document the "off by default" posture of `AllowAllReplayAdmission`.
- Add a first-party in-memory, exactly-once nonce admission example so
  consumers can copy a correct baseline store.
- Keep `ReplayAdmission` and `AllowAllReplayAdmission` interfaces unchanged.

## Impact

Consumers make an informed choice about replay posture. Correct baseline
replay store code is available in-repo. No behavior changes for existing
integrations.

## Dependencies

This change depends only on the audited revision. It does not change token,
proof, capability, or authorization semantics.

## Non-goals

- Do not change the token format or add a `nonce`/`nbh` claim.
- Do not add a durable or distributed replay store.
- Do not change `ReplayAdmission` or `AllowAllReplayAdmission` signatures.
- Do not change invocation authorization outcomes.
