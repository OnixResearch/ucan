## Goals

- Document the replay admission-key contract and the default accept posture.
- Provide a correct in-memory exactly-once baseline store example.
- Keep all public interfaces and outcomes unchanged.

## Package boundary

The change is documentation and an example under `examples/`. No library
behavior or public API changes.

## Replay contract

1. The admission key is `BLAKE3(compact_token_bytes)`.
2. The token format carries no invocation-specific nonce.
3. Identical bytes plus identical (resource, ability) are indistinguishable.
4. `AllowAllReplayAdmission` (default) accepts every replay.
5. Exactly-once semantics require a caller-owned store.

## Baseline example

Add `examples/replay_baseline.rs`. The example:

- issues one token;
- invokes the same resource/ability twice through a store-backed
  `ReplayAdmission`;
- shows the second invocation rejected as `ReplayAdmissionError::Duplicate`;
- documents the durable-storage extension point in comments.

## Verification plan

- Keep the audited-revision test baseline green.
- Verify the example compiles and runs.
- Verify existing invocation tests still pass unchanged.
