# Invocation Replay Identity

## ADDED Requirements

### Requirement: The replay identity contract is documented

r[ucan.replay.identity] The replay admission key MUST be documented as the BLAKE3 digest of the compact token. The documentation MUST state that identical token bytes and identical resource/ability pairs are indistinguishable to the admission hook.

#### Scenario: Consumer reads the contract

r[ucan.replay.identity.read]
- GIVEN a consumer reads the invocation documentation
- WHEN the consumer plans a replay store
- THEN the admission-key definition MUST be explicit
- AND the indistinguishability behavior MUST be explicit

### Requirement: The default posture is explicit

r[ucan.replay.posture] The default `AllowAllReplayAdmission` behavior MUST be documented as accept-everything. The documentation MUST require consumers that need exactly-once semantics to install a store.

#### Scenario: Consumer deploys without a store

r[ucan.replay.posture.read]
- GIVEN a consumer calls the default invocation surface
- WHEN the consumer reads the replay documentation
- THEN the missing-replay-protection behavior MUST be explicit
- AND the requirement to install a store MUST be explicit

### Requirement: A baseline store example exists

r[ucan.replay.example] The repo MUST provide a runnable in-memory exactly-once nonce admission example that consumers can extend with durable storage.

#### Scenario: Consumer follows the baseline

r[ucan.replay.example.follow]
- GIVEN a consumer runs the baseline replay example
- WHEN the same token invokes the same resource/ability twice
- THEN the second invocation MUST be rejected as a duplicate
- AND the example MUST show where durable storage plugs in

### Requirement: Public interfaces stay stable

r[ucan.replay.stable] `ReplayAdmission`, `AllowAllReplayAdmission`, and the invocation surface MUST keep their current signatures and outcomes.

#### Scenario: Existing integration recompiles

r[ucan.replay.stable.unchanged]
- GIVEN a consumer built against the audited revision
- WHEN the documentation change is applied
- THEN the consumer MUST compile without source changes
- AND invocation outcomes MUST be unchanged
