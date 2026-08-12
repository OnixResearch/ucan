## Why

The verification gateway claims a 60-second clock-skew tolerance through
`validate_token_envelope`, but `verify_live_dag_proof_transcript` evaluates its
traversal target with `tolerance_seconds = 0`. Measured at the audited revision
(`examples/pentest_chain.rs`, token `nbf=1000 exp=1200`):

- `t=999` (one second before `nbf`): rejected;
- `t=1259` and `t=1260` (within 60 seconds after `exp`): rejected;
- each rejection reports "proof-chain verification failed" instead of a
  temporal error.

The archived change `2026-05-06-verify-parsed-temporal-order-admission`
requires clock tolerance behavior to stay intact. The tolerance is documented
and intended; the traversal gate silently disables it.

## What Changes

- Apply one consistent tolerance to the envelope gate and the live traversal
  DAG gate.
- Report temporal boundary failures as temporal failures, not proof-chain
  failures.
- Keep zero-tolerance behavior available for callers that opt into it.

## Impact

Tokens presented within the documented grace window verify. Operators receive
honest error classes at boundary. No token that currently verifies becomes
rejected; the change only admits tokens that the documentation already
promises.

## Dependencies

This change depends only on the audited revision. It does not alter token,
proof, capability, or authorization semantics.

## Non-goals

- Do not change the default 60-second value.
- Do not change `ucan-core` or vendored verified-logic semantics.
- Do not introduce a tunable tolerance on the issuance path.
- Do not alter behavior inside the strict valid window.
