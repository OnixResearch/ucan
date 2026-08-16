# Invocation Replay Identity: Implementation Evidence

Date: 2026-08-15

## Documentation

- New file: `docs/invocation-reference.md`
- BLAKE3 digest: `927d5f45f92fb4040ea6bf8056fc7ad17e1ff96583644c4ad34998d26219807e`
- Documents the admission-key contract (bounded-token BLAKE3 digest), the
  indistinguishability behavior, the `AllowAllReplayAdmission` default
  accept-everything posture, and the caller-owned store requirement.
- README replay section updated to state the admission key, the default
  posture, the store requirement, and the reference link.

## Baseline example

- New file: `examples/replay_baseline.rs`
- BLAKE3 digest: `1f0066942019e21f6ba5dcb80c7b095e3b3d00576c33b4d6f03ef80e2692edfb`
- Demonstrates the admission key, the accept-everything default, and the
  exactly-once store behavior.
- Positive behavior: the first admit and the first verified invocation are
  allowed.
- Negative behavior: the second direct admit is `ReplayAdmissionError::Duplicate`;
  the second verified invocation is denied with `InvocationDenialReason::Replay`.
- The store comment documents the durable-storage extension point and keeps
  `admit_invocation` as the only commit point.

## Checks

- Baseline before edits: `cargo test -p ucan --lib` -> 192 passed, 0 failed.
- After edits: `cargo test -p ucan --lib` -> 192 passed, 0 failed (no
  regressions; no library changes).
- `cargo run --example replay_baseline` -> exit 0; duplicate denial and
  default-posture output observed.
- `cargo build --examples` -> exit 0 (all examples compile).
- `cargo clippy -p ucan --lib -- -D warnings` -> exit 0.
- `cargo clippy -p ucan --example replay_baseline -- -D warnings` -> exit 0.
- The changed source files are `rustfmt` clean. Pre-existing committed
  formatting drift in `examples/pentest_*.rs` is out of scope; the primary
  worktree carries uncommitted local fixes for those files.
- `cairn gate proposal|design|tasks document-invocation-replay-identity` ->
  expected exit 0 (recorded before closeout).

## Non-claims

No public interface or authorization outcome changed. The example and docs
record the existing measured admission behavior. No nonce-store truth,
durability, crash-recovery, transport, or execution-safety claim is added.
