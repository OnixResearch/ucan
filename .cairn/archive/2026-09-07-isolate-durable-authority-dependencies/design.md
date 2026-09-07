# Durable adapter feature boundary

The default-on durable-authority feature controls only src/durable_authority and
its root re-exports, replay-ledger-core and revocation-view-core. Generic token,
profile, replay and revocation service contracts stay compiled and unchanged.
Disabling a concrete adapter never supplies a permissive service automatically.

No core state transition or verifier ordering changes. Tests run default and
no-default library profiles; defaults retain durable uncertainty/failure controls.
A normal dependency-tree check rejects either durable library in the minimal graph.
The supported minimal library gets an actual pinned Rust 1.95 check without version
bypasses. Dev-only test dependencies can require the current owner compiler, so the
older-compiler check selects only the normal library, not dev dependencies.

The full workspace test exposed an unrelated Hegel bootstrap incompatibility:
hegel-core 0.2.3 uses a private Hypothesis API absent in 6.167.1. Its declared
minimum 6.148.5 passed the three actual properties. The development shell therefore
supplies a UV constraint for that test-only Python dependency. Fresh bootstrap
must pass; no Rust dependency, property assertion or third-party code is changed.

No vendor edit or runtime dependency revision change. Cargo/Nix locks remain generated.
Default API compatibility does not imply every historical no-default consumer used
the new opt-out contract. Document the explicit selection and its non-claims.
