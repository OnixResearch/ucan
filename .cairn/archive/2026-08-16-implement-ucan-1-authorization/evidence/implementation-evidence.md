# Implementation Evidence

## Result

The bounded final `ucan-wg-1.0.0` wire and authorization profile is implemented.
The functional core owns command, policy, chain, time, and admission rules. The
shell owns wire verification, CID-bound proof loading, revocation observations,
replay commitment, live authorization, and redacted receipts.

## Baseline

Before this change, workspace library tests passed with 224 `ucan` tests, 54
`ucan-core` tests, and 12 `ucan-nostr` tests. The final authorization profile
was declared but unsupported.

## Positive evidence

- `cargo test -p ucan-core`: 71 passed.
- `cargo test -p ucan --lib profile::v1_authorization`: 14 passed.
- `cargo test --workspace --lib`: 235 `ucan`, 85 `ucan-core`, and 12
  `ucan-nostr` tests passed before the final focused audit changes. The final
  audit changes then passed the focused core and shell suites.
- The exact flake nextest command passed 346 of 346 tests:
  `cargo nextest run --cargo-profile release --locked -p ucan -p ucan-core
  -p ucan-nostr --lib --examples --features ucan-core/peer-auth`.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- `cargo check -p ucan-core --no-default-features --target
  wasm32-unknown-unknown`: passed.
- `cargo test --test dependency_posture`: 3 passed.
- `cargo run --locked --example protocol_profile_report`: Delegation,
  Invocation, and Policy rows passed.
- Production readiness passed with immutable Nickel 1.17.0. The report bound
  catalog BLAKE3
  `2bd91f2d23540781ded43e409130bb23dd77785ac641a33394f8514edd2c6f25`.
- Cairn proposal, design, and tasks gates passed. Repository validation passed.
- `nix flake check --no-build -L`: all flake outputs and checks evaluated.

## Negative evidence

Tests cover invalid commands, lexical-prefix escalation, malformed selectors,
unknown operators, unsupported jq forms, unresolved selectors, type mismatch,
policy depth and work limits, invalid clock skew, clock overflow, root and
subject substitution, duplicate and reordered proofs, command attenuation,
time, revocation, policy denial, executor mismatch, tampered Invocation
signatures, missing proofs, unavailable proof storage, malformed proof bytes,
oversized proofs, substituted CIDs, replay denial, and receipt profile or
cohort substitution.

Every tested preflight denial made zero replay calls. An allowed preflight made
one replay call. All allowed receipt work occurs before that call; only
infallible moves and private live-value construction remain after replay
accepts.

## Security audit

A bounded three-lens audit checked authority flow, replay ordering, and receipt
redaction. It found and fixed these defects before acceptance:

- Invocation parsing did not also verify the Invocation signature.
- Replay failures could carry backend text into receipts.
- Allowed receipts were built after replay acceptance.
- Receipt decision identities held reversible bytes instead of domain-bound
  BLAKE3 identities.
- Clock-skew arithmetic could overflow or admit a negative skew.

The final tests cover each repaired boundary.

## Conformance differential

The pinned upstream `policy.json` has an invalid anonymous object wrapper at
lines 86 and 93. The report first validates the unchanged pinned bytes. It then
removes only those two exact lines from an in-memory execution projection. The
Policy row records reason code
`executed-with-pinned-json-normalization`.

The report does not claim byte-for-byte parity with the upstream encoder.

## Bounded infrastructure blocker

`nix flake check -L` evaluated all outputs and started the checks. It failed
only while the remote builder compiled the pinned Nickel 1.17.0 dependency.
The remote sandbox lost `/build` and `/dev/null`, which caused temporary-file
errors and exit 101 for `nickel-lang-deps-1.17.0`. No UCAN source diagnostic
caused the failure.

The next-best checks passed: full flake evaluation, the exact 346-test nextest
command, strict Clippy, formatting, no-std wasm, production readiness with
Nickel 1.17.0, dependency posture, conformance regeneration, and Cairn gates.
The repository does not wire an Octet check in this flake, so Octet is N/A for
this change.

## Non-claims

Passing authorization does not prove resolver truth, proof transport truth,
executor provenance, clock truth, revocation freshness, durable replay
storage, transport security, external resource ownership, policy completeness,
backend durability, effect correctness, or full interoperability.
