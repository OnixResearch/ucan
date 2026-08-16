# Declare UCAN Protocol Profiles: Implementation Evidence

Date: 2026-08-16

## Nominal profile catalog

- `src/protocol_profile.rs` adds a pure-core closed nominal profile catalog:
  - `onix-compact-ed25519-v1` (supported): three-part base64url compact
    token, Ed25519 EdDSA, JSON claims, BLAKE3 proof references, repository
    resource and ability model.
  - `ucan-wg-1.0.0` (declared but unsupported): DAG-CBOR signing, Varsig
    envelope, CIDv1 SHA-256 proof references, typed payload tags, subject,
    slash commands, arguments or policy, nonce, 53-bit time admission,
    nullable expiry.
  - `admit_protocol_profile_id` fails closed on unknown IDs and declines the
    final profile with a typed non-empty reason.
- `VerifiedToken::protocol_profile()` reports the local profile for every
  verified token; tokens and signed bytes are unchanged.
- A DAG-CBOR-style input fixture confirms the compact parser rejects such
  bytes without dispatch.

## Integration-profile selection

- `IntegrationSupportProfile` gains an optional `protocol_profile` field that
  defaults to the local compact profile. `admit_integration_profile` rejects
  a `ucan-wg-1.0.0` selection as `unsupported-protocol-profile` and an
  unknown selection as `unknown-protocol-profile`.
- The Nickel `IntegrationProfile` contract accepts the optional field. The
  fixture suite gains `negative-unsupported-protocol-profile` (registered in
  `suite.ncl` and `REQUIRED_CASE_IDS`), which the readiness rail rejects at
  the admission stage.
- The support-catalog identity is unchanged (`d46317f0...`), so BLAKE3-bound
  projections stay consistent; `check-production-readiness check` confirms
  freshness: `profiles_accepted=3 profiles_rejected=7 nickel_rejections=8`.

## Pinned sources and fixtures

- Pinned revisions: overview/fixtures `9955aa1f...`, Delegation
  `1cb32dbc...`, Invocation `0f4c1132...`, `rs-ucan` `59ff9b9c...`.
- `fixtures/1.0.0/delegation.json`, `invocation.json`, and `policy.json` are
  mirrored from `ucan-wg/spec` at the overview revision. Their Git blob
  identities match the pinned upstream blobs exactly.
- `fixtures/1.0.0/manifest.json` binds source URL, revision, safe path, Git
  blob, BLAKE3, case class, and expected status per file.
- `examples/protocol_profile_report.rs` recomputes BLAKE3 and Git blob
  identities, validates every manifest entry with the core validator, and
  writes `fixtures/1.0.0/report.json` (all rows `unsupported` for the final
  profile).

## Tests and checks

- `cargo test --workspace --lib`: 223 + 44 + 12 passed, 0 failed.
- `cargo clippy --locked -p ucan --lib --tests -- -D warnings`: clean.
- `cargo clippy --locked -p ucan --example protocol_profile_report -- -D warnings`: clean.
- `cargo fmt --check`: whole crate clean.
- `cargo run --locked --example protocol_profile_report`: manifest validation
  PASS (3 entries); deterministic report written.
- `cargo run --locked --bin check-production-readiness -- check --root . --nickel <nickel>`:
  PASS, including the new unsupported-protocol-profile rejection.
- Positive and negative fixture tests: known local admission, final 1.0.0
  declined, unknown ID fails closed, valid manifest, duplicate ID, unknown
  facts, unsafe paths, stale revision, Git blob mismatch, BLAKE3 mismatch,
  malformed identities, unsupported/untested/pass/fail classification, and
  identity-mismatch classification.
- Pre-existing clippy findings in `examples/pentest_memory.rs` and
  `examples/pentest_authz.rs` are unchanged by this change and are owned by
  the pentest examples.

## Non-claims

No DAG-CBOR parsing or signing exists in this revision. No Varsig envelope or
CIDv1 construction exists. Fixture presence is not interoperability. `rs-ucan`
is advisory, not authority. AWAKE, Promise, Revocation, transport, resolver,
and storage remain out of scope for the `ucan-wg-1.0.0` admission.
