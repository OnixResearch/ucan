# Implement the UCAN 1.0 Wire Profile

## No-std profile core

- `crates/ucan-core/src/profile/v1.rs` adds bounded no-std domain types and
  admission: nominal `SpecKind` tags, validated slash commands, bounded
  nonce, safe-integer timestamps with nullable expiry, bounded IPLD values,
  proof references, and Delegation/Invocation field-shape admission
  (required, optional, forbidden, wrong-type, tag substitution, oversize,
  field-count, and fail-before-allocation limits).
- Positive field-shape and boundary tests plus negative missing, extra,
  wrong-type, command, timestamp, and inverted-window tests all pass.

## Canonical DAG-CBOR and CID shell

- `src/profile/v1.rs` implements a canonical-CBOR subset encoder and strict
  decoder (definite forms, minimal integers, sorted unique map keys,
  trailing-byte, indefinite-form, float64, tag, and non-text-key rejection),
  protocol CIDv1 construction and validation (DAG-CBOR codec 0x71, SHA-256
  multihash), multibase base58btc round trip, and Varsig-subset envelopes
  (`[ sig, payload ]`) with Ed25519 signing and verification bound to the
  issuer DID key.
- The pinned delegation fixture CID
  `bafyreigyftnzjf4rcu7glp5kfop53vqlopc3zcldauoqdxqlz7t4343gr4` validates as
  CIDv1 DAG-CBOR SHA-256 with a 32-byte digest.
- Negative codec, CID, and crypto fixtures fail closed with stable reasons
  (duplicate field, unsorted/indefinite/non-minimal/trailing/float/tag
  inputs, wrong CID version/codec/multihash/digest, signature mutation,
  wrong key, wrong DID, public key length, unsupported resolver).

## Caller-owned ports and replay evidence

- `V1Signer` and `DidKeyResolver` are caller-owned traits with no ambient
  backends. `StaticEd25519Signer` and `StaticDidKeyResolver` provide
  concrete no-ambient implementations used by tests.
- A non-panicking, deterministic conformance example executes the wire API
  on the pinned fixtures and regenerates `fixtures/1.0.0/report.json`:
  `delegation-json=pass`, `invocation-json=pass`,
  `policy-json=unsupported` (authorization slice).
- The pinned delegation fixture metadata replays through the profile API:
  issuer, audience, subject, command, policy, expires, and nonce project
  onto typed payload fields, canonical encode, CID construction, and
  sign/verify round trips succeed. Derived mutation fixtures
  (`missing-issuer`, `missing-audience`, `tag-substitution`) are bound to the
  fixture BLAKE3 `23ddd201...` and fail with stable reasons. The invocation
  fixture BLAKE3 (`01aeb9aa...`) is asserted stable.

## Checks

- `cargo check -p ucan-core` (no-std): PASS.
- `cargo test -p ucan --lib`: 224 passed, 0 failed.
- `cargo test --test dependency_posture`: 3 passed.
- `cargo clippy -p ucan -p ucan-core -p ucan-nostr --lib --tests -- -D warnings`: clean.
- `cargo run --example protocol_profile_report`: manifest validation PASS,
  deterministic report written (delegation/invocation `pass`, policy
  `unsupported`).
- rustfmt: new and modified files fmt-clean.

## Non-claims and blockers

- The upstream envelope binary layout and pinned CID bytes are not yet
  re-derived byte-for-byte; our canonical form is self-consistent and the
  pinned CID validates structurally. Byte-parity with the upstream encoder
  remains a documented differential item for a later slice.
- No delegation attenuation, policy satisfaction, invocation authority,
  revocation freshness, replay durability, transport, or effect correctness
  is claimed by the wire slice. Those belong to
  `implement-ucan-1-authorization`.
- The Octet gate is not wired in this repository's flake (no octet input or
  `x86_64-linux.octet` check); the closeout entry records this, and
  workspace lints + this change's own rails stand as the local gate.
- `nix flake check -L` and a full upstream-byte differential run remain
  repository-CI activities.
