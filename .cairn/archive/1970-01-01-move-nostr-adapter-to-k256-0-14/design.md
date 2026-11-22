## Context

`ucan-nostr` is the only UCAN package that depends on `k256`. In the locked graph, `k256 0.13.4` is the only path to `ecdsa 0.16.9`, `elliptic-curve 0.13.8`, and `crypto-bigint 0.5.5`. `RUSTSEC-2026-0387` affects `crypto-bigint` below `0.7.6`.

Basalt commit `1c142e2` moved its vendored copy of the adapter to `k256 0.14.0` without a matching UCAN revision.

## Decisions

### Decision: Upgrade instead of pinning the advisory

**Choice:** Require exact `k256 0.14.0` and let Cargo resolve its companion crates with `cargo update -p k256 --precise 0.14.0`. Add no `deny.toml` pin for `RUSTSEC-2026-0387`.

**Rationale:** The upgrade removes the affected crate from the locked graph. A pin would leave affected constant-time arithmetic linked behind a rationale.

### Decision: Convert key bytes explicitly

**Choice:** `VerifyingKey::from_bytes` now takes `&FieldBytes`. Build a `k256::FieldBytes` from the decoded 32-byte x-only key at each construction site. Keep the existing error mapping.

**Rationale:** The conversion is a fixed-size copy with no new failure path. Point validation, signature parsing, and `verify_raw` keep the same inputs and diagnostics.

### Decision: Match Basalt `1c142e2` up to formatting, the test fix, and the identity label

**Choice:** The adapter changes carry the same tokens as Basalt's vendored `vendor/ucan/crates/ucan-nostr` files at `1c142e2`. The manifest is byte-identical. `src/model.rs` and `src/protocol.rs` differ only by whitespace, because UCAN's `rustfmt.toml` joins the three split `from_bytes(&field)` statements onto single lines. Basalt `1c142e2` did not compile the vendored adapter's unit tests, so its `src/tests.rs` still passed `&[u8; 32]` to `SigningKey::from_bytes`. This change converts that test secret to `FieldBytes`. `src/context.rs` also differs; see the next decision.

**Rationale:** Basalt's release-verify rail requires its vendored snapshot to equal a real UCAN revision, and UCAN's test and formatting gates must pass. A Basalt re-import takes these differences with the rest of the revision.

### Decision: Rename the k256 version in the implementation identity

**Choice:** The Nostr implementation-identity input changes from `ucan-nostr@0.1.0|k256@0.13.4|sha2@0.10.9|blake3@1.8.5|serde_json@1.0.149` to `ucan-nostr@0.1.0|k256@0.14.0|sha2@0.10.9|blake3@1.8.5|serde_json@1.0.149`. The resulting `VerifiedNostrCredential::implementation_identity()` changes from `38ee3e2bbf9af15fbf67910d11f2932326b42ea67ace165b711680a9dc5d6dc3` to `8d93504d1473a6ce668eea30cd81246186187470b3650131f603de8a05219392`. Both values were computed by calling `verify_credential` on the adapter before and after the edit.

**Rationale:** An identity that names `k256 0.13.4` while linking `0.14.0` misstates the implementation. The dependency change is the point where the identity must change. This follows the Zeroize and BLAKE3 identity precedents. Credentials issued before this change keep their original identity and do not migrate. No UCAN fixture, test, document, or Nickel contract pins the identity hash.

### Decision: Enforce the advisory closure in the posture rail

**Choice:** `tools/check-dependency-posture.rs` and `tests/dependency_posture.rs` require one locked `k256 0.14.0` and reject any `crypto-bigint` below `0.7.6`. The test also requires the Nostr identity input to name `k256@0.14.0`. It rejects a drifted manifest, a stale identity label, and a drifted lock.

**Rationale:** A later lock change could reintroduce the affected crate without touching `deny.toml`, and a later bump could leave the identity label stale. The lock and sources are the checked inputs, so the rail checks them directly.

## Risks / Trade-offs

- The lock now carries two `sha2` versions, `0.10.9` for UCAN-owned hashing and `0.11.x` for `k256`. UCAN-owned digest code keeps using `sha2 0.10.9`.
- Consumers that store or compare the Nostr adapter implementation identity see a new value after re-import.
