# ucan

## Architecture

- `crates/ucan-core`: `#![no_std]` functional core. Keep parsing, structural validation, and other deterministic UCAN logic here.
- `ucan` (repo root): `std` shell. Keep file I/O, process integration, networking, clocks, crypto, and other side effects here.
- `vendor/verified-logic`: vendored snapshot of the verified library used by the `std` shell for UCAN ability subsumption, attenuation checks, exact finite capability-set authorization, proof-chain issuer/audience linkage, proof-depth budget admission, finite revocation-set membership, concrete invocation admission, deterministic receipt executor/timestamp checks, finite typed caveat helpers, finite proof traversal transcript checks, Web-of-Trust principal digest derivation/admission, WOT evidence/policy helpers, WOT UCAN authorization, token-time validation, Ed25519 signing/verification, and `did:key` encoding/decoding.

The boundary is FCIS-first: the shell gathers bytes and environment state, then hands plain strings and values into `ucan-core`. When a primitive needs verified semantics, the shell bridges validated core values into `verified-logic` instead of reimplementing the logic locally.

The shell crate now carries `serde`, `serde_json`, `base64`, `blake3`, and `snafu` as the correctness-focused foundation for compact-token parsing, strict claim decoding, proof references, and typed error reporting. Property-based integration coverage uses Hegel via the `hegeltest` crate.

## End-to-end issue/parse/verify

The primary public workflow is token-oriented:

```rust
use ucan::{
    AudienceDid, CapabilitySet, ED25519_SECRET_KEY_BYTES, Ed25519InMemorySigner,
    KeyResolutionContext, ProofCollection, TokenSigner, TokenTimeBounds,
    VerificationContext, VerificationTime, issue_token_with_signer, verify_compact_token,
};

let issuer = Ed25519InMemorySigner::from_seed_bytes([7; ED25519_SECRET_KEY_BYTES]);
let audience_key = Ed25519InMemorySigner::from_seed_bytes([9; ED25519_SECRET_KEY_BYTES]);
let audience = AudienceDid::from(audience_key.issuer()?);
let capabilities = CapabilitySet::single("did:key:z6Mkresource", "store/add")?;
let proofs = ProofCollection::empty();
let time_bounds = TokenTimeBounds::new(1_000, 2_000)?;
let token = issue_token_with_signer(&issuer, &audience, &capabilities, &proofs, time_bounds)?;
let context = VerificationContext::new(
    VerificationTime::from_unix_seconds(1_500),
    KeyResolutionContext::new(vec![issuer.verification_key()?]),
    ProofCollection::empty(),
);
let verified = verify_compact_token(&token, &context)?;
assert_eq!(verified.capabilities().as_slice().len(), 1);
assert!(verified.authorize("did:key:z6Mkresource", "store/add").is_allowed());
assert!(!verified.authorize("did:key:z6Mkresource", "admin/delete").is_allowed());
assert!(!verified.authorize("did:key:z6Mkresource", "store/*").is_allowed());
# Ok::<(), Box<dyn std::error::Error>>(())
```

For integration code with many inputs, prefer the named builders and boundary-only
time conversion helpers over positional constructors:

```rust
# use std::time::{Duration, UNIX_EPOCH};
# use ucan::{CapabilitySet, ED25519_SECRET_KEY_BYTES, Ed25519SigningKey, IssueRequest, ProofCollection, TokenTimeBounds};
# let signing_key = Ed25519SigningKey::from_bytes([7; ED25519_SECRET_KEY_BYTES]);
# let audience = ucan::AudienceDid::from(signing_key.issuer()?);
let request = IssueRequest::builder()
    .signing_key(signing_key)
    .audience(audience)
    .capabilities(CapabilitySet::single("did:key:z6Mkresource", "store/add")?)
    .proofs(ProofCollection::empty())
    .time_bounds(TokenTimeBounds::from_system_time_and_duration(
        UNIX_EPOCH + Duration::from_secs(1_000),
        Duration::from_secs(1_000),
    )?)
    .build()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Run the same happy path as a normal example:

```bash
cargo run --example issue_and_verify
cargo run --example http_bearer
cargo run --example failure_handling
```

After `verify_compact_token` succeeds, use `VerifiedToken::authorize`,
`VerifiedToken::authorize_request`, or `VerifiedToken::authorize_with_policies`
to evaluate a concrete operation against the effective delegation only. Concrete
request admission rejects wildcard request abilities through the same
`VerifiedCapability` / `verified-logic` ability bridge used for delegation
containment rather than a parallel shell-local ability parser. Authorization
decisions are structured: allowed decisions expose the matched effective
capability, while denied decisions separate malformed requests (for example a
requested ability containing a `*` segment), missing caveat policies, rejected
caveats, and requests with no matching effective capability. Caveats are opaque
domain/type/key/payload records preserved in `ucan-core` and evaluated in the
shell through caller-supplied `CaveatPolicySet`; unknown caveats fail closed.
For callers that explicitly adopt the vendored typed WOT caveat vocabulary,
`typed_caveat_is_satisfied` and `typed_caveat_set_is_satisfied` expose finite
time-bound and rate/count-window predicates over caller-supplied context without
installing default caveat policies or changing opaque shell caveat behavior.

For invocation-shaped checks, `verify_invocation` first verifies the compact
token, then authorizes the requested resource/ability with the supplied caveat
policies and returns either `InvocationAllowed` context or a structured denial.

Invocation verification composes token/proof verification, caveat-aware authorization, and effective constraints. For concrete matched capabilities, the admitted request is cross-checked through the `invocation_request_is_authorized` verified invocation bridge; wildcard matched capabilities continue to use `VerifiedCapability` containment so wildcard delegation and caveat-denial semantics are not weakened. Allowed invocation results expose the token audience as the invoker exercising the delegated capability. For caller-owned receipt records, `receipt_execution_is_valid` exposes the verified receipt executor/timestamp check without adding receipt storage, replay tracking, signing, networking, or ambient clock reads.

```bash
cargo run --example invocation
```

## Proof-chain delegation

Proof material is explicit. A child token carries BLAKE3 proof references in `prf`; callers may keep using `ProofCollection`, or inject their own synchronous `ProofStore` with `verify_compact_token_with_resolvers`. Verification checks each parent signature, proof-depth budget admission through `proof_depth_within_budget`, issuer/audience linkage through the `proof_link_is_valid` verified-chain bridge, temporal narrowing, capability attenuation, and self-delegation rejection before returning the effective delegation constraints. Advanced callers that already have resolved public chain fields can use `VerifiedChainEntry` plus `structural_chain_is_valid` to run the vendored structural chain composition checker over issuer/audience linkage, caller-provided signature-valid flags, exact attenuation narrowing, and temporal validity. If they also have aligned proof-reference bytes and finite revoked-reference bytes, `structural_chain_not_revoked_is_valid` runs the vendored composed non-revoked-chain checker over the same structural data plus reference-count alignment and finite revocation-set non-membership. For caller-owned finite capability sets, `capability_set_authorizes` runs the vendored capability-set authorizer with resource byte-prefix refinement and exact ability equality; it is not wildcard subsumption and does not replace shell token/effective-delegation authorization. For resolved concrete invocations, `VerifiedInvocationChainRequest` plus `invocation_chain_is_authorized` additionally checks explicit authorization-reference binding to the chain leaf, leaf capability index admission, invoker/audience equality, resource refinement, and ability equality through the vendored invocation-chain checker. For shell-produced finite traversal transcripts, `VerifiedProofTraversalTranscript` plus `proof_traversal_transcript_is_valid` checks resolved entries, visited-reference alignment, duplicate/cycle rejection, depth/proof-count/input-byte budgets, issuer/audience linkage, attenuation narrowing, ordered caveat-id preservation, target authorization, explicit time validity, and supplied revocation-denial facts. For finite Web-of-Trust authorization data, `web_of_trust_principal_digest` derives fixed-width public principal bytes and `web_of_trust_principal_digest_is_valid` admits raw digest bytes through vendored verified-logic for caller-supplied WOT inputs; `VerifiedWebOfTrustUcanAuthorizationRequest` plus `web_of_trust_ucan_authorization` composes the vendored token, caveat, DID/CID link, threshold trust-chain, and revocation-aware Web-of-Trust UCAN authorizer into an explicit allow/deny decision over caller-supplied public facts. These are focused bridges, not proof resolution, compact-token verification, DID/CID decoding, cryptography, revocation backend/freshness checks, caveat policy evaluation, wildcard containment replacement, networking, persistence, replay checks, or ambient clock behavior.

`KeyResolver`, `ProofStore`, `RevocationChecker`, and `ReplayAdmission` are std-shell injection points only: the crate does not provide built-in HTTP, IPFS, database, filesystem, registry, replay persistence, or ambient global lookup. `KeyResolutionContext` implements `KeyResolver`, `ProofCollection` implements `ProofStore`, `RevocationList` implements `RevocationChecker`, and `AllowAllReplayAdmission` preserves compatibility when replay is enforced elsewhere; production consumers should wire their own replay/nonce backend. These hooks remain consumer-agnostic: Aspen, Clankers, or another caller owns resource/action mapping, identity trust, RPC/tool/session envelopes, backend freshness, retry, persistence, and outage policy. Use `verify_compact_token_with_resolvers_and_revocations` when the application has revocation state; use `verify_invocation_with_replay` when the application wants the crate to call its replay/nonce admission policy after token and caveat authorization. `VerificationLimits::default()` bounds recursion with visible defaults for maximum proof depth, maximum resolved proof count, and maximum serialized compact-token byte length; use `VerificationContext::with_limits` or `verify_compact_token_with_resolvers` to override them. To reject oversized caller input before constructing a `CompactToken`, call `verify_compact_token_str`. Live recursive proof traversal, compact-token codec/serde/signing-input construction, BLAKE3 proof-reference derivation, backend error freshness, and opaque caveat-preserving attenuation payload semantics remain shell-local tested boundaries; the verified traversal bridge only checks already-resolved finite transcript facts. See `docs/verified-boundaries.md` for the audit record.

```bash
cargo run --example proof_chain
cargo run --example proof_store
cargo run --example revocation
```

The verified result exposes the issuer, audience, direct capability set, direct proof list, and effective delegation window/capabilities so callers do not need to recompute chain constraints.

Advanced WOT integrations can use `web_of_trust_attestation_payload_bytes`,
`web_of_trust_attestation_signature_is_valid`, `web_of_trust_attestation_is_active_at`,
`web_of_trust_revocation_payload_bytes`, `web_of_trust_revocation_signature_is_valid`,
`web_of_trust_revocation_matches_attestation`, `web_of_trust_revocation_is_effective_at`,
and `web_of_trust_threshold_accepts` for finite public evidence checks. These are
lower-level building blocks beneath `web_of_trust_ucan_authorization`; they do not
resolve identities, fetch evidence, sign records, consult registries, persist state,
or read ambient clocks.

## Support limits

This crate is **controlled-integration ready**, not a turnkey production UCAN platform. The machine-readable and operator-facing support report is maintained in [`docs/production-readiness.md`](docs/production-readiness.md) and exposed in Rust through `production_readiness_report()`.

Reviewed Nickel integration profiles under `contracts/integration-profiles/` are authoring-time declarations bound to the Rust support catalog by BLAKE3. They do not run in token or authorization paths. Check catalog, profile, fixture, and documentation freshness with `cargo run --locked --bin check-production-readiness -- check --root . --nickel nickel`.

- Production-oriented issuance should use `TokenSigner` / `issue_token_with_signer`; `IssueRequest` remains as a compatibility wrapper around the in-memory Ed25519 signer path.
- Supported DID methods: `did:key` for Ed25519 public keys; `decode_did_key` is a structural byte decoder only and does not resolve DIDs or verify signatures.
- Supported signing algorithms: Ed25519 compact-token signatures with `alg = "EdDSA"`.
- Proof-loading model: caller-supplied proof tokens only; the library does not fetch proofs from storage or the network.
- Revocation model: caller-supplied `RevocationChecker` values can deny the leaf token or any proof-chain token by `ProofReference`; revocation registries, credential formats, replay stores, persistence, and remote fetches remain application-owned.
- Replay model: caller-supplied `ReplayAdmission` values can admit or deny a verified invocation after caveat/policy authorization; the finite replay outcome transcript is routed through vendored verified logic for allow/duplicate/stale/malformed/denied/backend fail-closed shape, while durable nonce stores, request identity provenance, crash recovery, duplicate semantics, and backend freshness remain application-owned.
- Out-of-scope UCAN features in this release: remote DID resolution, network proof fetching, storage layers, caveat-specific attenuation rules beyond caller policy evaluation, registry-backed revocation, replay stores, and non-Ed25519 key types.

## Development

```bash
nix develop -c cargo test --workspace
nix develop -c cargo fmt --manifest-path Cargo.toml -p ucan -p ucan-core --check
nix develop -c cargo clippy --manifest-path Cargo.toml -p ucan -p ucan-core --all-targets --no-deps -- -D warnings -A clippy::cargo-common-metadata
nix flake check
```

The dev shell also includes correctness tooling for follow-up hardening work:

```bash
cargo-mutants --help
cargo fuzz --help
uv --version
```

Hegel-backed property tests use `uv` on first run to install the pinned `hegel-core` helper into `.hegel/`, which is intentionally gitignored.

`vendor/verified-logic` is a checked-in upstream snapshot. Keep it byte-for-byte aligned with upstream and exclude it from this repo's local `fmt`/`clippy` policy; refresh it with the sync script instead of reformatting or relinting it in place.

Refresh the vendored `verified-logic` snapshot from the sibling Trellis source repo with:

```bash
./scripts/sync-verified-logic.sh ../trellis
```

That script imports the committed `HEAD` revision from Trellis, ignores uncommitted sibling changes, and records the imported revision in `vendor/verified-logic-revision.txt`. The Josh path-selection pilot is documented in `docs/verified-logic-josh-sync.md`; `josh/verified-logic.josh` is the canonical filter for the vendored subtree.

## Verification

```bash
verus verus/example_spec.rs
```

Install and run the local pre-commit hook for the cheap Josh sync boundary check:

```bash
pre-commit install
pre-commit run verified-logic-josh-sync-config --all-files
```

The hook runs the focused Nix check only; it validates the Josh filter, verifier unit tests, and revision metadata without requiring a sibling Trellis checkout.

Verified replay-admission transcript aggregation now gates `verify_invocation_with_replay` replay outcomes before allowing or denying replay-aware invocations; nonce-store truth and durability remain caller-owned. The remaining verified follow-up surfaces now cover proof traversal orchestration, compact-token codec structure, core structural validators, ability helper predicates, and backend transcript aggregation without expanding the claim to parser, crypto, backend, storage, or consumer-policy truth.

## License

`ucan-core` and the synchronized `verified-logic` snapshot are `MPL-2.0`; the root `ucan` std shell is `AGPL-3.0-or-later`. Complete texts and the package/vendor map are in [LICENSES](LICENSES) and [docs/licensing.md](docs/licensing.md).

The snapshot records a committed Trellis source revision and preserves its license artifacts. That alignment does not certify UCAN shell behavior, external protocol interoperability, resolver truth, revocation freshness, replay durability, or whole-system correctness. Earlier grants and third-party terms remain intact.

## References

- [Nostr protocol and NIPs](https://github.com/nostr-protocol/nips) — signed-event and request-authentication interoperability reference. UCAN retains token algorithms, DIDs, and authority boundaries.
