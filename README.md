# ucan

## Architecture

- `crates/ucan-core`: `#![no_std]` functional core. Keep parsing, structural validation, and other deterministic UCAN logic here.
- `ucan` (repo root): `std` shell. Keep file I/O, process integration, networking, clocks, crypto, and other side effects here.
- `vendor/verified-logic`: vendored snapshot of the verified library used by the `std` shell for UCAN ability subsumption, attenuation checks, proof-chain issuer/audience linkage, proof-depth budget admission, finite revocation-set membership, concrete invocation admission, deterministic receipt executor/timestamp checks, token-time validation, Ed25519 signing/verification, and `did:key` encoding.

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

For invocation-shaped checks, `verify_invocation` first verifies the compact
token, then authorizes the requested resource/ability with the supplied caveat
policies and returns either `InvocationAllowed` context or a structured denial.

Invocation verification composes token/proof verification, caveat-aware authorization, and effective constraints. For concrete matched capabilities, the admitted request is cross-checked through the `invocation_request_is_authorized` verified invocation bridge; wildcard matched capabilities continue to use `VerifiedCapability` containment so wildcard delegation and caveat-denial semantics are not weakened. Allowed invocation results expose the token audience as the invoker exercising the delegated capability. For caller-owned receipt records, `receipt_execution_is_valid` exposes the verified receipt executor/timestamp check without adding receipt storage, replay tracking, signing, networking, or ambient clock reads.

```bash
cargo run --example invocation
```

## Proof-chain delegation

Proof material is explicit. A child token carries BLAKE3 proof references in `prf`; callers may keep using `ProofCollection`, or inject their own synchronous `ProofStore` with `verify_compact_token_with_resolvers`. Verification checks each parent signature, proof-depth budget admission through `proof_depth_within_budget`, issuer/audience linkage through the `proof_link_is_valid` verified-chain bridge, temporal narrowing, capability attenuation, and self-delegation rejection before returning the effective delegation constraints.

`KeyResolver`, `ProofStore`, and `RevocationChecker` are std-shell injection points only: the crate does not provide built-in HTTP, IPFS, database, filesystem, registry, or ambient global lookup. `KeyResolutionContext` implements `KeyResolver`, `ProofCollection` implements `ProofStore`, and `RevocationList` implements `RevocationChecker` for deterministic in-memory verification; `RevocationList` denial membership and duplicate insertion admission use the verified revocation-set bridge over caller-provided proof-reference bytes. Use `verify_compact_token_with_resolvers_and_revocations` when the application has revocation state; it checks the leaf token and every recursively resolved proof token by `ProofReference` before verification can succeed, and `RevocationError` backend failures fail closed as `TokenError::Revocation`. `VerificationLimits::default()` bounds recursion with visible defaults for maximum proof depth, maximum resolved proof count, and maximum serialized compact-token byte length; use `VerificationContext::with_limits` or `verify_compact_token_with_resolvers` to override them. To reject oversized caller input before constructing a `CompactToken`, call `verify_compact_token_str`.

```bash
cargo run --example proof_chain
cargo run --example proof_store
cargo run --example revocation
```

The verified result exposes the issuer, audience, direct capability set, direct proof list, and effective delegation window/capabilities so callers do not need to recompute chain constraints.

## Support limits

- Production-oriented issuance should use `TokenSigner` / `issue_token_with_signer`; `IssueRequest` remains as a compatibility wrapper around the in-memory Ed25519 signer path.
- Supported DID methods: `did:key` for Ed25519 public keys.
- Supported signing algorithms: Ed25519 compact-token signatures with `alg = "EdDSA"`.
- Proof-loading model: caller-supplied proof tokens only; the library does not fetch proofs from storage or the network.
- Revocation model: caller-supplied `RevocationChecker` values can deny the leaf token or any proof-chain token by `ProofReference`; revocation registries, credential formats, replay stores, persistence, and remote fetches remain application-owned.
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

Refresh the vendored `verified-logic` snapshot from the sibling source repo with:

```bash
./scripts/sync-verified-logic.sh
```

That script imports the committed `HEAD` revision from `../verified-logic`, ignores uncommitted sibling changes, and records the imported revision in `vendor/verified-logic-revision.txt`.

## Verification

```bash
verus verus/example_spec.rs
```
