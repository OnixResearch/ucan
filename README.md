# ucan

## Architecture

- `crates/ucan-core`: `#![no_std]` functional core. Keep parsing, structural validation, and other deterministic UCAN logic here.
- `ucan` (repo root): `std` shell. Keep file I/O, process integration, networking, clocks, crypto, and other side effects here.
- `vendor/verified-logic`: vendored snapshot of the verified library used by the `std` shell for UCAN ability subsumption, attenuation checks, token-time validation, Ed25519 signing/verification, and `did:key` encoding.

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
# Ok::<(), Box<dyn std::error::Error>>(())
```

Run the same happy path as a normal example:

```bash
cargo run --example issue_and_verify
```

## Proof-chain delegation

Proof material is explicit. A child token carries BLAKE3 proof references in `prf`; callers provide the actual parent compact tokens through `ProofCollection`. Verification checks each parent signature, issuer/audience linkage, temporal narrowing, capability attenuation, and self-delegation rejection before returning the effective delegation constraints.

```bash
cargo run --example proof_chain
```

The verified result exposes the issuer, audience, direct capability set, direct proof list, and effective delegation window/capabilities so callers do not need to recompute chain constraints.

## Support limits

- Production-oriented issuance should use `TokenSigner` / `issue_token_with_signer`; `IssueRequest` remains as a compatibility wrapper around the in-memory Ed25519 signer path.
- Supported DID methods: `did:key` for Ed25519 public keys.
- Supported signing algorithms: Ed25519 compact-token signatures with `alg = "EdDSA"`.
- Proof-loading model: caller-supplied proof tokens only; the library does not fetch proofs from storage or the network.
- Out-of-scope UCAN features in this release: revocation registries, remote DID resolution, network proof fetching, storage layers, invocation-specific caveats, and non-Ed25519 key types.

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
