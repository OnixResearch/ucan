# Public API Inventory

## Primary token workflow

Use these entry points for consumer-facing UCAN flows:

- `issue_token_with_signer(&signer, ...)` for signer-bound compact token issuance without exposing raw secret bytes to the issuer pipeline.
- `IssueRequest::builder()` plus `issue_token(&request)` for compatibility compact token issuance while downstream code migrates to signer-bound issuance. The positional `IssueRequest::new(...)` constructor remains for compatibility, but new code should prefer the named builder.
- `CompactToken`, `parse_compact_token`, and `validate_decoded_token` for staged parsing and structural validation.
- `VerificationContext::builder()`, `VerificationTime`, `KeyResolutionContext`, `ProofCollection`, and `verify_compact_token` for explicit verification inputs. The positional `VerificationContext::new(...)` constructor remains available for existing integrations.
- `RevocationChecker`, `NoRevocations`, `RevocationList`, and `verify_compact_token_with_resolvers_and_revocations` for caller-supplied revocation checks over the leaf token and every proof-chain token. The library provides injection points and deterministic in-memory lists, not registries or network/storage fetchers; `RevocationList` denial membership and duplicate insertion admission route through the verified revocation-set bridge, and `examples/revocation.rs` demonstrates the supported local flow and fail-closed backend errors without logging compact token values.
- `VerifiedToken` and `EffectiveDelegation` for verified issuer, audience, capabilities, proof list, and effective constraints.
- `VerificationTime::try_from_system_time(...)`, `TokenTimeBounds::from_system_time_and_duration(...)`, and `TokenTimeBounds::from_unix_seconds_and_duration(...)` for boundary-only clock conversion. The library still does not read ambient system time.

## Retained supporting APIs

These helpers remain public as supporting APIs for advanced callers and tests, but README onboarding uses the token workflow above as the primary path:

- `CapabilityDocument`, `load_capability_from_path`, `load_capability_from_reader`, and `write_capability_to_writer`: simple capability document I/O shell helpers.
- `VerifiedCapability`, `VerifiedCompactTokenParts`, `VerifiedCompactTokenEnvelope`, `VerifiedVerificationStage`, `VerifiedVerificationStageTranscript`, `VerifiedVerificationStageOutcome`, `VerifiedChainEntry`, `VerifiedInvocationChainRequest`, `VerifiedProofTraversalEntry`, `VerifiedProofTraversalBudget`, `VerifiedProofTraversalTarget`, `VerifiedProofTraversalTranscript`, `VerifiedWebOfTrustUcanAuthorizationRequest`, `VerifiedWebOfTrustAuthorization`, `attenuation_chain_is_valid`, `capability_set_authorizes`, `compact_token_envelope_is_valid`, `verification_stage_transcript_outcome`, `structural_chain_is_valid`, `structural_chain_not_revoked_is_valid`, `invocation_chain_is_authorized`, `proof_traversal_transcript_is_valid`, `web_of_trust_principal_digest`, `web_of_trust_principal_digest_is_valid`, `web_of_trust_ucan_authorization`, `proof_link_is_valid`, `proof_depth_within_budget`, `revocation_reference_is_listed`, `invocation_request_is_authorized`, `receipt_execution_is_valid`, and `compose_time_window_chain`: verified-logic bridge helpers for focused semantic checks, including delegated-capability containment, exact finite capability-set authorization, caller-supplied compact-token framing, caller-supplied verification-stage transcript admission/first-failure reporting, caller-supplied structural chain validity, caller-supplied non-revoked structural chain validity, caller-supplied resolved invocation-chain authorization, shell-produced finite traversal transcript validation, deterministic Web-of-Trust principal digest derivation and raw digest admission, caller-supplied finite Web-of-Trust UCAN authorization, concrete-request ability admission, issuer/audience proof-link admission, proof-depth budget admission, finite revocation-set membership, concrete invocation admission, deterministic receipt executor/timestamp checks, and temporal intersection. The capability-set bridge uses exact ability equality and resource byte-prefix refinement; it does not perform wildcard ability subsumption or replace shell token/effective-delegation authorization. The verification-stage transcript bridge consumes caller-supplied public booleans only; it does not perform parsing, decoding, hashing, cryptography, proof fetching, revocation querying, caveat policy evaluation, or backend validation. The WOT principal digest bridge derives fixed-width public principal bytes and admits raw digest bytes only through vendored verified-logic; it does not resolve identities, fetch or validate trust records, check revocations, authorize UCANs, access storage/network backends, or read ambient clocks. The structural/invocation/proof-traversal/Web-of-Trust authorization bridges consume resolved public fields, aligned caller-provided proof-reference bytes, finite caller-provided revoked-reference bytes, explicit invocation authorization-reference bytes, caller-provided signature-valid flags, finite root/attestation/revocation data, and explicit caller-owned ability/caveat/DID-CID facts; they do not perform proof resolution, compact-token verification, DID/CID decoding, key lookup, cryptographic signature verification, revocation backend/freshness checks, caveat policy evaluation, wildcard containment replacement, networking, persistence, replay checks, or ambient clock reads.
- `Ed25519InMemorySigner`, `TokenSigner`, `SignerSignature`, `SignerError`, and `SignerResult`: signer-bound issuance primitives for callers that need explicit key-custody boundaries.
- `derive_ed25519_public_key`, `encode_ed25519_did_key`, `decode_did_key`, `sign_ed25519`, and `verify_ed25519_signature`: low-level Ed25519 / structural `did:key` primitives used by the token workflow. `decode_did_key` returns public decoded bytes and codec through the vendored verifier; it does not perform DID resolution, key lookup, signature verification, trust checks, proof fetching, persistence, networking, or ambient clock reads.
- `TokenEnvelopeInput`, `validate_token_envelope`, `token_time_valid`, `token_time_valid_at`, and `token_needs_refresh`: lower-level verified envelope and temporal helpers.
- `typed_caveat_is_satisfied` and `typed_caveat_set_is_satisfied`: opt-in finite typed caveat helpers for callers that explicitly use `VerifiedWebOfTrustCaveat` and explicit context. These do not interpret arbitrary opaque shell `CaveatDocument` payloads or change `CaveatPolicySet` fail-closed behavior.
- `web_of_trust_attestation_payload_bytes`, `web_of_trust_attestation_signature_is_valid`, `web_of_trust_attestation_is_active_at`, `web_of_trust_revocation_payload_bytes`, `web_of_trust_revocation_signature_is_valid`, `web_of_trust_revocation_matches_attestation`, `web_of_trust_revocation_is_effective_at`, and `web_of_trust_threshold_accepts`: lower-level finite WOT evidence and policy helpers. They operate on caller-supplied public evidence and explicit time, below `web_of_trust_ucan_authorization`, and do not resolve identities, fetch evidence, consult registries, sign, persist state, or read ambient clocks.

## Verified boundary notes

`docs/verified-boundaries.md` records the current audit. Compact-token exact byte framing/signing-input construction over already-split encoded parts is routed through `compact_token_envelope_is_valid`; `verification_stage_transcript_outcome` verifies finite caller/shell-supplied stage admission and first-failure ordering. Compact splitting, base64url decoding, JSON serde, proof-reference hashing, Ed25519 cryptography, live recursive proof traversal/backends, backend error freshness, and opaque caveat-preserving attenuation payload semantics remain shell-local tested boundaries. Finite proof traversal transcript consistency is verified for already-resolved caller/shell-supplied data, including explicit topologically ordered multi-parent DAG transcripts; live verification now emits/checks DAG transcripts for no-proof tokens, exact or wildcard-ability single-parent linear proof chains, and representable multi-parent proof graphs.

## Secret material surface checklist

Current public secret-bearing surfaces are intentionally small:

| Public surface | Secret material | Debug | Display | Serde/export | Error text | Test-failure output |
| --- | --- | --- | --- | --- | --- | --- |
| `Ed25519SigningKey` | Owns Ed25519 seed bytes. | Manual `Debug` prints the type plus `<redacted>` and never prints the byte array. | Not implemented. | Not implemented. | `try_from_slice` reports invalid length only. | `expect_err` and failed assertions use redacted `Debug`. |
| `IssueRequest` | Owns an `Ed25519SigningKey` for compatibility issuance. New code should prefer signer-bound issuance. | Derived `Debug` is safe only through the redacted `Ed25519SigningKey` implementation. | Not implemented. | Not implemented. | No request-specific error text embeds key input. | Failed request assertions use the embedded redacted key formatter. |
| `Ed25519InMemorySigner` | Owns Ed25519 seed bytes behind the signer abstraction. | Manual `Debug` prints the type plus `<redacted>` and never prints the byte array. | Not implemented. | Not implemented. | Constructor errors report invalid length only; signer-output errors report algorithms, lengths, or issuer mismatch only. | Failed signer assertions use redacted `Debug`. |

Non-secret key material remains printable as before: `Ed25519PublicKey`, `Ed25519VerificationKey`, `KeyResolutionContext`, and `SignerSignature` contain public verification/signature material only.

## Trait implementation matrix

The public API intentionally separates non-secret textual wrappers from secret-bearing custody types:

| Public surface | `Display` | `FromStr` / `TryFrom` | Serde string round-trip | Notes |
| --- | --- | --- | --- | --- |
| `CompactToken` | Yes | Yes | Yes | Credential-like; serialization is available for protocol integration, but examples and docs should avoid logging token values. |
| `IssuerDid` | Yes | Yes | Yes | Validates through the same DID admission path as token issuance and verification. |
| `AudienceDid` | Yes | Yes | Yes | Validates through the same DID admission path as token issuance and verification. |
| `CapabilitySet` | No | No | No | Built through capability constructors so resource/ability/caveat validation remains explicit. |
| `ProofCollection` | No | No | No | Carries proof tokens; callers should keep proof transport explicit. |
| `Ed25519SigningKey` | No | No | No | Secret-bearing; only redacted `Debug` is implemented. |
| `Ed25519InMemorySigner` | No | No | No | Secret-bearing signer custody type; only redacted `Debug` is implemented. |

Builder finalization returns `BuilderError::MissingField { field }`, so callers can present deterministic configuration errors without scraping string text. System-time conversion helpers return `TimeConversionError` instead of panicking or reading the clock internally.

## Signer construction decision

`Ed25519InMemorySigner::from_seed_bytes` and `try_from_slice` preserve deterministic test-seed and compatibility construction without adding RNG or `zeroize` dependencies in this slice. Production integrations that keep keys outside process memory should implement `TokenSigner` directly; built-in KMS/HSM, RNG-backed generation, and zeroizing storage remain outside this change.

## Deprecated APIs

No public helpers are hard-deprecated in this change. The helper-only surface is demoted by documentation: new consumers should start with the request/context builders and `verify_compact_token`; low-level helpers are retained for integration code that needs direct access to verified primitives.
