# Public API Inventory

## Primary token workflow

Use these entry points for consumer-facing UCAN flows:

- `issue_token_with_signer(&signer, ...)` for signer-bound compact token issuance without exposing raw secret bytes to the issuer pipeline.
- `IssueRequest` plus `issue_token(&request)` for compatibility compact token issuance while downstream code migrates to signer-bound issuance.
- `CompactToken`, `parse_compact_token`, and `validate_decoded_token` for staged parsing and structural validation.
- `VerificationContext`, `VerificationTime`, `KeyResolutionContext`, `ProofCollection`, and `verify_compact_token` for explicit verification inputs.
- `VerifiedToken` and `EffectiveDelegation` for verified issuer, audience, capabilities, proof list, and effective constraints.

## Retained supporting APIs

These helpers remain public as supporting APIs for advanced callers and tests, but README onboarding uses the token workflow above as the primary path:

- `CapabilityDocument`, `load_capability_from_path`, `load_capability_from_reader`, and `write_capability_to_writer`: simple capability document I/O shell helpers.
- `VerifiedCapability`, `attenuation_chain_is_valid`, and `compose_time_window_chain`: verified-logic bridge helpers for focused semantic checks.
- `Ed25519InMemorySigner`, `TokenSigner`, `SignerSignature`, `SignerError`, and `SignerResult`: signer-bound issuance primitives for callers that need explicit key-custody boundaries.
- `derive_ed25519_public_key`, `encode_ed25519_did_key`, `sign_ed25519`, and `verify_ed25519_signature`: low-level Ed25519 / `did:key` primitives used by the token workflow.
- `TokenEnvelopeInput`, `validate_token_envelope`, `token_time_valid`, `token_time_valid_at`, and `token_needs_refresh`: lower-level verified envelope and temporal helpers.

## Secret material surface checklist

Current public secret-bearing surfaces are intentionally small:

| Public surface | Secret material | Debug | Display | Serde/export | Error text | Test-failure output |
| --- | --- | --- | --- | --- | --- | --- |
| `Ed25519SigningKey` | Owns Ed25519 seed bytes. | Manual `Debug` prints the type plus `<redacted>` and never prints the byte array. | Not implemented. | Not implemented. | `try_from_slice` reports invalid length only. | `expect_err` and failed assertions use redacted `Debug`. |
| `IssueRequest` | Owns an `Ed25519SigningKey` for compatibility issuance. New code should prefer signer-bound issuance. | Derived `Debug` is safe only through the redacted `Ed25519SigningKey` implementation. | Not implemented. | Not implemented. | No request-specific error text embeds key input. | Failed request assertions use the embedded redacted key formatter. |
| `Ed25519InMemorySigner` | Owns Ed25519 seed bytes behind the signer abstraction. | Manual `Debug` prints the type plus `<redacted>` and never prints the byte array. | Not implemented. | Not implemented. | Constructor errors report invalid length only; signer-output errors report algorithms, lengths, or issuer mismatch only. | Failed signer assertions use redacted `Debug`. |

Non-secret key material remains printable as before: `Ed25519PublicKey`, `Ed25519VerificationKey`, `KeyResolutionContext`, and `SignerSignature` contain public verification/signature material only.

## Signer construction decision

`Ed25519InMemorySigner::from_seed_bytes` and `try_from_slice` preserve deterministic test-seed and compatibility construction without adding RNG or `zeroize` dependencies in this slice. Production integrations that keep keys outside process memory should implement `TokenSigner` directly; built-in KMS/HSM, RNG-backed generation, and zeroizing storage remain outside this change.

## Deprecated APIs

No public helpers are hard-deprecated in this change. The helper-only surface is demoted by documentation: new consumers should start with `IssueRequest` and `verify_compact_token`; low-level helpers are retained for integration code that needs direct access to verified primitives.
