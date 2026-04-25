# Public API Inventory

## Primary token workflow

Use these entry points for consumer-facing UCAN flows:

- `IssueRequest` plus `issue_token(&request)` for compact token issuance.
- `CompactToken`, `parse_compact_token`, and `validate_decoded_token` for staged parsing and structural validation.
- `VerificationContext`, `VerificationTime`, `KeyResolutionContext`, `ProofCollection`, and `verify_compact_token` for explicit verification inputs.
- `VerifiedToken` and `EffectiveDelegation` for verified issuer, audience, capabilities, proof list, and effective constraints.

## Retained supporting APIs

These helpers remain public as supporting APIs for advanced callers and tests, but README onboarding uses the token workflow above as the primary path:

- `CapabilityDocument`, `load_capability_from_path`, `load_capability_from_reader`, and `write_capability_to_writer`: simple capability document I/O shell helpers.
- `VerifiedCapability`, `attenuation_chain_is_valid`, and `compose_time_window_chain`: verified-logic bridge helpers for focused semantic checks.
- `derive_ed25519_public_key`, `encode_ed25519_did_key`, `sign_ed25519`, and `verify_ed25519_signature`: low-level Ed25519 / `did:key` primitives used by the token workflow.
- `TokenEnvelopeInput`, `validate_token_envelope`, `token_time_valid`, `token_time_valid_at`, and `token_needs_refresh`: lower-level verified envelope and temporal helpers.

## Secret material surface checklist

Current public secret-bearing surfaces are intentionally small:

| Public surface | Secret material | Debug | Display | Serde/export | Error text | Test-failure output |
| --- | --- | --- | --- | --- | --- | --- |
| `Ed25519SigningKey` | Owns Ed25519 seed bytes. | Manual `Debug` prints the type plus `<redacted>` and never prints the byte array. | Not implemented. | Not implemented. | `try_from_slice` reports invalid length only. | `expect_err` and failed assertions use redacted `Debug`. |
| `IssueRequest` | Owns an `Ed25519SigningKey` until signer abstraction work removes raw key ownership from issuance inputs. | Derived `Debug` is safe only through the redacted `Ed25519SigningKey` implementation. | Not implemented. | Not implemented. | No request-specific error text embeds key input. | Failed request assertions use the embedded redacted key formatter. |

Non-secret key material remains printable as before: `Ed25519PublicKey`, `Ed25519VerificationKey`, and `KeyResolutionContext` contain public verification material only.

## Deprecated APIs

No public helpers are hard-deprecated in this change. The helper-only surface is demoted by documentation: new consumers should start with `IssueRequest` and `verify_compact_token`; low-level helpers are retained for integration code that needs direct access to verified primitives.
