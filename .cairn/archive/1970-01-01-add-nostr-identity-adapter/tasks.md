# Tasks: Add a bounded Nostr identity adapter

## Package and protocol core

- [x] [serial] Add the optional `ucan-nostr` package and isolate it from UCAN token paths. r[ucan.nostr_identity_adapter.package_boundary]
- [x] [serial] Add canonical x-only public-key parsing and typed key identities. r[ucan.nostr_identity_adapter.protocol_verification]
- [x] [serial] Add NIP-01 serialization, SHA-256 event identity, and BIP-340 verification. r[ucan.nostr_identity_adapter.protocol_verification]
- [x] [parallel] Add official positive vectors and malformed key, ID, and signature vectors. r[ucan.nostr_identity_adapter.final_validation]

## Authentication profiles

- [x] [serial] Add closed NIP-42, NIP-98, and application challenge profiles. r[ucan.nostr_identity_adapter.authentication_context]
- [x] [serial] Bind audience, purpose, challenge, request, event kind, freshness, and replay inputs. r[ucan.nostr_identity_adapter.authentication_context]
- [x] [parallel] Add wrong-audience, wrong-purpose, stale-event, and replay-denial cases. r[ucan.nostr_identity_adapter.final_validation]

## Output and support boundary

- [x] [serial] Add opaque `VerifiedNostrCredential` construction and redacted public fields. r[ucan.nostr_identity_adapter.credential_boundary]
- [x] [parallel] Add digest-domain, NIP-05, `npub`, secret-field, and authority-promotion rejection cases. r[ucan.nostr_identity_adapter.final_validation]
- [x] [serial] Add the preview surface to Rust, JSON, Nickel, fixture, and documentation projections. r[ucan.nostr_identity_adapter.support_profile]
- [x] [serial] Document consumer-owned relay, signer, clock, replay, subject, and authorization responsibilities. r[ucan.nostr_identity_adapter.support_profile]

## Closeout

- [x] [serial] Run package, workspace, Clippy, support-profile, Cairn, and Nix checks. r[ucan.nostr_identity_adapter.final_validation]
- [x] [serial] Record the exact reviewed Nostr standards, vectors, dependency revision, and license evidence. r[ucan.nostr_identity_adapter.final_validation]
