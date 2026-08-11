## Phase 1: Support catalog authority

- [x] [serial] Define canonical deterministic bytes for `production_readiness_report()` and a Rust-owned support-catalog identity using BLAKE3. r[ucan.integration_support_profiles.support_catalog]
- [x] [serial] Generate `docs/production-readiness.json` and a compact Nickel support vocabulary from the canonical Rust catalog, with exact freshness checks. r[ucan.integration_support_profiles.support_catalog] r[ucan.integration_support_profiles.freshness]
- [x] [serial] Preserve unsupported and preview surfaces explicitly and require evidence-backed review for every support-level promotion. r[ucan.integration_support_profiles.support_levels]

## Phase 2: Nickel integration profile contract

- [x] [serial] Add shared contracts for exact schema/id, closed support/integration enums, finite named verification limits, unique surface sets, BLAKE3 identities, and non-claim requirements. r[ucan.integration_support_profiles.profile_contract]
- [x] [serial] Define the human-authored integration profile for selected surfaces, explicit preview admission, DID/signature/key classes, caller-owned resolver/proof/revocation/replay/clock/caveat/signer modes, fail-closed behavior, and support-catalog binding. r[ucan.integration_support_profiles.profile_contract]
- [x] [serial] Implement a pure subset-admission core over catalog and profile values, keeping file reads and Nickel invocation in a thin shell. r[ucan.integration_support_profiles.subset_admission] r[ucan.integration_support_profiles.runtime_boundary]

## Phase 3: Fixture manifests and guard replacement

- [x] [serial] Add a Nickel fixture-manifest contract for public fixture identity, required surfaces, expected result class, profile binding, and bounded non-claims. r[ucan.integration_support_profiles.fixture_manifests]
- [x] [serial] Replace the readiness Python guard with a pinned Rust cargo script whose pure core checks catalog/report/docs/profile/fixture parity and whose shell only reads files and renders diagnostics. r[ucan.integration_support_profiles.freshness]
- [x] [parallel] Add positive profiles for the supported caller-wired Ed25519/did:key path and explicitly admitted preview helper use. r[ucan.integration_support_profiles.fixtures]
- [x] [parallel] Add negative profiles for unsupported DID/signature/proof transports, missing resolver/revocation/replay/caveat/signer policy, invalid limits, implicit preview use, stale catalog identity, duplicate surfaces, secret-like fixture fields, and production overclaims. r[ucan.integration_support_profiles.fixtures]

## Phase 4: Documentation and verification

- [x] [serial] Render or check operator documentation from the same support catalog/profile data without treating prose matching as structural parity. r[ucan.integration_support_profiles.freshness]
- [x] [serial] Run profile contract checks, support-catalog/report freshness, focused readiness and limit tests, positive/negative fixture checks, workspace tests, Cairn validation, and proposal/design/tasks gates. r[ucan.integration_support_profiles.fixtures] r[ucan.integration_support_profiles.freshness]
  - PASS: the BLAKE3-bound checker admits two profiles and one public manifest, rejects fourteen negative cases, strict Clippy and workspace tests pass, current Cairn validation and all three gates pass, and pure `nix flake check` reports all checks passed.
- [x] [serial] Document that support-profile conformance does not prove resolver truth, key custody, cryptography, revocation/replay freshness, backend durability, or application authorization completeness. r[ucan.integration_support_profiles.runtime_boundary]
