## Phase 1: Token model and FCIS boundary

- [ ] Define first-class token claim and capability-set types in `crates/ucan-core`, including pure structural validation plus positive and negative tests for malformed or incomplete claims. [covers=library.token-round-trip library.fcis-boundary library.core-no-std]
- [ ] Keep wildcard ability validation aligned with `verified-logic` while introducing the new core token types so `*` remains valid only as a full segment. [covers=library.fcis-boundary library.delegation-chain]
- [ ] Add shell-side error and orchestration types that keep clocks, proof material, and key resolution explicit instead of relying on ambient state. [covers=library.fcis-boundary]

## Phase 2: Compact-token usability

- [ ] Add shell-owned compact-token encode/decode support and keep any base64url/JSON dependencies out of `ucan-core`. [covers=library.token-round-trip library.fcis-boundary]
- [ ] Add consumer-facing builder/parser/verifier entry points in `ucan` for issuing and verifying `did:key` / Ed25519 tokens end to end, with positive and negative integration tests. [covers=library.token-round-trip library.did-key-ed25519]
- [ ] Add README and example coverage that shows a fresh consumer how to issue, parse, and verify a token through the public API, including documented supported algorithms and limitations. [covers=library.consumer-onboarding]

## Phase 3: Delegation-chain verification

- [ ] Implement proof-chain verification across parent tokens, composing issuer/audience linkage, temporal narrowing, and capability attenuation through `vendor/verified-logic`, with positive integration coverage for valid narrower-child delegation chains. [covers=library.delegation-chain]
- [ ] Add negative tests for broken proof links, malformed compact tokens, signature mismatch, self-delegation, expired parents, and over-broad child capabilities. [covers=library.token-round-trip library.did-key-ed25519 library.delegation-chain]

## Phase 4: Verification and release bar

- [ ] Add a dedicated no-std verification rail for `ucan-core` and a deterministic bridge audit that fails if attenuation, token-time, or signature semantics stop routing through `vendor/verified-logic`. [covers=library.core-no-std library.fcis-boundary]
- [ ] Run the relevant workspace tests and end-to-end library verification rails from the public entry points, then keep final evidence that the documented consumer flow works without private helper calls. [covers=library.token-round-trip library.consumer-onboarding library.delegation-chain]
- [ ] Before Crane-based verification, stage new files with `git add -N`, keep `cargo fmt` and `cargo clippy` scoped to `ucan` and `ucan-core`, and preserve the existing `.gitignore` unignore for `vendor/verified-logic/src/result.rs`.
