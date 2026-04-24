## Phase 1: Token model and FCIS boundary

- [x] Define the full `ucan-core` claim model — issuer/audience fields, proof references, capability sets, temporal bounds, and the top-level token-claim composite — and integrate the existing capability-document surface into that model. [covers=library.token-round-trip library.fcis-boundary library.core-no-std]
- [x] Add structural validation for the new core claim model, including required-field failures, malformed-claim rejection, and explicit wildcard-segment alignment tests for whole-segment vs embedded-wildcard cases. [covers=library.token-round-trip library.fcis-boundary library.core-no-std library.delegation-chain]
- [ ] Add named semantic wrapper types in `ucan` plus positive and negative tests so issuer/audience/time/proof roles are not exposed primarily as raw primitives and malformed public API inputs fail deterministically. [covers=library.token-round-trip library.fcis-boundary]
- [ ] Add stage-typed parse/validate/verify result types plus shell-side error/orchestration types so invalid token-workflow states are not representable and clocks, proof material, and key resolution stay explicit. [covers=library.token-round-trip library.fcis-boundary library.delegation-chain]
- [ ] Run an intermediate `ucan-core` no-std compile rail after Phase 1 changes, staging any new files with `git add -N` before Crane-based checks. [covers=library.core-no-std library.fcis-boundary]

## Phase 2: Compact-token usability

- [ ] Add shell-owned compact-token encode/decode support and keep any base64url/JSON dependencies out of `ucan-core`. [covers=library.token-round-trip library.fcis-boundary]
- [ ] Add consumer-facing builder/parser/verifier entry points in `ucan` for issuing and verifying `did:key` / Ed25519 tokens end to end, exposing the staged verification surface through ergonomic public APIs and covering both positive and negative integration cases. [covers=library.token-round-trip library.did-key-ed25519]
- [ ] Add builder-style token/proof test helpers so integration and property tests declare only the preconditions they need instead of inheriting general fixtures. [covers=library.token-round-trip library.delegation-chain]
- [ ] Add README and example coverage that teaches a fresh consumer the architecture boundary first, the end-to-end issue/parse/verify flow second, and proof-chain details third, while documenting supported algorithms and limitations. [covers=library.consumer-onboarding]

## Phase 3: Delegation-chain verification

- [ ] Implement shell-level proof-chain verification across parent tokens, including issuer/audience linkage, self-delegation rejection, temporal narrowing, and capability attenuation through `vendor/verified-logic`, with positive integration coverage for valid narrower-child delegation chains. [covers=library.delegation-chain]
- [ ] Add explicit negative coverage for `r[library.delegation-chain.self-delegation-is-rejected]` so tokens whose issuer and audience are the same fail with a structured authorization error. [covers=library.delegation-chain]
- [ ] Add negative tests for broken proof links, malformed compact tokens, signature mismatch, expired parents, and over-broad child capabilities. [covers=library.token-round-trip library.did-key-ed25519 library.delegation-chain]

## Phase 4: Verification and release bar

- [ ] Add a dedicated no-std verification rail for `ucan-core` and a deterministic bridge audit that fails if attenuation, token-time, signature semantics, or wildcard-segment enforcement stop routing through `vendor/verified-logic`, or if `ucan-core` picks up shell-only concerns such as `std`, JSON, or compact-token codec dependencies. [covers=library.core-no-std library.fcis-boundary]
- [ ] Run the relevant workspace tests and end-to-end library verification rails from the public entry points, then keep final evidence that the documented consumer flow works without private helper calls. [covers=library.token-round-trip library.consumer-onboarding library.delegation-chain]
- [ ] Before Crane-based verification, stage new files with `git add -N`, keep `cargo fmt` and `cargo clippy` scoped to `ucan` and `ucan-core`, and preserve the existing `.gitignore` unignore for `vendor/verified-logic/src/result.rs`.
