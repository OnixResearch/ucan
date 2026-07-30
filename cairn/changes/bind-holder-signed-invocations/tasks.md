## Phase 1: Contract and core

- [ ] [serial] Define the domain-separated canonical holder-request format and field limits in the no-std functional core. r[ucan.holder_invocation.canonical]
- [ ] [serial] Add positive and negative canonical-format tests, including exact length and substitution differences. r[ucan.holder_invocation.core_tests]
- [ ] [serial] Add fixed typed profile, request-binding, nonce, signature, and limits inputs. r[ucan.holder_invocation.typed_binding]

## Phase 2: Injected shell

- [ ] [serial] Add borrowed signing and verification requests without caller-controlled audience truth. r[ucan.holder_invocation.borrowed_verification]
- [ ] [serial] Resolve the verified audience key and verify its holder signature. r[ucan.holder_invocation.holder_proof]
- [ ] [serial] Add explicit operation-profile and nonce/replay admission traits. r[ucan.holder_invocation.injected_boundaries]
- [ ] [serial] Return a private-construction, non-serde, non-clone live success value. r[ucan.holder_invocation.live_success]
- [ ] [serial] Remove the false invoker claim from audience-only compatibility APIs. r[ucan.holder_invocation.compatibility]

## Phase 3: Adversarial tests and integration

- [ ] [parallel] Add direct and delegated holder-signed invocation success tests. r[ucan.holder_invocation.integration_tests]
- [ ] [parallel] Add wrong-holder, replay, nonce, substitution, malformed signature, and oversize tests. r[ucan.holder_invocation.security_tests]
- [ ] [parallel] Add time, proof, revocation, caveat, and unknown-profile denial tests. r[ucan.holder_invocation.security_tests]
- [ ] [serial] Update the invocation example, readiness evidence, public API docs, verified boundaries, and exact non-claims. r[ucan.holder_invocation.documentation]

## Phase 4: Validation and lifecycle

- [ ] [serial] Run focused and workspace tests, all targets, format, strict Clippy, readiness, pre-commit, Nix, and canonical Cairn policy gates. r[ucan.holder_invocation.final_validation]
- [ ] [serial] Sync accepted requirements and archive with `CAIRN_ARCHIVE_DATE=2026-07-30`, then run post-archive validation. r[ucan.holder_invocation.final_validation]
