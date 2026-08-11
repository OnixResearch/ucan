## Why

`ucan-core::token::TimeBounds::new` is a security-relevant functional-core boundary: it admits a token window only when `nbf < exp` and preserves both values for later verification. The function is safe, sequential, allocation-free, dependency-light, and does not touch cryptography, parsing, clocks, storage, or networking. That makes it the smallest credible downstream Aeneas pilot after Octet proves the provider path.

The existing tests and vendored verified-logic time predicates remain valuable, but they do not directly establish that this exact UCAN constructor and its returned getters implement the intended relation. A scoped Aeneas/Lean theorem can check the compiled core path without moving proof tooling into runtime behavior.

## What Changes

- Add an opt-in Octet Aeneas/Lean proof rail for the exact `crates/ucan-core/src/token.rs::TimeBounds::new` implementation and getter functions.
- Require the reviewed Octet provider/effective-extraction/adequacy contracts and Valence Aeneas translation-chain profile before any UCAN proof status is promoted.
- Bind measured Aeneas `translation.json` rows from the exact selected LLBC items to generated Lean declarations/files while keeping `def_id` within-run only.
- Prove in Lean that construction succeeds exactly when `not_before_seconds < expires_at_seconds`, fails otherwise with `InvalidTimeBounds`, and preserves accepted values through both getters.
- Keep Aeneas-generated definitions separate from hand-maintained theorem source and bind source, effective extraction options, LLBC, translation manifest, generated Lean, approved theorem statement/requirement/claim class, complete trust closure, toolchain, budget, and receipt identities.
- Add positive boundary cases and negative evidence for equality/reversed bounds, an intentionally false theorem, a vacuous `True` theorem, partial/errorful extraction, borrow-check bypass, stale manifest/generated output, source drift, trust/theorem mismatch, budget exhaustion, and overclaiming receipts.
- Record a deterministic blocked feasibility result if exact source cannot be translated; do not add a copied constructor or weaken the theorem.

## Impact

- **Core runtime**: no runtime Aeneas, Lean, Nickel, filesystem, process, clock, network, or proof-receipt dependency is introduced.
- **Proof surface**: one exact constructor and two getters; capability parsing, token codecs, signatures, proof traversal, caveats, revocation, replay, and authorization remain outside the claim.
- **Evidence**: UCAN-owned theorem mapping and Octet receipt, with Valence identity/linkage validation and existing generic Cairn lifecycle consumption.
- **Documentation**: add the proof to verified-boundary documentation only when exact-source positive and negative evidence passes; a blocked result remains documented as a blocker.
- **Testing**: exact-source selection, effective extraction and manifest checks, theorem checks, false-theorem and vacuity rejection, boundary inputs, trust-closure and stage tampering, budget outcomes, ordinary workspace tests, and Cairn gates.
- **Claims**: a passing receipt proves only the declared constructor/getter properties over exact bound source and model inputs. It does not prove token validity, clock correctness, parser or cryptographic correctness, proof-chain soundness, authorization completeness, UCAN interoperability, or whole-system security.
