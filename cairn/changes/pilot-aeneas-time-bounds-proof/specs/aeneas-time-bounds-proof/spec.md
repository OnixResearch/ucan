# Aeneas Time Bounds Proof Specification

## ADDED Requirements

### Requirement: UCAN consumes reviewed proof providers

r[ucan.aeneas_time_bounds.provider_dependencies] UCAN MUST consume exact reviewed Octet `aeneas-lean` provider, effective extraction profile, theorem-adequacy policy, compatibility receipt, and Valence Aeneas translation-chain profile identities and MUST NOT vendor, reconstruct, or ambiently resolve their Aeneas, Charon, OCaml, Lean, receipt, or evidence-policy implementations.

#### Scenario: Reviewed provider chain is available

- GIVEN UCAN declares exact Octet and Valence revisions, package/profile identities, and supported receipt schemas
- WHEN proof preflight runs
- THEN every provider identity MUST match before source translation begins.

#### Scenario: Provider chain drifts

- GIVEN an Octet package/profile, Valence profile, or receipt schema differs from the reviewed declaration
- WHEN preflight runs
- THEN the pilot MUST fail before execution and MUST NOT fall back to ambient tools.

### Requirement: Time bounds proof targets exact core source

r[ucan.aeneas_time_bounds.exact_source] The pilot MUST target the compiled `TimeBounds::new`, `not_before_seconds`, and `expires_at_seconds` items defined in `crates/ucan-core/src/token.rs` by exact source and item identities and MUST reject copied, simplified, non-const, or otherwise rewritten proof-only implementations.

#### Scenario: Exact core items are selected

- GIVEN Charon identifies the selected items as originating from the measured UCAN source spans, effective extraction options are reviewed and non-errorful, and `translation.json` links the selected LLBC items to generated Lean declarations/files
- WHEN source binding is validated
- THEN the pilot MAY continue with BLAKE3-bound durable identities while retaining manifest `def_id` values only as within-run join keys.

#### Scenario: Simplified proof fixture is supplied

- GIVEN a separate constructor omits `const`, changes the error representation, or duplicates equivalent-looking logic
- WHEN source binding is validated
- THEN the pilot MUST reject it as evidence for the production `TimeBounds` API.

### Requirement: Translation manifest linkage is exact

r[ucan.aeneas_time_bounds.translation_manifest] UCAN MUST bind measured Aeneas `translation.json` rows from each selected LLBC item to generated Lean declarations/files and preserve source span, opacity, failure/divergence, recursion, and loop-parent metadata without using `def_id` as durable identity.

#### Scenario: Current-run item mapping passes

- GIVEN each constructor/getter LLBC item, manifest row, generated declaration, and generated-file identity matches the Octet receipt
- WHEN manifest validation runs
- THEN UCAN MUST preserve the mapping in deterministic pilot evidence.

#### Scenario: Manifest or declaration ID drifts

- GIVEN a manifest is stale, maps a selected item to a different generated declaration/file, omits required metadata, or reuses a `def_id` from another run/profile
- WHEN validation runs
- THEN the pilot MUST fail before theorem evidence is admitted.

### Requirement: Exact-source feasibility is explicit

r[ucan.aeneas_time_bounds.feasibility] UCAN MUST classify exact-source Aeneas feasibility as supported or blocked from typed stage evidence including the effective extraction contract, LLBC error status, target metadata, translation manifest, and generated-file inventory, and MUST distinguish unsupported source constructs from package, process, environment, or budget failures.

#### Scenario: Exact items translate

- GIVEN the reviewed provider translates the exact constructor and getters with all required stage identities
- WHEN feasibility evaluation runs
- THEN it MUST report supported and bind source, LLBC, generated-model, provider, and assumption identities.

#### Scenario: Exact items use an unsupported construct

- GIVEN the reviewed provider cannot translate the exact `const fn`, `Result`, error enum, struct construction, or getter representation
- WHEN feasibility evaluation runs
- THEN it MUST report blocked with the exact stage, stable diagnostic class, bounded diagnostic artifact identity, unsupported construct, and next smallest check.

#### Scenario: Tool setup fails

- GIVEN execution fails before a language-support decision
- WHEN feasibility evaluation runs
- THEN it MUST report tool failure rather than asserting an Aeneas source-language limitation.

### Requirement: Time bounds properties are exact

r[ucan.aeneas_time_bounds.properties] When feasible, the Lean theorem layer MUST prove over the exact generated model and approved statement/requirement/claim identities that construction succeeds if and only if `not_before_seconds < expires_at_seconds`, equality and reversed ordering return the typed `InvalidTimeBounds` error carrying the inputs, and successful getters preserve both accepted values.

#### Scenario: Strictly ordered bounds succeed

- GIVEN arbitrary `u64` bounds with `not_before_seconds < expires_at_seconds`
- WHEN the generated constructor is evaluated in the checked Lean theorem
- THEN the result MUST be successful and both getters MUST equal the original inputs.

#### Scenario: Equal or reversed bounds fail

- GIVEN `not_before_seconds >= expires_at_seconds`
- WHEN the generated constructor is evaluated in the checked Lean theorem
- THEN it MUST return the modeled `InvalidTimeBounds` result with the original input values.

#### Scenario: Rust and Lean models differ

- GIVEN theorem mapping changes the approved statement hash, requirement ID, claim class, integer width, ordering, error fields, result variant, quantification, or a trust input
- WHEN theorem-map validation runs
- THEN it MUST fail and MUST NOT infer the intended UCAN property.

### Requirement: Theorem adequacy and trust closure are required

r[ucan.aeneas_time_bounds.theorem_adequacy] UCAN MUST reject property promotion unless each selected theorem matches its approved statement BLAKE3, requirement ID, and claim class, has a complete declared model/assumption/axiom/opaque-definition closure, contains no `sorry` or `admit`, and is non-vacuous for the declared constructor/getter property.

#### Scenario: Adequate theorem proceeds

- GIVEN the theorem matches its approved property identity and complete trust closure and passes deterministic adequacy checks
- WHEN theorem admission runs
- THEN it MAY proceed to Lean checking and evidence-chain admission.

#### Scenario: Vacuous or trust-incomplete theorem is rejected

- GIVEN a `True`-style statement is offered for the constructor/getter claim, or a theorem has `sorry`, `admit`, an undeclared axiom/model/opaque definition, or mismatched approval identity
- WHEN theorem admission runs
- THEN UCAN MUST reject property promotion even if Lean accepts the encoded source.

### Requirement: Generated model and theorem sources remain separate

r[ucan.aeneas_time_bounds.generated_boundary] UCAN MUST keep Aeneas-generated Lean definitions separate from hand-maintained theorem source and MUST validate source, effective extraction contract, LLBC, `translation.json`, generated-file inventory, Aeneas invocation, generated bytes, theorem bytes, and Lean package/toolchain freshness before accepting theorem evidence.

#### Scenario: Fresh model is checked

- GIVEN every generation input and output matches the receipt and maintained theorem source imports the generated model
- WHEN freshness validation runs
- THEN theorem checking MAY proceed.

#### Scenario: Model is stale or theorem source is overwritten

- GIVEN generated bytes are stale, manually changed, unbound, or generated into the maintained theorem path
- WHEN freshness or layout validation runs
- THEN the proof rail MUST fail before reporting a property result.

### Requirement: UCAN proof evidence composes Octet and Valence

r[ucan.aeneas_time_bounds.evidence_chain] UCAN MUST report property evidence only when its theorem map and Octet Aeneas receipt pass, Octet artifact verification succeeds, and Valence validates the complete translation chain with matching source, extraction contract, LLBC, translation manifest, generated files, theorem approval/adequacy/trust closure, resource-budget identity, roles, receipt, and non-claims.

#### Scenario: Complete evidence chain passes

- GIVEN every UCAN, Octet, and Valence identity and status matches
- WHEN evidence admission runs
- THEN UCAN MAY report the scoped time-bounds theorem properties.

#### Scenario: Upstream or local evidence is stale

- GIVEN source, LLBC, generated Lean, theorem, assumption, provider, Octet receipt, artifact-verification result, or Valence chain identity is missing or mismatched
- WHEN evidence admission runs
- THEN UCAN MUST fail closed and MUST NOT preserve a prior passing property status.

### Requirement: Negative proof paths are maintained

r[ucan.aeneas_time_bounds.negative_evidence] When exact-source feasibility is supported, UCAN MUST maintain intentionally false and vacuous `True` Lean theorems outside positive selection. In both supported and blocked outcomes, UCAN MUST maintain applicable negative fixtures for invalid bounds, extraction-policy drift, source/manifest/intermediate-stage drift, theorem approval or trust-closure mismatch, budget failure, receipt mismatch, and overclaiming evidence.

#### Scenario: False and vacuous theorems are rejected at distinct gates

- GIVEN exact-source feasibility is supported and the intentionally false theorem and vacuous `True` theorem are evaluated with the exact provider/policy used by the positive pilot
- WHEN the negative rail runs
- THEN Lean MUST reject the false theorem, adequacy admission MUST reject the vacuous theorem, and no UCAN, Octet, or Valence artifact may report either as passed property evidence.

#### Scenario: Negative fixture enters positive selection

- GIVEN positive selection would include a false theorem or tampered fixture
- WHEN selection validation runs
- THEN the rail MUST fail before publishing positive evidence.

### Requirement: Proof campaign resources are bounded

r[ucan.aeneas_time_bounds.resource_budget] UCAN MUST bind named Octet provider execution, log, and retained-artifact budget identities and MUST classify exhaustion without converting it into a source-language support or theorem result.

#### Scenario: Proof completes within reviewed budgets

- GIVEN every stage remains within the selected provider budget profile
- WHEN the pilot completes
- THEN its receipt MUST record the budget identity and bounded outcome.

#### Scenario: Resource budget is exhausted

- GIVEN a stage exceeds a named time, log, memory, or retained-artifact limit
- WHEN the shell reports the observation
- THEN UCAN MUST report a budget failure and MUST NOT claim unsupported source or theorem failure.

### Requirement: Proof tooling does not enter runtime

r[ucan.aeneas_time_bounds.runtime_boundary] The Aeneas pilot MUST remain an explicit development or CI evidence lane, and `ucan-core` plus runtime issue, parse, verify, invocation, caveat, revocation, replay, and authorization APIs MUST NOT discover or execute proof profiles, load proof receipts, or depend on Aeneas, Lean, Nickel runtime evaluation, process, filesystem, clock, or network effects.

#### Scenario: Normal UCAN build runs

- GIVEN a consumer builds or uses UCAN without selecting proof evidence lanes
- WHEN normal compile, test, issuance, or verification paths run
- THEN Aeneas/Lean packages and receipts MUST NOT be required.

#### Scenario: Proof receipt is present at runtime

- GIVEN proof artifacts exist beside a consumer build
- WHEN runtime APIs execute
- THEN they MUST ignore those artifacts unless an explicit external operator evidence path consumes them outside UCAN runtime semantics.

### Requirement: Time bounds proof claims remain bounded

r[ucan.aeneas_time_bounds.claim_boundary] UCAN documentation and evidence MUST scope any passing result to the exact constructor/getter properties and MUST NOT promote integration-support levels or claim token validity, ambient clock correctness, parser/codec correctness, cryptographic correctness, proof-chain soundness, caveat/revocation/replay freshness, authorization completeness, interoperability, whole-program correctness, or whole-system security.

#### Scenario: Passing proof is documented

- GIVEN the exact-source evidence chain passes
- WHEN verified-boundary documentation is updated
- THEN it MUST name the exact functions, properties, types, assumptions, source/model/toolchain identities, receipts, and non-claims.

#### Scenario: Feasibility is blocked

- GIVEN exact-source translation is blocked
- WHEN status is documented
- THEN UCAN MUST record the exact blocker and next check and MUST NOT claim that the time-bounds properties were proved by Aeneas.

### Requirement: Final validation accepts proof or an exact blocker

r[ucan.aeneas_time_bounds.final_validation] Before archive, the change MUST produce either a verified exact-source positive/false/vacuous theorem matrix or a deterministic blocked feasibility receipt with the smallest remaining discriminating check, and all extraction-contract, translation-manifest, adequacy/trust, resource-budget, runtime-boundary, workspace, Octet, Valence, and Cairn checks relevant to the achieved outcome MUST pass.

#### Scenario: Exact-source theorem succeeds

- GIVEN feasibility is supported and implementation is complete
- WHEN final validation runs
- THEN valid strict-order cases and getter preservation MUST pass, equal/reversed cases and the false theorem MUST reject as declared, tamper fixtures MUST fail, and Octet/Valence evidence checks MUST pass.

#### Scenario: Exact-source theorem remains blocked

- GIVEN a reviewed provider boundary prevents theorem checking over the exact core items
- WHEN final validation runs
- THEN the blocked receipt, tool identities, bounded diagnostics, unsupported boundary, and next check MUST be durable and no completion evidence may claim Aeneas proof success.
