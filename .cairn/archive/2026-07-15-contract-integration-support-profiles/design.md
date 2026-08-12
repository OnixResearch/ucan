## Context

UCAN already exposes a structured Rust readiness report and machine JSON, but their parity is checked indirectly. Integration choices are described in prose or consumer code: supported DID/signature classes, caller-supplied backends, verification budgets, caveat/replay policy, and whether preview surfaces are allowed.

Nickel is useful for reviewing and merging those choices, provided it cannot redefine what the library actually supports or participate in runtime authorization.

## Decisions

### 1. Rust owns actual support capability

**Choice:** `production_readiness_report()` remains the authoritative capability catalog for this crate version. A deterministic Rust renderer emits the machine support catalog and a compact generated Nickel vocabulary containing stable surface ids and support levels. Both projections bind the canonical Rust catalog bytes with BLAKE3.

**Rationale:** Support claims must follow compiled implementation and evidence, not a separately editable configuration file.

### 2. Nickel owns reviewed consumer profile intent

**Choice:** A human-authored integration profile declares:

- exact profile schema and id;
- bound crate support-catalog identity;
- required support surfaces and explicitly admitted preview surfaces;
- DID method, signing algorithm, and key class selections from the catalog;
- named proof depth/count/input-size limits;
- caller-owned key resolver, proof store, revocation, replay, clock, caveat-policy, and signer-custody modes;
- fail-closed backend behavior; and
- explicit non-claims.

The contract uses closed enums, positive/bounded integers, unique sets, exact BLAKE3 identities, and whole-profile validation.

**Rationale:** Consumers need mergeable reviewable intent without granting Nickel authority over token decisions.

### 3. Profile admission is subset checking

**Choice:** A pure Rust core validates that every required surface is present at an admitted support level, every preview use is explicit, unsupported surfaces are absent, required caller-owned integrations are selected, limits are finite, and non-claims are not weakened. It consumes values only; file reads and Nickel invocation stay in a thin check/generation shell.

**Rationale:** A valid shape is insufficient if the selected capability is unsupported by the bound crate version.

### 4. Fixture manifests carry public identities, not authority

**Choice:** Nickel fixture manifests list fixture id, profile id, public input/reference BLAKE3, expected allow/deny/error class, required support surfaces, and bounded non-claims. Actual compact tokens and cryptographic operations remain Rust-generated test artifacts. Live credentials, private keys, bearer tokens, ambient backend locators, and secret payloads are forbidden.

**Rationale:** Reviewable test coverage is useful; treating a manifest as proof of cryptography or backend truth is not.

### 5. Readiness parity uses a Rust cargo script

**Choice:** Replace or retire `scripts/check-production-readiness.py` with a pinned Rust cargo script decomposed into pure catalog/profile/docs/fixture checks and a thin I/O shell. It verifies exact report generation, contract/export freshness, duplicate ids, support-level transitions, profile subset admission, fixture coverage, and bounded documentation claims.

**Rationale:** The current guard duplicates literals, relies on prose fragments, and does not compare the JSON report structurally with the Rust API.

### 6. Generation is explicit and runtime remains Nickel-free

**Choice:** Nickel is invoked only by explicit profile export/check commands. Runtime issue/parse/verify/invocation APIs never discover or evaluate profiles implicitly. Applications may consume the checked JSON profile in their own shell, but UCAN's deterministic core receives explicit typed inputs as today.

**Rationale:** Configuration convenience must not introduce ambient policy or evaluator authority.

### 7. Legacy lifecycle history is preserved

**Choice:** The native Cairn delta is the forward plan. Existing `openspec/` accepted/archive material remains unchanged until an explicit migration package is reviewed.

**Rationale:** A new configuration contract does not justify rewriting historical lifecycle evidence.

## Risks / Trade-offs

- A support catalog generated from Rust can churn as surfaces are added; BLAKE3 binding makes that review explicit.
- Profiles can be mistaken for authorization policy. Names, docs, and non-claims must consistently call them integration support declarations.
- Consumer-specific resource/ability mapping does not belong in this generic profile and remains downstream-owned.
- A passing profile cannot establish external backend truth or freshness; it only proves that required integration hooks and support classes were declared coherently.
