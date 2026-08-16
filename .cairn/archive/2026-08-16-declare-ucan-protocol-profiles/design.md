## Context

The existing shell accepts three unpadded base64url segments, a JSON `JWT` header with `EdDSA`, and claims named `iss`, `aud`, `att`, `prf`, `exp`, and `nbf`. It uses BLAKE3 proof references and this repository's resource and ability model.

The reviewed final UCAN `1.0.0` overview at `ucan-wg/spec@9955aa1fb7b32897f80b57651f4ee8b22ebf35a7` requires DAG-CBOR signing, a Varsig envelope, CIDv1 with SHA-256, typed payload tags, a subject, slash commands, arguments or policy, a nonce, 53-bit time admission, and nullable expiry. The required sub-specifications are pinned at:

- Delegation: `1cb32dbc9d4d15a23bf9844a02515d760b81e816`
- Invocation: `0f4c11325af6aca298b565cc19e90009d10e0197`

The upstream `rs-ucan` reference is pinned at `59ff9b9c8479b41072688d36709eb762ac9d8ecd`. Its README declares `1.0.0-rc.1` and warns that the code is unaudited. It is an implementation reference, not protocol authority.

## Decisions

### Decision: Use closed nominal protocol profiles

**Choice:** Add a typed profile ID and catalog with at least these entries:

- `onix-compact-ed25519-v1`: the existing local compact-token behavior.
- `ucan-wg-1.0.0`: the final upstream target profile, initially unsupported.

No profile ID implies another profile. Unknown IDs fail closed.

**Rationale:** Nominal IDs prevent structurally similar credentials from crossing incompatible semantic boundaries.

### Decision: Keep the current API byte-compatible

**Choice:** Existing issue, parse, verify, proof, and authorization functions remain bound to `onix-compact-ed25519-v1`. The implementation must not add a claim to current token bytes only to carry a profile ID.

**Rationale:** Adding an unreviewed field would change signatures and token identity. Profile-aware APIs can be explicit without rewriting existing bytes.

### Decision: Let Rust own support and Nickel own reviewed intent

**Choice:** Extend the Rust readiness catalog with protocol-profile facts. Extend the Nickel integration profile contract with an exact protocol-profile field bound to the same BLAKE3 catalog identity.

**Rationale:** Rust owns implemented behavior. Nickel can select an implemented profile but cannot promote unsupported protocol behavior.

### Decision: Inventory upstream fixtures before implementation

**Choice:** Import or mirror only the pinned `fixtures/1.0.0` files through a deterministic script or checked manifest. Record source URL, Git revision, path, Git blob identity, BLAKE3 byte identity, fixture class, and expected local status.

The initial inventory includes `delegation.json`, `invocation.json`, and `policy.json`. Tests must include one valid manifest and malformed, stale-revision, path-traversal, duplicate, and hash-mismatch manifests.

**Rationale:** Reproducible fixture identity is valuable even before support exists. The report must not convert presence into conformance.

### Decision: Produce a bounded conformance matrix

**Choice:** The checker classifies each case as `pass`, `fail`, `unsupported`, or `untested`. It records the exact profile, implementation revision, upstream revision, fixture BLAKE3, stage, reason code, and non-claims.

A release claim for `ucan-wg-1.0.0` remains unsupported until all required positive and negative cases have executable evidence.

**Rationale:** An exact unsupported result is safer than a broad compatibility claim.

### Decision: Separate later implementation slices

**Choice:** This change prepares two later local changes:

1. an isolated UCAN `1.0.0` wire component;
2. UCAN `1.0.0` delegation and invocation semantics.

No compatibility shim will infer one format from the other.

**Rationale:** Wire decoding and authority evaluation have different invariants, dependencies, and evidence.

## Functional core and imperative shell

The pure core owns profile IDs, support states, manifest validation, fixture classification, and conformance-report meaning. It receives all revisions, hashes, and case outcomes as explicit values.

The shell owns file reads, optional explicit fixture refresh, BLAKE3 calculation, source control commands, and report rendering. Runtime issue and verification functions do not discover profile files or invoke Nickel.

## Risks and trade-offs

- The local profile name does not assert historical upstream compatibility. This is deliberate.
- Upstream fixtures may be incomplete. The report must list that limitation.
- The overview, Delegation, and Invocation repositories can drift independently. Every profile update must pin and review all required revisions.
- `rs-ucan` can help test behavior, but agreement with it cannot override the final specifications.
- BLAKE3 identifies stack-owned manifests and reports. UCAN `1.0.0` CID construction must use protocol-required SHA-256 in the later wire component.
