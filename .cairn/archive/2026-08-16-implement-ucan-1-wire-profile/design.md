## Context

The current token shell is one large compact-format module. Final UCAN `1.0.0` uses a different data model and canonical byte representation. Structural overlap is limited to some names such as issuer and audience.

The normative sources are the pinned final overview, Delegation, and Invocation revisions recorded by `declare-ucan-protocol-profiles`. The pinned `rs-ucan` repository is useful for design comparison and differential fixtures, but it declares release-candidate behavior and no formal audit.

## Decisions

### Decision: Add an isolated profile component

**Choice:** Add a narrow component, such as `ucan_core::profile::v1` for pure types and validation plus `ucan::profile::v1` for cryptographic shell behavior. Public names must include the profile or typed envelope kind.

The existing `CompactToken` and its functions remain unchanged. No function accepts an untagged enum that guesses between wire formats.

**Rationale:** Separate components prevent accidental parser and authority crossover.

### Decision: Keep canonical wire meaning in the functional core

**Choice:** The no-std core owns bounded domain types and deterministic admission for:

- typed payload tags `ucan/dlg@1.0.0` and `ucan/inv@1.0.0`;
- issuer, audience, and subject shape;
- slash-command syntax and segment boundaries;
- finite IPLD arguments, policy values, metadata, proof references, and nonce bytes;
- exact safe-integer timestamp bounds from `-(2^53 - 1)` through `2^53 - 1`, plus nullable expiry;
- Delegation and Invocation required, optional, and forbidden field combinations;
- canonical DAG-CBOR shape facts passed by the codec adapter.

The core returns typed values and errors. It performs no I/O, clock reads, key lookup, or signing.

**Rationale:** Wire invariants are deterministic protocol meaning.

### Decision: Use a thin codec and cryptographic shell

**Choice:** The std shell owns DAG-CBOR library calls, Varsig signature operations, caller-provided DID key resolution, caller-provided signer operations, and byte/CID presentation.

The codec must reject duplicate fields, non-canonical encodings, unsupported tags, indefinite forms when forbidden, unsupported signature suites, oversized values, and trailing bytes. Decoder limits are explicit inputs with reviewed defaults.

**Rationale:** Library and cryptographic mechanisms remain adapters around domain validation.

### Decision: Implement protocol CID exactly

**Choice:** UCAN token references use CIDv1, base58btc presentation, DAG-CBOR multicodec, and SHA-256 multihash as required by final UCAN `1.0.0`.

Repository manifests, conformance reports, cache identities, and receipts use BLAKE3 with domain-separated framing.

**Rationale:** Interoperability requires SHA-256 at the CID boundary. That requirement does not change stack-owned hashing defaults.

### Decision: Start with the required Ed25519 profile

**Choice:** The first implementation supports final-spec Ed25519 and `did:key`. P-256 and secp256k1 remain explicit unsupported algorithm states until separate positive and negative evidence exists.

Varsig headers must be parsed as self-describing values and compared to the admitted profile. Algorithm and key mismatches fail closed.

**Rationale:** A narrow verified cryptographic profile is safer than nominally listing every required suite without evidence.

### Decision: Treat Delegation and Invocation as different nominal types

**Choice:** Expose different builders, decoders, verified envelopes, payload structures, and errors for Delegation and Invocation.

A Delegation cannot enter an Invocation API because fields look similar. Tag substitution, field substitution, and cross-type signature fixtures must fail.

**Rationale:** Token kind is protocol meaning, not a display label.

### Decision: Preserve caller-owned external capabilities

**Choice:** Application-owned shell ports provide signing and DID key resolution. Token proof resolution remains outside this wire slice.

The component provides no built-in HTTP, IPFS, filesystem, database, clock, random nonce, key custody, or trust root.

**Rationale:** The library must not gain ambient authority while adding a codec.

### Decision: Use fixture and mutation evidence

**Choice:** Execute all applicable pinned `fixtures/1.0.0` Delegation and Invocation cases. Derive negative cases by controlled mutation of tag, canonical form, fields, limits, Varsig, signature, key, CID, timestamps, nullable fields, command, and trailing bytes.

Each derived fixture records the source fixture BLAKE3 and the deterministic mutation description. Positive and negative fixtures stay together.

**Rationale:** The upstream directory has a small fixture set. Mutation evidence is necessary but does not claim official fixture status.

## Component boundaries

- `ucan-core` profile module: pure bounded protocol values and invariant checks.
- root `ucan` profile module: codec, cryptographic adapters, CID construction, and orchestration.
- caller ports: signer and key resolver.
- tests and tools: explicit pinned fixture loading and conformance receipts.

No vendor type crosses into the core public contract.

## Risks and trade-offs

- DAG-CBOR and multiformat dependencies increase attack surface. Dependency review and malformed-input tests are required.
- Canonical decoding can differ across libraries. Exact byte round trips and independent negative fixtures must test the selected adapter.
- A valid signature and CID do not prove authority, key trust, revocation freshness, replay safety, or execution correctness.
- Supporting only Ed25519 means the profile is a documented subset until other required suites have evidence.
