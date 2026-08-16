# Tasks: Implement the UCAN 1.0 Wire Profile

## Phase 1: Pure profile types

- [x] [serial] Add bounded no-std Delegation and Invocation payload types, nominal tags, slash-command validation, nonce, proof, metadata, policy, and argument values. r[ucan.v1_wire.types]
- [x] [parallel] Add positive field-shape and boundary tests plus negative missing, extra, wrong-type, command, timestamp, and nullable-expiry tests. r[ucan.v1_wire.fields]
- [x] [serial] Add explicit decoder and collection limits with fail-before-allocation checks. r[ucan.v1_wire.limits]

## Phase 2: Canonical envelope and identity

- [x] [depends:ucan.v1_wire.types] Add strict canonical DAG-CBOR adapters for separate Delegation and Invocation envelopes. r[ucan.v1_wire.codec]
- [x] [parallel] Add negative canonicalization, duplicate-field, tag-substitution, cross-kind, indefinite-form, trailing-byte, and oversized-value fixtures. r[ucan.v1_wire.codec]
- [x] [depends:ucan.v1_wire.codec] Add exact CIDv1, base58btc, DAG-CBOR, and protocol-required SHA-256 construction and validation. r[ucan.v1_wire.cid]
- [x] [parallel] Add positive CID cases from pinned canonical fixtures and negative version, base, codec, multihash, digest, and payload-mismatch cases. r[ucan.v1_wire.cid]

## Phase 3: Signature shell

- [x] [depends:ucan.v1_wire.codec] Add Varsig parsing and the first admitted Ed25519/`did:key` signing and verification adapter. r[ucan.v1_wire.crypto]
- [x] [parallel] Add positive signing cases and negative malformed Varsig, unsupported algorithm, wrong key class, issuer mismatch, signature mutation, and signer-output cases. r[ucan.v1_wire.crypto]
- [x] [depends:ucan.v1_wire.crypto] Expose caller-owned signer and DID key resolver ports with no ambient backends. r[ucan.v1_wire.ports]

## Phase 4: Interoperability evidence

- [x] [serial] Replay all applicable pinned final UCAN `1.0.0` Delegation and Invocation fixtures through the profile-specific API. r[ucan.v1_wire.fixtures]
- [x] [parallel] Add derived mutation fixtures bound to source fixture BLAKE3 identities and stable mutation descriptions. r[ucan.v1_wire.fixtures]
- [x] [serial] Update the protocol conformance report without promoting authorization semantics. r[ucan.v1_wire.docs]
- [x] [serial] Run no-std checks, focused tests, workspace tests, Clippy, Octet gate, Cairn gates, and `nix flake check -L`. r[ucan.v1_wire.validation]
