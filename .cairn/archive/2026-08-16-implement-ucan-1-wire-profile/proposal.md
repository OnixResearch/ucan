## Why

The protocol-profile catalog will identify final UCAN `1.0.0` as unsupported. Supporting it requires a new wire component, not changes to the current three-part compact parser.

Final UCAN `1.0.0` requires canonical DAG-CBOR, Varsig envelopes, typed Delegation and Invocation payload tags, CIDv1 proof references, SHA-256 multihashes, 53-bit timestamps, and distinct payload shapes. Mixing these rules into the compact parser would create profile confusion and unsafe compatibility behavior.

## What Changes

- Add a separate UCAN `1.0.0` wire component with typed Delegation and Invocation envelopes.
- Decode and encode canonical DAG-CBOR with strict map, integer, byte, tag, and duplicate-field admission.
- Parse and verify the required Varsig and `did:key` cryptographic profile.
- Construct and validate protocol-required CIDv1, base58btc, DAG-CBOR, and SHA-256 references.
- Preserve caller-owned signing and DID resolution ports in the std shell.
- Run pinned upstream positive fixtures and derived negative mutation fixtures.
- Keep the current compact token API and bytes unchanged.

## Impact

The crate gains a profile-specific wire API that can establish structural and cryptographic facts for UCAN `1.0.0` Delegations and Invocations. It does not yet establish delegation-chain authority or policy satisfaction.

SHA-256 is used only where the UCAN `1.0.0` interoperability contract requires it. BLAKE3 remains the default for repository-owned fixture manifests, reports, and receipts.

## Dependencies

This change depends on `declare-ucan-protocol-profiles`.

## Non-goals

- Do not alter or auto-detect the existing compact profile.
- Do not implement delegation attenuation, policy evaluation, invocation authorization, Promise, or Revocation.
- Do not add network, filesystem, IPFS, database, or ambient DID resolution.
- Do not adopt `rs-ucan` as a runtime dependency without a separate audit and dependency decision.
- Do not implement AWAKE.
