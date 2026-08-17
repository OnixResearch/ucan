## Why

A valid UCAN `1.0.0` envelope does not establish authority. Authorization requires ordered Delegation proof resolution, issuer and audience alignment, subject continuity, command attenuation, policy evaluation over Invocation arguments, time validity, proof uniqueness, invocation replay admission, and exact executor checks.

The current compact profile uses capability arrays, wildcard ability segments, resource-prefix rules, BLAKE3 proof references, and a separate holder-signature extension. Those semantics cannot be reused as final UCAN `1.0.0` behavior by renaming fields.

## What Changes

- Add typed final `1.0.0` Delegation and Invocation authority models over verified wire envelopes.
- Resolve caller-supplied CID proof chains in strict order and bind every result to the requested CID.
- Implement principal alignment, subject and Powerline rules, command hierarchy, time bounds, and proof-chain limits.
- Implement the final Delegation policy language as a separate pure component over bounded IPLD arguments.
- Admit an Invocation only after proof, policy, signature, executor, revocation observation, and replay checks pass.
- Return a non-forgeable live authorization value and deterministic redacted evidence.
- Preserve the existing compact authorization behavior unchanged.

## Impact

The crate can evaluate bounded final UCAN `1.0.0` Delegation and Invocation authority through explicit caller-owned stores and observations. Consumers retain resource ownership truth, key trust, revocation freshness, replay durability, transport, and effect authority.

## Dependencies

This change depends on `implement-ucan-1-wire-profile`.

## Non-goals

- Do not replace the current compact authorization API.
- Do not infer final semantics from the compact capability model.
- Do not implement Promise, the separate Revocation token protocol, AWAKE, transport, storage, or remote resolution.
- Do not claim that policy syntax proves external resource ownership or effect safety.
- Do not let persisted receipts recreate live authorization.
