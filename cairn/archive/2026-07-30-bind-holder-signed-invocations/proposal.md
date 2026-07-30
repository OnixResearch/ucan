## Why

`verify_invocation` currently passes the verified token audience as both audience and invoker. Audience equality proves delegation target identity, but it does not prove that the live sender holds the audience private key.

UCAN needs a separate holder-signed invocation boundary. It must bind the verified token and downstream request identity without taking ownership of downstream action semantics.

## What Changes

- Add a borrowed holder-invocation API that verifies the complete bounded compact token before holder-request canonicalization.
- Add a domain-separated canonical request signed by the token audience key.
- Bind the complete token BLAKE3 reference, verified audience DID, resource, ability, operation-profile identity, exact request-binding digest, and fixed-size nonce.
- Resolve the audience key and verify the holder signature before replay admission.
- Add explicit operation-profile and nonce/replay admission boundaries.
- Return a private-construction, non-serde, non-clone live success value.
- Keep `verify_invocation` as explicit audience-only compatibility and remove its false invoker claim.
- Document that downstream action mapping, request canonicalization, profile registry truth, nonce durability, and execution remain consumer-owned.

## Impact

- **Files**: `crates/ucan-core/src`, `src/token.rs`, `src/token/holder_invocation.rs`, `src/lib.rs`, examples, readiness data, README, public API and verified-boundary documents, and Cairn lifecycle artifacts.
- **Testing**: Direct and delegated success; wrong holder; replay; malformed and substituted nonce; request, ability, resource, and profile substitution; malformed signature; oversized fields; token time; proof; revocation; caveat; unknown profile; workspace, format, Clippy, readiness, Nix, and Cairn gates.
