## Context

The existing audience-only invocation helper verifies a UCAN and checks that its audience can exercise a capability. It then constructs an `invoker` value from that audience DID. No live sender signs the invocation request, so this output overstates the evidence.

The new boundary must prove possession of the audience key for one exact, replay-admitted request. It must not define Basalt actions, request payload formats, durable nonce truth, or execution semantics.

## Success Contract

Completion requires all of the following evidence:

- complete borrowed token verification runs before holder canonicalization;
- every variable field is bounded by reviewed hard maxima before allocation;
- the total canonical size is bounded and exact allocation failure returns an error;
- one documented canonical format binds all required fields;
- the resolved audience key encodes the verified audience DID and validates the signature;
- an explicit profile admission boundary rejects unknown profiles;
- non-consuming profile and caveat observations finish before nonce admission;
- the nonce/replay boundary runs exactly once as the final commit point;
- all owned success fields exist before replay, with no work after replay accepts;
- the success type has private construction and no serde or clone surface;
- direct and delegated positive tests pass;
- each requested negative class fails at the intended boundary;
- full repository and Cairn rails pass.

False completion includes audience equality alone, signing a partial token identity, caller-supplied audience substitution, policy calls before signature verification, replay before pure checks, work after replay success, unbounded canonicalization, a generic serialized success receipt, or a UCAN-owned action enum.

## Portfolio Search Registry

The bounded search uses local source, dependency APIs, deterministic tests, and lifecycle gates. It has three rounds: construction, adversarial substitution audit, and full validation. It does not use network sources or advisory model agreement as evidence.

| Family | Mechanism | State | Reason |
| --- | --- | --- | --- |
| Holder request signature | Sign one canonical request with the verified audience key. | selected | Proves live possession and binds request identity without changing token format. |
| Token confirmation claim | Add a confirmation key or request key to UCAN claims. | rejected | Requires issuer and token-format coordination and still needs request replay binding. |
| Transport identity | Treat a TLS, RPC, or session identity as the holder. | rejected | Couples UCAN to consumer transport and does not provide a portable request signature. |
| Audience-only authorization | Keep audience equality as sender evidence. | falsified | It proves delegation target identity only. |

## Decisions

### Decision: Use a fixed domain-separated binary canonical format

**Choice:** The canonical request starts with the exact domain `ucan/holder-invocation/v1`. It then encodes fields in this order:

1. complete bounded compact-token BLAKE3 digest;
2. verified audience DID as a big-endian `u32` length and bytes;
3. resource as a big-endian `u32` length and bytes;
4. ability as a big-endian `u32` length and bytes;
5. fixed 32-byte operation-profile identity;
6. fixed 32-byte request-binding digest;
7. fixed 32-byte nonce.

The domain is not caller-configurable. Fixed fields have no redundant length. Variable fields use one fixed-width length prefix. The functional core calculates the exact output length and writes into a caller-provided exact slice.

The shell enforces reviewed hard maxima of 1,024 audience bytes, 16,384 resource bytes, 1,024 ability bytes, and 16,384 total canonical bytes. It uses `try_reserve_exact` before initialization. It returns a limit error for excessive configuration, total length, or allocation failure.

**Rationale:** Field order, widths, and domain separation make substitution and concatenation ambiguity testable. The complete token digest binds all token bytes after the existing complete-input bound. Hard shell maxima prevent public custom limits from requesting `u32::MAX`-scale allocation.

### Decision: Keep canonicalization in `ucan-core`

**Choice:** A no-std pure core admits bounded fields, calculates exact canonical length, and writes canonical bytes. The std shell verifies tokens, resolves keys, signs, verifies, calls profile and replay boundaries, and maps errors.

**Rationale:** Canonical logic can be tested with plain assertions. Injected resolvers and admission traits keep I/O and mutable policy in a thin shell.

### Decision: Use fixed typed operation evidence

**Choice:** `OperationProfileId`, `RequestBindingDigest`, and `HolderInvocationNonce` each wrap exactly 32 bytes. `OperationBinding` combines the profile identity and request digest. An injected `OperationProfileAdmission` admits known profile identities.

**Rationale:** Basalt can map each closed action variant to its own stable profile digest and exact request digest. UCAN does not parse or define the action enum.

### Decision: Separate signing from verified admission

**Choice:** A signing helper bounds its borrowed fields, checks that the signer DID equals the supplied audience DID, derives the complete token digest, and signs the canonical bytes. The verification API ignores caller claims about audience, uses only the verified token audience, and rejects a resolver result whose public key encodes a different DID.

**Rationale:** A holder needs a portable signing helper. The verifier must establish token truth independently before it trusts the audience identity.

### Decision: Use replay as the final commit point

**Choice:** The required order is complete token verification, bounds and canonicalization, audience-key signature verification, operation-profile admission, capability and caveat authorization, complete live-success construction, and exactly one replay admission call. Replay receives the verified audience, fixed nonce, and canonical request digest. UCAN returns the prebuilt success directly when replay accepts.

`OperationProfileAdmission` and `CaveatPolicy` are non-consuming observations. They may record telemetry, but they must not claim nonces, spend quota, reserve capacity, or mutate admission state. A consumer that needs consumptive rate limits applies them in a separate downstream atomic effect boundary after UCAN success.

**Rationale:** Unauthenticated requests cannot consume profile, caveat, or replay state. Unknown profiles and denied capabilities or caveats do not burn nonces. Replay is the only consuming step and no allocation, policy call, resolver call, canonicalization, or fallible work follows it.

### Decision: Narrow the compatibility claim

**Choice:** `verify_invocation` and `verify_invocation_with_replay` remain compatibility helpers. Their allowed value exposes issuer, audience, capability, and time bounds, but no `invoker` claim. Documentation calls them audience-only authorization.

**Rationale:** Existing authorization remains available without presenting audience equality as holder possession.

## Adversarial Audit

The test matrix mutates one signed field at a time. It covers token bytes, audience key, resource target, ability action, profile identity, request digest, and nonce. Separate tests cover duplicate admission, nonce width, signature width or corruption, hard field and total limits, simulated allocation failure, token time, proof resolution, revocation, caveat denial, and unknown profiles.

Call-order tests prove that a bad signature calls no profile, caveat, or replay trait; profile denial calls no caveat or replay trait; caveat denial calls no replay trait; and replay denial occurs exactly once after all observations.

The API must not expose public constructors or fields for the success value. A source guard rejects `Clone`, serde, and public construction surfaces.

## Non-Claims

- A valid holder signature does not prove transport identity, user identity, or key custody policy.
- Profile admission does not prove downstream action semantics or registry freshness.
- Request-binding equality does not prove the downstream request canonicalizer is correct.
- Nonce admission does not prove uniqueness, durability, crash consistency, freshness, or cross-process coordination.
- Caveat evaluation and profile admission do not perform consumptive quota or rate-limit effects.
- Token verification does not prove downstream execution, authorization completeness, or side-effect safety.
- BLAKE3 identity binds bytes; it does not make bearer input public or prove issuer intent beyond verified claims.

## Risks / Trade-offs

- The canonical binary format becomes a stable interoperability surface and must remain versioned.
- A consumer that maps two actions to one profile and request digest can weaken its own downstream binding.
- Audience key rotation and resolver freshness remain explicit caller policy.
- Compatibility helpers remain weaker by design and must stay clearly named in documentation.
