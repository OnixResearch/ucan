## Context

`HolderInvocationReplayAdmission` is UCAN's final state-consuming authorization boundary.
`RevocationChecker` is a non-authoritative observation boundary that runs before replay.
The shared component has separate pure cores and separate application-owned persistence ports.

## Decisions

### Decision: Depend on the two cores separately

**Choice:** The root shell imports `replay-ledger-core` and `revocation-view-core` from one exact Radicle object.

**Rationale:** UCAN can use each capability without importing Redb or an umbrella authority facade.

### Decision: Keep complete replay scope explicit

**Choice:** The adapter constructor receives tenant, operation profile, authority generation, ledger namespace, attempt identity, and the application-owned replay port.
The adapter derives the actor from the verified audience DID and uses the verified holder request digest and nonce.

**Rationale:** The UCAN candidate does not own tenant, generation, namespace, persistence, or recovery policy.

### Decision: Reserve at the final UCAN commit

**Choice:** First admission writes the shared reserved record with compare-and-swap before returning success.
Duplicates, conflicts, stale writes, unavailable reads, and unknown commit outcomes fail closed.

**Rationale:** UCAN performs no work after replay success. Downstream effect completion and recovery remain caller-owned.

### Decision: Treat revocation state as an explicit observation

**Choice:** The revocation adapter receives source, minimum generation, current time, and an application-owned view port.
It maps only current, complete, caller-authenticated snapshot lookups to revoked or not revoked.

**Rationale:** Missing, stale, incomplete, unauthenticated, unavailable, or contradictory state cannot support authorization.

### Decision: Preserve existing UCAN errors

**Choice:** The adapters map shared decisions into existing `HolderInvocationReplayError` and `RevocationError` classes.
They do not expose storage-engine errors or shared vendor types through the UCAN traits.

**Rationale:** Existing callers retain stable denial and backend meanings.

### Decision: Keep source acquisition exact

**Choice:** Cargo and Nix resolve the same full Radicle object through the admitted HTTPS adapter.
No GitHub, sibling, branch, tag, or path fallback is allowed.

**Rationale:** Consumer verification must not depend on ambient workspace state.

## Risks / Trade-offs

- A successful reservation does not prove the protected downstream effect completed.
- Callers must finalize or recover reserved records through their chosen persistence shell.
- A caller-supplied authenticity observation can be wrong.
- The adapter cannot prove global replay exclusion across uncoordinated stores.
