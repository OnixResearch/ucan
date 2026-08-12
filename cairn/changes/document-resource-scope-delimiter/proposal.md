## Why

Resource containment is byte-prefix matching per the UCAN prefix model. A
capability on `did:key:z6Mkresource` authorizes `did:key:z6Mkresource/photos`
(correct) and also `did:key:z6MkresourceX` (a sibling string that shares the
prefix). This is intended UCAN semantics, but applications that concatenate
strings into resources without a delimiter can create accidental overlap that
grants more than the issuer intended.

## What Changes

- Document the byte-prefix containment semantics and the shared-prefix
  overmatch hazard in the authorization reference.
- Add an optional delimiter-guard recommendation for resource construction.
- Add coverage fixtures that record the sibling-prefix behavior so the
  semantics stay pinned.

## Impact

Consumers construct resources with explicit separators and avoid accidental
overlap. The measured prefix behavior is recorded as pinned fixtures. No
authorization outcomes change unless a consumer adopts the guard.

## Dependencies

This change depends only on the audited revision. It does not change token,
proof, capability, or authorization semantics.

## Non-goals

- Do not change the byte-prefix containment rule.
- Do not change ability or caveat semantics.
- Do not implement a new resource namespace or registry.
