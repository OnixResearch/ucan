# Document Resource Scope Delimiter: Implementation Evidence

Date: 2026-08-15

## Documentation

- New file: `docs/authorization-reference.md`
- BLAKE3 digest: `e66b8046861fa227591472294c6f4d040f8ee31d080a71fbd9e16bd1385039eb`
- Documents the byte-prefix containment rule, the shared-prefix overmatch
  example, delimited resource-construction guidance, and the delimiter-free
  concatenation warning.
- README links the reference beside the `capability_set_authorizes`
  description in the proof-chain delegation section.

## Fixtures

- `src/verified.rs` tests module:
  - `pins_byte_prefix_scope_admits_nested_and_sibling_resources` records that
    a capability scoped to `did:key:z6Mkresource` authorizes
    `did:key:z6Mkresource/photos` and the sibling overmatch
    `did:key:z6MkresourceX`. The pin comment names the byte-prefix
    containment rule it locks in place.
  - `pins_byte_prefix_scope_rejects_unrelated_resource` records that the same
    scope rejects `did:key:z6Mkother`. The pin comment names the rejection
    side of the containment rule it locks in place.
- These are positive and negative fixtures (both paths) for the documented
  semantics.

## Checks

- Baseline before edits: `cargo test -p ucan --lib` -> 190 passed, 0 failed.
- After edits: `cargo test -p ucan --lib` -> 192 passed, 0 failed.
- `cargo clippy -p ucan --lib -- -D warnings` -> exit 0.
- The changed source files are `rustfmt` clean. Pre-existing committed
  formatting drift in `examples/pentest_*.rs` is out of scope; the primary
  worktree carries uncommitted local fixes for those files.
- `cairn gate proposal|design|tasks document-resource-scope-delimiter` ->
  all exit 0 with no issues.

## Non-claims

This change does not alter library behavior. The docs and fixtures record
the existing measured byte-prefix semantics. No equivalence, cryptographic,
policy, or release-readiness claim is added.
