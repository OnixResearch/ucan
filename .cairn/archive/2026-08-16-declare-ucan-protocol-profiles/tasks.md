# Tasks: Declare UCAN Protocol Profiles

## Phase 1: Nominal profile contract

- [x] [serial] Add closed Rust protocol-profile IDs and support states for the local compact profile and the unsupported UCAN `1.0.0` target. r[ucan.protocol_profiles.catalog]
- [x] [depends:ucan.protocol_profiles.catalog] Bind existing compact APIs and support surfaces to the local profile without changing token bytes. r[ucan.protocol_profiles.compact]
- [x] [depends:ucan.protocol_profiles.catalog] Add the exact protocol-profile field to the typed Nickel integration profile and regenerate BLAKE3-bound projections. r[ucan.protocol_profiles.selection]
- [x] [parallel] Add positive local-profile admission tests and negative missing, unknown, stale, and unsupported-profile tests. r[ucan.protocol_profiles.selection]

## Phase 2: Pinned fixture evidence

- [x] [serial] Pin the final overview, Delegation, Invocation, fixture, and `rs-ucan` revisions with roles, licenses, and non-claims. r[ucan.protocol_profiles.sources]
- [x] [depends:ucan.protocol_profiles.sources] Add a bounded fixture manifest for `fixtures/1.0.0` with source paths, Git blob IDs, and BLAKE3 byte identities. r[ucan.protocol_profiles.fixtures]
- [x] [parallel] Add positive manifest tests and negative malformed, duplicate, traversal, stale-revision, and digest-mismatch tests. r[ucan.protocol_profiles.fixtures]
- [x] [depends:ucan.protocol_profiles.fixtures] Generate a deterministic per-case conformance report that preserves `unsupported` and `untested` outcomes. r[ucan.protocol_profiles.report]

## Phase 3: Documentation and validation

- [x] [serial] Update the README and readiness docs to distinguish the local compact profile, final UCAN `1.0.0`, legacy fixture sources, and unaudited references. r[ucan.protocol_profiles.docs]
- [x] [serial] Document that AWAKE remains a separate deferred session protocol. r[ucan.protocol_profiles.docs]
- [x] [serial] Run readiness freshness, Nickel contracts, positive and negative fixture tests, workspace tests, Clippy, Cairn gates, and `nix flake check -L`. r[ucan.protocol_profiles.validation]
