## Phase 1: Core decisions

- [ ] [serial] Implement the canonical verification-relevant key projection backed by BLAKE3 in `ucan-core`. r[ucan.cache.projection]
- [ ] [serial] Implement the `no_std` retention decision core: eviction target, promotion disposition, watermark trim plans, and deferred-release plans from supplied values. r[ucan.cache.decision] r[ucan.cache.deferral]
- [ ] [serial] Require an explicit capacity with no implicit default bound. r[ucan.cache.bound]

## Phase 2: Standard shell store

- [ ] [depends:ucan.cache.bound] Implement the bounded store in the std shell. Relying on the core decisions. r[ucan.cache.bound]
- [ ] [depends:ucan.cache.deferral] Execute deferred releases strictly after the guard releases, with no user destructor inside the synchronization boundary. r[ucan.cache.deferral]
- [ ] [serial] Route cache misses to the existing verifier unchanged. r[ucan.cache.boundary]

## Phase 3: Fixtures and evidence

- [ ] [parallel] Add positive fixtures for projection stability, bounded retention, eviction order, promotion at and below threshold, and deferred-release ordering. r[ucan.cache.verification]
- [ ] [parallel] Add negative and boundary fixtures for missing bounds, reversed watermarks, zero capacity, single slot, threshold 0 and 100, and verdict invariance on hit. r[ucan.cache.verification]
- [ ] [serial] Document the claim boundary and the recorded cross-repo retention contract in repo docs. r[ucan.cache.boundary]
- [ ] [serial] Run workspace, Clippy, formatting, Cairn, and Nix checks, then record evidence. r[ucan.cache.verification]
