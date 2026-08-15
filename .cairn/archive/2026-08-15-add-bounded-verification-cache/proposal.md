## Why

UCAN verification results are recomputed per token or retained without a
bounded retention contract. Unbounded retention grows memory without limit
under high token throughput and creates replay-hazard tables.

The stack now has a reviewed bounded-retention pattern: the `bounded-cache`
component and the external `adanil-code/LRUHashTable` design reference.

UCAN should own a bounded verification-result cache. Eviction and promotion
decisions belong in the `no_std` core, keyed by BLAKE3 digest of a canonical
token projection, with result release deferred outside the synchronization
boundary.

## What Changes

- Add a `no_std` verification-cache decision core in `ucan-core`: canonical key
  projection, eviction selection, promotion decision, watermark trim plans,
  and deferred-release plans from supplied values.
- Add a bounded verification-cache store in the std shell that executes core
  decisions and releases results after the guard releases.
- Key every entry by BLAKE3 digest of the canonical verification-relevant token
  projection.
- Require an explicit capacity. Add no implicit default bound.
- Record the cross-repo contract: the cache policy follows the `bounded-cache`
  retention contract, and the store can later adopt a published `bounded-cache`
  revision.

## Impact

- **Files**: `crates/ucan-core` cache decision module, std shell store, tests,
  and this lifecycle package.
- **Testing**: workspace tests, Clippy, formatting, Cairn validation and gates,
  and `nix flake check`.

## Dependencies

New sibling component: `bounded-cache` (consumed by an exact published Git
revision once available; retained as a policy reference until then).

External reference: `adanil-code/LRUHashTable`
(<https://github.com/adanil-code/LRUHashTable>) under Apache-2.0.

## Non-goals

- Do not change verification semantics. The cache is advisory only.
- Do not add sibling-path dependencies.
- Do not read clocks in the core.
- Do not claim that a cache hit proves verification correctness or fresh
  authority.
