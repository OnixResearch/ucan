# Durable adapter selection evidence

Base: `a7d2c21cbb9a262c048672e09c77c3f0825bdd2d`.
Feature source: `75ac18c9273004c05bd3c3d2114ab4c21ae6947c`.
Test-bootstrap source: `add83022fff7b8f13b53b418708bb07ad138b8d4`.

The pre-change default library baseline passed 247 tests. After the feature change,
247 default and 238 no-default library tests passed. Two source-pin controls passed.
Strict Clippy passed for both library profiles. Runtime dependency revisions, Cargo
lock, Nix lock and the verified-logic vendor snapshot stayed unchanged.

The sandboxed minimal profile compiled with actual rustc 1.95.0. Its normal-library
dependency observation contained UCAN and ucan-core, and neither durable-state
library. Both positive and negative observer tests passed. The full flake check on
feature source passed: 238 minimal and 355 default/core/Nostr nextest cases, zero
skipped in those selected runs. Nix intentionally excludes Hegel integration.

The first workspace run hung because Hegel 0.2.3 accessed ConjectureRunner's removed
interesting_examples member in Hypothesis 6.167.1. It was stopped, not reported as
passed. Hegel's declared minimum Hypothesis 6.148.5 passed all three actual property
tests. A checked-in UV constraint then passed a fresh bootstrap and all three tests
again. No property assertion, Rust package pin or third-party source was changed.
The original install and server failure logs remain retained. The complete workspace
suite, including all three Hegel properties, then passed on bootstrap source,
followed by the full flake check and unchanged-lock/vendor checks. The combined
committed-source gate took 1 minute 26 seconds.

An initial Nix prototype used cargoCheck, unavailable in this pinned Crane version.
The maintained profile instead builds the normal library through buildPackage.
A formatting check rejected two edited file layouts; normal repository formatting
fixed those without vendor edits or new suppressions.

The gate covers feature selection and verified observations, not backend durability,
operator grants, production readiness or downstream compatibility. Default-on
selection retains concrete adapters. Explicit opt-out keeps verifier service ports
and checks; it supplies no permissive fallback. Basalt and Animus must separately
qualify their published-source updates before adopting this profile.

Full logs are retained by the initiating Neural checkout under
`.pi/drains/2026-09-07-ucan-isolation/`.
