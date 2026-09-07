# Tasks

Evidence: `evidence/README.md`; sources `75ac18c` and `add8302`. All workspace
tests, fresh Hegel bootstrap, both library profiles, Rust 1.95 normal-library
isolation and full flake checks passed. No downstream activation is claimed.

- [x] [serial] Add default-on durable adapter feature without changing verification services or dependency revisions. r[ucan.durable_profile.selection]
- [x] [serial] Test default/minimal library behavior, forbidden dependency rejection and actual Rust 1.95 normal-library compatibility. r[ucan.durable_profile.verification]
- [x] [serial] Run maintained gates, record bounded evidence, sync/archive and publish only qualified source. r[ucan.durable_profile.verification]
