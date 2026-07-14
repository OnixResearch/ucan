## Context

The repository already enforces a no-std core / std shell split. The license boundary follows that architecture and depends on the sibling Trellis license change before the vendored snapshot can be refreshed honestly.

## Decisions

### MPL protocol core

`crates/ucan-core` declares MPL-2.0. This permits embedding UCAN parsing and validation in larger applications while keeping modifications to covered core files available.

### AGPL std shell

The root `ucan` package remains AGPL-3.0-or-later because it owns issuance, verification orchestration, resolver integration, and network/runtime-facing behavior.

### MPL verified primitive snapshot

`vendor/verified-logic` is refreshed only through `scripts/sync-verified-logic.sh` from a committed Trellis revision whose package metadata and license artifact declare MPL-2.0. The recorded source revision remains authoritative.

### Explicit non-claims

The split does not relicense third-party dependencies, revoke prior grants, prove protocol interoperability, or transfer Trellis proofs to the UCAN shell.
