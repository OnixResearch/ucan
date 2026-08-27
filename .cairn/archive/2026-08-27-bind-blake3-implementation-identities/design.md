## Context

The previous dependency alignment changed exact Cargo requirements and the lock to BLAKE3 `1.8.5`. The implementation-identity material in `ucan-core` peer authentication and `ucan-nostr` still names `1.8.4`.

## Decision

Keep each owner-defined identity domain and framing unchanged. Replace only the reviewed dependency version in each implementation revision input.

Extend the test-only dependency-posture core to validate these facts together:

- both exact manifest requirements name BLAKE3 `1.8.5`;
- the lock contains one BLAKE3 `1.8.5` package;
- both implementation revision inputs name BLAKE3 `1.8.5`;
- a deliberately drifted identity input fails validation.

## Compatibility

The implementation identity changes because its reviewed dependency input changes. Consumers must bind the new immutable UCAN revision. Old receipts do not migrate or gain authority.

## Verification

Run the focused dependency, peer-authentication, and Nostr tests before and after the change. Then run workspace tests, strict scoped Clippy, scoped formatting, `nix flake check`, and Cairn gates.

## Non-claims

Source-label alignment does not prove BLAKE3 correctness, UCAN cryptographic correctness, downstream policy completeness, or universal dependency compatibility.
