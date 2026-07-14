## Why

UCAN is both a protocol library and an operator/runtime shell. Strong AGPL licensing on `ucan-core` and its verified primitives discourages protocol adoption, while removing AGPL from the std shell would weaken reciprocity for network-facing integrations.

## What Changes

- License `ucan-core` under MPL-2.0.
- Keep the root `ucan` std shell under `AGPL-3.0-or-later`.
- Refresh the vendored Trellis `verified-logic` snapshot after Trellis adopts MPL-2.0.
- Add complete license texts and a package/vendor boundary map.

## Impact

Protocol parsing and validation remain reusable with file-level copyleft; network/runtime shell modifications remain AGPL. The vendored snapshot remains revision- and license-preserving.
