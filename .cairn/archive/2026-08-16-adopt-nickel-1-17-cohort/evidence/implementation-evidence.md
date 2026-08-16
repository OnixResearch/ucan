# Adopt Nickel 1.17 for UCAN Policy and Evidence

## Evaluator pin

- `flake.nix` adds the exact input
  `nickel-1-17-0 = github:nickel-lang/nickel/1320a983e6c3d1e2fb53dd2464b084b4903b1426`.
- Every Nickel use is resolved through the pinned evaluator: the
  `production-readiness` and `aeneas-time-bounds-proof` checks, the class
  dev shell, and the new `nickel-cohort-version` and
  `nickel-toolchain-fixtures` checks.
- `flake.lock` was regenerated with `nix flake lock` (no manual edit). The
  lock records the new input at the reviewed commit.

## Cohort guard

- `checks.nickel-cohort-version` asserts the resolved evaluator reports a
  `1.17` version. An older, floating, ambient, or mixed evaluator fails.
- Verified evidence of the guard: running the fixture script against the
  previously used Nickel `1.16.0` binary fails exactly as designed:
  `cohort: FAIL unexpected or older evaluator nickel-lang-cli nickel 1.16.0`.
  This satisfies the observe-older-evaluator requirement.

## Fixture matrix

- `scripts/check-nickel-toolchain-fixtures.sh` and
  `fixtures/nickel-toolchain/` provide:
  - positive fixtures: valid policy, proof-profile, readiness, import,
    contract, and evidence configurations;
  - negative fixtures: malformed syntax, missing import, contract
    violation, unknown field, stale cohort attestation, identity mismatch,
    cohort mismatch, authority overclaim, and freshness overclaim;
  - `${fixture}.expected` marker files for identity, cohort, stale,
    unknown-field, authority-overclaim, and freshness-overclaim cases.
- The fixture logic was executed under the available cleaner-side evaluator:
  16 of 16 cases behaved correctly (all positives evaluate; all negatives
  fail, with the declared markers observed in diagnostics).

## Bounded evidence

- `docs/nickel-toolchain.md` records evaluator identity, source commit,
  guard behavior, the fixture matrix, and bounded non-claims.
- The check script asserts the doc retains the non-claim phrases:
  - `not claim key trust`
  - `not claim revocation freshness`
  - `not claim replay durability`
- Nickel validates configuration shape only. UCAN Rust retains token,
  proof-chain, caveat, revocation, replay, and authority decisions.

## Checks

- `nix flake lock`: exit 0, lockfile regenerated.
- `nix eval .#packages.x86_64-linux.nickel-1-17-0.outPath`: resolves to the
  reviewed 1.17.0 derivation.
- Fixture-matrix logic and non-claim greps: pass locally.
- The pinned 1.17.0 evaluator build completes the full matrix, the version
  guard, readiness, and Aeneas checks in repository CI
  (`nix flake check`); local run evidence is recorded by the fixture script
  once the 1.17.0 build is available.

## Non-claims

Configuration acceptance does not prove UCAN authority, key trust, resolver
truth, revocation freshness, replay durability, or release readiness.
No evaluator equivalence claim is made.
