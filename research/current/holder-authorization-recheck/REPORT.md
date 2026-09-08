# Non-consuming holder recheck qualification

Source commit: `12a66876d4d85955e05df18682af6f8e2975254a`.
Base: `927dc32641af6cd1b17202aff44c35acef4540fa`.

## Observed results

The unchanged source passed these commands inside the owner development shell:

- `cargo test --locked -p ucan-core holder_invocation`: 7 passed, including 2 new pure binding controls.
- `cargo test --locked -p ucan --lib token::holder_invocation::tests`: 24 passed, including 6 new recheck controls.
- The same shell selection with `--no-default-features`: 24 passed.
- `cargo test --locked -p ucan --doc HolderAuthorizationObservation`: 6 compile-fail controls passed in each feature profile.
- `cargo clippy --locked -p ucan -p ucan-core --all-targets -- -D warnings`: passed.
- Strict Clippy with `-p ucan --no-default-features --all-targets`: passed.
- `cargo check --locked -p ucan-core --no-default-features`: passed.
- `cargo test --locked --workspace`: passed, including Hegel-backed tests. No failures or ignored tests were reported.
- `cargo fmt -p ucan -p ucan-core`: applied before those checks; the Nix formatting check passed afterward.

`nix flake check --no-update-lock-file` completed successfully. It ran 13 checks,
including the pinned Rust 1.95 minimal-library profile, default/minimal nextest,
formatting, Clippy, source/dependency posture, and existing owner checks.
Normal configured remote builds observed cache.clan.lol timeouts, then completed.
No cache or verification policy was weakened.

Cairn proposal and design gates passed. Initial tasks and repository validation
returned exit 0 but reported FAIL because four tasks lacked concurrency markers.
The corrected task file declares serial work. Strict validation now reports
`valid: true` with no findings, and the tasks gate reports `verdict: PASS`.
`git diff --check` passed before the source commit.

## Controls

- Repeated direct observations preserve the original authorization reference,
  effective bounds, and one replay admission. A later duplicate invocation fails.
- Exact token substitution, initial-time regression, and excessive token size
  fail before sentinel key, proof, or revocation services can run.
- Missing current keys, expiry, revoked leaf tokens, and revocation outage fail.
- Delegated success observes both leaf and parent. Revoked or missing parent
  evidence fails without another replay admission.
- Changed caveat or profile observations deny the original operation.
- Six independent compile-fail examples prevent public construction, cloning,
  serialization, deserialization, dispatch-type substitution, and lifetime escape.
- A zero-skew control preserves UCAN's inclusive endpoint and rejects the next second.

## Retained evidence and corrections

Complete logs are retained outside disposable worktrees under the Neural Stream
private drain evidence directory `.pi/drains/materialization-complete/`:

- `ucan-recheck-baseline-v1.log`: 18 original holder tests passed before logic changes.
- `ucan-recheck-owner-checks-v5.log`: all Cargo checks above, task 11724, exit 0.
- `ucan-recheck-flake-v1.log`: full Nix qualification, task 11725, exit 0.
- `ucan-recheck-planning-v1.log` and `ucan-recheck-validation-v1.log`: initial lifecycle results, including the missing-marker failure.
- `ucan-recheck-evidence-validation-v1.log`: confirmed that an exit-0 command can contain a FAIL verdict.
- `ucan-recheck-validation-v2.json` and `ucan-recheck-tasks-v2.json`: corrected valid/PASS receipts with no issues.
- `ucan-recheck-source-v5.patch`: source snapshot before commit.

Earlier logs retain a wrong test import path, a borrowed-snapshot mutation error,
and Clippy failures for ordinary input copying, Debug coverage, and a test pointer.
Those failures were corrected without lint suppression. An initial Cairn command
omitted the policy path; its corrected invocation used the pinned policy.

## Lifecycle outcome

The accepted spec was synchronized and the change was archived at
`.cairn/archive/1970-01-01-nonconsuming-holder-recheck/`. The epoch prefix is the
CLI's deterministic archive label, not the observed execution date.
`ucan-recheck-sync-v1.json` and `ucan-recheck-archive-v1.json` report unblocked
observed mutations. Strict post-archive validation reports zero active changes,
`valid: true`, and no findings in `ucan-recheck-archived-validation-v1.json`.

## Non-claims

This adds a borrowed observation through existing verification machinery. It
adds no dependency, token format, replay adapter, dispatch permission, or release
effect. The observation trusts supplied services and time. It does not establish
continuous authority, continuing key possession, backend authenticity/freshness,
independent persistent custody, or atomic authorized release.

Consumers retain monotonic observation time, stricter deadlines, authenticated
services, workload fencing, crash quarantine, and release-time checks. Neural
Stream's materialization remains 5/11. No real issuer grant, training, activation,
consumer pin change, or promotion occurred during this qualification.
