## Phase 1: Command and policy core

- [x] [serial] Add the final-profile slash-command type and complete-segment attenuation rules without reusing compact wildcard abilities. r[ucan.v1_authorization.command]
- [x] [parallel] Add positive exact, parent, root, and Unicode command cases plus negative case, slash, trailing, segment, and lexical-prefix cases. r[ucan.v1_authorization.command]
- [x] [serial] Add a bounded policy AST, selector parser, and predicate evaluator for only the final Delegation policy language. r[ucan.v1_authorization.policy]
- [x] [parallel] Add positive operator, connective, quantifier, selector, collection, byte, optional, and glob fixtures. r[ucan.v1_authorization.policy]
- [x] [parallel] Add negative unknown operator, unsupported jq, malformed selector, mismatch, unresolved, depth, count, size, and work-limit fixtures. r[ucan.v1_authorization.policy]

## Phase 2: Proof-chain authority

- [x] [serial] Add pure ordered-chain composition for principal, subject, Powerline, command, time, and proof identity facts. r[ucan.v1_authorization.chain]
- [x] [parallel] Add positive direct, delegated, Powerline, and alternate-path cases plus negative root, alignment, subject, cycle, duplicate, order, time, and attenuation cases. r[ucan.v1_authorization.chain]
- [x] [depends:ucan.v1_authorization.chain] Add a caller-owned CID Delegation store adapter that binds every returned token to the requested CID. r[ucan.v1_authorization.proof_store]
- [x] [parallel] Add missing, substituted, stale, malformed, oversized, and unavailable proof-store tests. r[ucan.v1_authorization.proof_store]

## Phase 3: Invocation admission

- [x] [depends:ucan.v1_authorization.chain] Add pure exact Invocation admission over verified wire, chain, command, arguments, policy, executor, time, and revocation facts. r[ucan.v1_authorization.invocation]
- [x] [depends:ucan.v1_authorization.invocation] Add preflight ordering and one final caller-owned replay commit. r[ucan.v1_authorization.replay]
- [x] [depends:ucan.v1_authorization.replay] Add a private, borrowed, non-clone, non-serde live authorization value. r[ucan.v1_authorization.live]
- [x] [parallel] Add positive direct and delegated invocation cases plus negative proof, policy, executor, expiry, revocation, replay, and backend matrices. r[ucan.v1_authorization.tests]
- [x] [parallel] Assert every preflight denial makes zero replay calls and no fallible work occurs after replay accepts. r[ucan.v1_authorization.replay]

## Phase 4: Evidence and validation

- [x] [serial] Add deterministic redacted BLAKE3 receipts that bind the profile and specification cohort without carrying bearer or request payloads. r[ucan.v1_authorization.receipt]
- [x] [parallel] Add redaction, determinism, non-authority, and profile-substitution receipt tests. r[ucan.v1_authorization.receipt]
- [x] [serial] Update conformance and readiness reports with exact supported and unsupported authorization surfaces. r[ucan.v1_authorization.docs]
- [x] [serial] Run focused property and fixture tests, no-std checks, workspace tests, Clippy, Octet gate, Cairn gates, and `nix flake check -L`. r[ucan.v1_authorization.validation]
