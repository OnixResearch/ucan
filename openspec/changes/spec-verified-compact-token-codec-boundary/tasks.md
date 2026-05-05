## Tasks

- [x] Add OpenSpec proposal/design/tasks/spec delta for compact-token codec boundary hardening.
- [ ] Inventory compact-token parse/encode/signing-input/proof-reference paths and classify structural versus trusted-runtime behavior.
- [ ] Add structural admission helpers or tests only where the current shell behavior has an exact deterministic property to preserve.
- [ ] Add negative tests for malformed compact shape, invalid base64/JSON, and signing-input/proof-reference stability without exposing compact token values in logs.
- [ ] Update README/API docs to distinguish structural checks from trusted codec/hash/crypto boundaries.
- [ ] Run focused/full validation, archive the change, commit, push, and verify a clean tree.
