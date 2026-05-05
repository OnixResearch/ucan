## Tasks

- [x] Add OpenSpec proposal/design/tasks/spec delta for finite verified proof traversal primitives.
- [ ] Implement or vendor verified-logic data models for proof traversal transcript entries, proof edges, traversal budgets, revocation facts, fold steps, and authorization requests.
- [ ] Add verified primitives for proof graph well-formedness, bounded traversal/cycle rejection, effective delegation folding, chain authorization, revocation-aware denial, and transcript consistency.
- [ ] Expose exact UCAN bridge helpers only for primitives whose inputs match already-resolved shell data or shell-produced traversal transcripts.
- [ ] Add focused UCAN tests for valid traversal, broken links, cycles, duplicate references, depth/count/input limits, revocation denial, backend errors, over-broad delegation, and transcript mismatch.
- [ ] Update docs and bridge guards to describe which traversal facts are verified and which parser/resolver/backend/crypto/caveat-policy boundaries remain shell-local.
- [ ] Run focused/full validation, archive the change, commit, push, and verify a clean tree.
