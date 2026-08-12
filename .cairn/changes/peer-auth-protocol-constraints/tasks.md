## Framing and protocol core

- [ ] [serial] Pin the reviewed Celld peer-protocol design revision and record the selected constraints and license in `README.md`. r[ucan.peer_auth.reference]
- [ ] [serial] Add typed versioned authenticated-message framing DTOs to `ucan-core`. r[ucan.peer_auth.framing]
- [ ] [serial] Implement pure HMAC, body-bound signature, version, clock-bound, and replay-disposition validation. r[ucan.peer_auth.validation]

## Output and boundary

- [ ] [serial] Add opaque authenticated-message verdict construction and redacted public fields. r[ucan.peer_auth.verdict]
- [ ] [parallel] Add official-vector and matching-version positive cases. r[ucan.peer_auth.verification]
- [ ] [parallel] Add wrong-version, altered-body, bad-HMAC, stale, out-of-skew, and replay-denial negative cases. r[ucan.peer_auth.verification]
- [ ] [parallel] Add digest-role, secret-field, empty-message, and capability-promotion rejection cases. r[ucan.peer_auth.verification]
- [ ] [serial] Document consumer-owned transport, key custody, clock, replay, subject, and authorization responsibilities. r[ucan.peer_auth.boundary]

## Closeout

- [ ] [serial] Run package, workspace, Clippy, Cairn, and Nix checks. r[ucan.peer_auth.verification]
- [ ] [serial] Record the reviewed revision, vectors, dependency revision, and license evidence. r[ucan.peer_auth.reference]
