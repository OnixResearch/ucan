## Why

`verify_compact_token` and the issuance self-check leak heap memory for every
token that carries caveats. `decoded_caveat_inputs`, `decoded_capability_inputs`,
and `capability_inputs` call `Box::leak` and `payload.leak` to fabricate
borrowed core inputs. The allocator never reclaims that memory.

Measured evidence from `examples/pentest_memory.rs`:
- ~461 bytes per verification for a 260-byte caveat payload;
- ~4,352 bytes per verification for a 4,096-byte payload.

Payload length is attacker controlled and bounded only by the 64 KiB compact
token cap. A long-running verifier that accepts untrusted tokens grows resident
memory without bound. This is a remote memory-exhaustion path.

## What Changes

- Remove permanent `Box::leak` / `payload.leak` from the verification and
  issuance paths.
- Keep `ucan-core` borrowed-input APIs unchanged.
- Keep the verification and issuance behavior byte-for-byte identical apart
  from memory lifetime.
- Add a regression test that measures stable memory across repeated
  verified tokens with large caveat payloads.

## Impact

Resident memory of a long-running verifier stops growing with cumulative token
volume. Tokens and receipts keep their current formats and identities.

## Dependencies

This change depends only on the audited revision. It does not change token,
proof, caveat, or authorization semantics.

## Non-goals

- Do not change `ucan-core` public APIs.
- Do not alter caveat payload meaning or encoding.
- Do not change the 64 KiB compact-token limit.
- Do not implement an allocator or a memory pool.
