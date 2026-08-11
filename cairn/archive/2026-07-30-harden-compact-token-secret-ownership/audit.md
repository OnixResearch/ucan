# Compact-token allocation audit

## Scope

This audit covers leaf tokens, proof tokens, decoded bytes, signing input, signatures, errors, debug output, and clone paths.

## Allocation paths

| Path | Previous risk | Current ownership |
| --- | --- | --- |
| Borrowed leaf input | `verify_compact_token_str` created an owned token copy. | Verification borrows `&str`. It checks the complete byte limit before parsing or BLAKE3. |
| `CompactToken` | `String` could clone, format, serialize, and reallocate. | A fixed `Zeroizing<Box<[u8]>>` owns the bytes. Only borrowed `as_str` access is public. |
| Proof resolution | `ProofStore` returned a cloned token. | `ProofStore` returns `ProofToken::Borrowed` or `ProofToken::Owned`. Owned values use `CompactToken`. |
| Compact parts | Verified framing helpers copied all encoded parts into `Vec`. | Verification borrows header, payload, signature, and signing input slices from bounded input. The copying helpers are removed. |
| Base64 output | Allocating codec helpers returned growing `Vec` values. | `decode_slice` and `encode_slice` write into fixed zeroizing boxed slices. Length mismatch is an error. |
| Decoded JSON | Ordinary `Vec` values retained header and payload bytes. | Fixed zeroizing boxed slices own decoded bytes. Serde string fields borrow from these slices. |
| Serde escapes | Escaped strings used ordinary serde scratch storage. | Header and payload bytes containing `\` are rejected before serde runs. `serde_json` is pinned to `1.0.149`. |
| Verification signing input | `header.payload` was rebuilt in an ordinary vector. | Signature verification borrows the exact signing-input prefix from bounded compact input. |
| Signature verification | The verified bridge copied message and signature bytes into ordinary vectors. | Fixed-width `ed25519-dalek` calls use borrowed slices and stack arrays after vendored length admission. |
| Signer output | `SignerSignature::new(Vec<u8>)` accepted unknown allocation history. | `SignerSignature` owns a zeroizing fixed 64-byte array. Its slice constructor rejects other lengths. |
| Issuance JSON | `serde_json::to_vec` used a growing ordinary vector. | A counting pass determines the length. The second pass writes into one fixed zeroizing boxed slice. |
| Issuance joining | `format!` and growing strings built signing input and compact output. | Checked exact lengths allocate fixed zeroizing boxed slices before bytes are written. |
| Issuance proofs | Issuance accepted proof-token owners and encouraged cloning. | Issuance accepts only public `ProofReferences`. Proof tokens remain in verification stores. |
| BLAKE3 evidence | Hash helpers could run before complete bounds. | Complete input bounds run first. Public evidence is one fixed-width BLAKE3 digest. |
| Errors | Codec and parser text could include dependency details. | Errors contain fixed classes, stages, public references, and lengths. They do not contain bearer bytes. |
| Debug and formatting | Derived traits exposed compact text. | `CompactToken` has redacted `Debug`. It has no `Display`, serde, `Clone`, `FromStr`, or owned reconstruction. |
| Test copies | Production `Clone` encouraged bearer copies. | A test-only helper creates a new zeroizing `CompactToken`. Production code has no clone implementation. |

## Dependency findings

- `zeroize 1.8.2` wipes fixed live allocations during normal drop and early returns.
- `base64 0.22.1` slice codecs use caller-owned output and do not allocate output buffers.
- `serde_json 1.0.149` borrows unescaped strings from slice input. Escaped strings are rejected first.
- `ed25519-dalek 2.2.0` accepts borrowed messages and fixed key or signature arrays.
- Vendored compact framing and signature wrappers required ordinary `Vec` copies. The live bearer path no longer calls those wrappers.

## Evidence boundaries

The tests cover borrowed verification, bounded failure order, fixed allocation lengths, growth rejection, early-error drop, JSON escape rejection, proof traversal, redacted output, and forbidden source surfaces.

This audit does not claim stack clearing, memory locking, swap exclusion, crash-time wiping, or caller-buffer wiping.
