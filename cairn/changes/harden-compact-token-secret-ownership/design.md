# Design: Compact-token secret ownership

## Context

The current verification shell creates several ordinary bearer copies:

- `CompactToken(String)` derives `Debug` and `Clone`, implements `Display` and serde, and exposes `into_string`.
- `verify_compact_token_str` copies borrowed input into `String` before verification.
- `ProofStore` returns an owned cloned `CompactToken`.
- parse stages retain compact text, decoded signature bytes, and an allocated signing input.
- verified framing bridges copy the complete compact token and every encoded segment into ordinary vectors.
- base64 and serde helpers return growing ordinary vectors and strings.
- issuance uses `serde_json::to_vec`, base64 return allocations, `format!`, and a final ordinary `String`.

These mechanisms cannot support a no-stale-bearer-copy claim.

## Success Contract

The implementation is complete only when these facts hold:

1. The leaf token and each proof token receive a size check before token-derived allocation or BLAKE3 identity.
2. Borrowed verification does not allocate an owned compact-token copy.
3. Owned bearer values and reconstruction-capable temporary buffers zeroize on every return path.
4. Bearer-bearing vectors use exact preallocation or deterministic two-pass sizing and never grow after secret bytes enter them.
5. Public errors, debug output, serde output, and formatting cannot reveal compact tokens.
6. Proof traversal does not clone compact proof tokens.
7. Public token evidence contains only a fixed-width BLAKE3 reference over one complete bounded input.
8. Positive and negative tests cover the required cleanup and compatibility boundaries.

False completion includes redaction without wiping, zeroizing only the final allocation, prefix hashing, proof cloning, or archiving after a dependency blocker.

## Decisions

### 1. Borrow complete inputs at the verification shell

The primary string API accepts `&str`. It checks the complete byte length and compact shape before decoding.

Internal stages borrow the encoded signing input directly from the original compact text. They do not rebuild `header.payload` during verification.

The existing explicit time, resolver, proof, revocation, and limit inputs remain parameters. No ambient source is added.

### 2. Use non-cloneable zeroizing owners

`CompactToken` owns a fixed zeroizing byte buffer. Manual `Debug` reports only length and `<redacted>`. The type has no `Display`, serde, or `Clone` implementation.

The type exposes a narrow borrowed view for verification and transport integration. It does not expose `String`, `Vec`, or an unwiped consuming reconstruction.

Signing keys, signer signatures, proof collections, decoded token stages, and structurally valid token stages follow the same ownership rule when they contain secret or bearer-reconstruction bytes.

### 3. Make proof resolution borrow-aware

`ProofStore` returns a `ProofToken` value. The value can borrow a token from store-owned zeroizing storage or own a zeroizing token.

Verification consumes the value only for the recursive call. It stores the BLAKE3 proof reference in the verified result, not the proof token.

### 4. Use exact buffers and deterministic two-pass encoding

Base64 decoding calculates the exact unpadded output length. It initializes one fixed zeroizing boxed slice and calls `decode_slice`.

Issuance counts deterministic JSON output first. It then writes into one fixed zeroizing boxed slice and rejects a length mismatch.

Base64 encoding writes into fixed zeroizing output. Signing-input and compact-token assembly use checked exact lengths and cannot grow.

### 5. Constrain serde to its reviewed borrowing path

The locked `serde_json` slice reader has an ordinary internal scratch vector. Its source borrows strings only when they contain no JSON escapes.

The parser rejects decoded header or payload bytes that contain JSON escape syntax before serde runs. Parsed token structs borrow string fields from zeroizing decoded JSON buffers.

This compatibility restriction prevents secret bytes from entering serde scratch storage. The exact reviewed `serde_json` version remains pinned.

If this source behavior changes, or another serde path copies bearer-reconstruction bytes, this change is blocked until the dependency or parser changes.

### 6. Keep evidence exact and bounded

BLAKE3 hashes the complete compact byte slice only after the configured bound succeeds. No API hashes an oversized prefix.

`ProofReference` stores one fixed-width BLAKE3 digest. Error and debug paths can show this public reference, byte counts, stages, and fixed diagnostics.

They cannot show compact text, encoded segments, decoded JSON, signing input, or signature-plus-input reconstruction material.

### 7. Retain explicit non-claims

Zeroization covers normal Rust drop and early-return paths for owned live allocations. It does not prove stack clearing, process isolation, swap exclusion, crash cleanup, allocator history outside these owners, or caller buffer wiping.

The current resolver, proof, revocation, replay, clock, persistence, authorization, and verified-logic non-claims remain unchanged.

## Dependency Audit

The implementation relies on these reviewed source facts:

- `zeroize 1.8.2` uses volatile writes and a compiler fence. Fixed boxed slices avoid prior reallocations.
- `base64 0.22.1` `decode_slice` and `encode_slice` do not allocate output storage.
- `serde_json 1.0.149` borrows unescaped strings from slice input. Escaped strings use ordinary scratch storage and are rejected before parsing.
- `ed25519-dalek 2.2.0` accepts borrowed messages and fixed arrays. The live path bypasses vendored signature wrappers that require ordinary vectors.

## Validation Strategy

Runtime tests cover borrowed success, malformed and oversized input, proof chains, early errors, exact capacities, and unchanged authorization behavior.

Source tests reject forbidden secret traits, ordinary reconstruction, proof-token cloning, allocating codec helpers, bearer-building `format!` paths, and verified bearer-copy wrappers.

The final rail includes focused tests, workspace tests, formatting, strict Clippy, readiness checks, Cairn gates, sync, archive, and post-archive validation.
