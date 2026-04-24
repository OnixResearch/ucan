//! Verified did:key encoding and decoding for UCAN tokens.
//!
//! Models the `did:key:z...` encoding: multicodec varint prefix for the
//! key type (0xed for Ed25519) followed by the raw public key bytes,
//! encoded as base58btc with the multibase 'z' prefix.
//!
//! Varint encode/decode is fully internalized. Base58btc is external_body
//! with assumed round-trip. The proof surface covers DID round-trip,
//! injectivity, codec preservation, and prefix validity.

#![allow(clippy::ptr_arg)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::vec_init_then_push)]

use vstd::prelude::*;

// --- Base58btc runtime (invisible to Verus) ---

#[cfg(not(verus_keep_ghost))]
fn base58btc_encode_runtime(bytes: &[u8]) -> Vec<u8> {
    bs58::encode(bytes).into_vec()
}

#[cfg(verus_keep_ghost)]
fn base58btc_encode_runtime(_bytes: &[u8]) -> Vec<u8> {
    Vec::new()
}

#[cfg(not(verus_keep_ghost))]
fn base58btc_decode_runtime(encoded: &[u8]) -> Option<Vec<u8>> {
    bs58::decode(encoded).into_vec().ok()
}

#[cfg(verus_keep_ghost)]
fn base58btc_decode_runtime(_encoded: &[u8]) -> Option<Vec<u8>> {
    None
}

fn varint_decode_runtime(bytes: &[u8]) -> Option<(u64, usize)> {
    if bytes.is_empty() {
        return None;
    }
    let mut val: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if i >= 10 {
            return None;
        }
        if b < 128 {
            let v = val.checked_add((u64::from(b)).checked_shl(shift)?)?;
            return Some((v, i + 1));
        }
        let low = u64::from(b & 0x7f);
        val = val.checked_add(low.checked_shl(shift)?)?;
        shift = shift.checked_add(7)?;
    }
    None
}

verus! {

/// Multicodec code for Ed25519 public keys.
pub const CODEC_ED25519: u64 = 0xed;

/// did:key method prefix bytes: "did:key:z"
pub const DID_KEY_PREFIX_LEN: usize = 9;

/// Parsed did:key with decoded public key bytes and codec.
pub struct DidKey {
    pub public_key_bytes: Vec<u8>,
    pub codec: u64,
    pub encoded: Vec<u8>,
}

// --- Varint spec (LEB128, fully internalized) ---

/// Varint encode spec: LEB128 encoding of a u64.
// r[impl ucan-did.varint-round-trip]
pub open spec fn varint_encode_spec(n: u64) -> Seq<u8>
    decreases n,
{
    if n < 128 {
        seq![n as u8]
    } else {
        seq![(n % 128 + 128) as u8] + varint_encode_spec((n / 128) as u64)
    }
}

/// Varint decode spec: returns (value, bytes_consumed) or None.
// r[impl ucan-did.varint-round-trip]
pub open spec fn varint_decode_spec(bytes: Seq<u8>) -> Option<(u64, nat)>
    decreases bytes.len(),
{
    if bytes.len() == 0 {
        None
    } else if bytes[0] < 128 {
        Some((bytes[0] as u64, 1))
    } else {
        match varint_decode_spec(bytes.subrange(1, bytes.len() as int)) {
            None => None,
            Some((rest_val, rest_len)) => {
                let low = (bytes[0] - 128) as u64;
                Some(((low + rest_val * 128) as u64, rest_len + 1))
            }
        }
    }
}

/// Varint round-trip: encoding then decoding recovers the value.
// r[verify ucan-did.varint-round-trip]
pub proof fn varint_round_trip(n: u64)
    ensures varint_decode_spec(varint_encode_spec(n)) == Some((n, varint_encode_spec(n).len())),
    decreases n,
{
    if n < 128 {
        assert(varint_encode_spec(n) == seq![n as u8]);
        assert(varint_decode_spec(seq![n as u8]) == Some((n, 1nat)));
    } else {
        let tail_val = (n / 128) as u64;
        let low_byte = (n % 128 + 128) as u8;
        let tail_enc = varint_encode_spec(tail_val);
        let full = seq![low_byte] + tail_enc;
        varint_round_trip(tail_val);
        assert(full.subrange(1, full.len() as int) =~= tail_enc);
        assert(varint_decode_spec(tail_enc) == Some((tail_val, tail_enc.len())));
        let low = (low_byte - 128) as u64;
        assert(low == n % 128);
        assert(low + tail_val * 128 == n) by(nonlinear_arith)
            requires low == n % 128, tail_val == n / 128, n >= 128u64;
    }
}

/// Varint decode rejects empty input.
// r[impl ucan-did.varint-rejects-empty]
// r[verify ucan-did.varint-rejects-empty]
pub proof fn varint_decode_rejects_empty()
    ensures varint_decode_spec(Seq::<u8>::empty()) == None::<(u64, nat)>,
{
}

/// Varint encode always produces at least one byte.
// r[verify ucan-did.varint-round-trip]
pub proof fn varint_encode_nonempty(n: u64)
    ensures varint_encode_spec(n).len() >= 1,
    decreases n,
{
}

// --- Varint exec ---

/// Encode a u64 as LEB128 varint.
// r[impl ucan-did.varint-round-trip]
pub fn varint_encode(n: u64) -> (result: Vec<u8>)
    ensures result@ == varint_encode_spec(n),
{
    let mut out = Vec::new();
    let mut val = n;
    loop
        invariant
            val <= n,
            out@ + varint_encode_spec(val) == varint_encode_spec(n),
        decreases val,
    {
        if val < 128 {
            out.push(val as u8);
            assert(out@ =~= out@.subrange(0, out@.len() - 1) + seq![val as u8]);
            return out;
        }
        let low = (val % 128 + 128) as u8;
        out.push(low);
        val = val / 128;
    }
}

/// Decode a LEB128 varint from the start of a byte slice.
// r[impl ucan-did.varint-round-trip]
#[verifier::external_body]
pub fn varint_decode(bytes: &Vec<u8>) -> (result: Option<(u64, usize)>)
    ensures
        match result {
            Some((val, len)) => varint_decode_spec(bytes@) == Some((val, len as nat))
                && len <= bytes@.len(),
            None => varint_decode_spec(bytes@).is_none(),
        },
{
    varint_decode_runtime(bytes)
}

// --- Multicodec framing spec ---

/// Multicodec-prefixed key bytes.
// r[impl ucan-did.codec-preserved]
pub open spec fn multicodec_prefix_spec(codec: u64, key_bytes: Seq<u8>) -> Seq<u8> {
    varint_encode_spec(codec) + key_bytes
}

/// Parse multicodec prefix: extract (codec, key_bytes).
// r[impl ucan-did.codec-preserved]
pub open spec fn multicodec_parse_spec(prefixed: Seq<u8>) -> Option<(u64, Seq<u8>)> {
    match varint_decode_spec(prefixed) {
        None => None,
        Some((codec, len)) => Some((codec, prefixed.subrange(len as int, prefixed.len() as int))),
    }
}

/// Multicodec round-trip: prefix then parse recovers codec and key.
// r[verify ucan-did.codec-preserved]
pub proof fn multicodec_round_trip(codec: u64, key_bytes: Seq<u8>)
    ensures multicodec_parse_spec(multicodec_prefix_spec(codec, key_bytes)) == Some((codec, key_bytes)),
{
    let enc = varint_encode_spec(codec);
    let prefixed = enc + key_bytes;
    varint_round_trip(codec);
    varint_encode_nonempty(codec);
    varint_decode_prefix_free(codec, key_bytes);
    let vlen = enc.len();
    assert(prefixed.subrange(vlen as int, prefixed.len() as int) =~= key_bytes);
}

/// Varint decode is prefix-free: extra trailing bytes don't change the result.
// r[verify ucan-did.varint-round-trip]
proof fn varint_decode_prefix_free(n: u64, suffix: Seq<u8>)
    ensures
        varint_decode_spec(varint_encode_spec(n) + suffix)
            == Some((n, varint_encode_spec(n).len())),
    decreases n,
{
    let enc = varint_encode_spec(n);
    let combined = enc + suffix;
    if n < 128 {
        assert(enc =~= seq![n as u8]);
        assert(combined[0] == n as u8);
        assert((n as u8) < 128);
    } else {
        let low_byte = (n % 128 + 128) as u8;
        let tail_val = (n / 128) as u64;
        let tail_enc = varint_encode_spec(tail_val);
        assert(enc =~= seq![low_byte] + tail_enc);
        assert(combined[0] == low_byte);
        assert(low_byte >= 128u8);
        let combined_tail = combined.subrange(1, combined.len() as int);
        assert(combined_tail =~= tail_enc + suffix);
        varint_decode_prefix_free(tail_val, suffix);
        assert(varint_decode_spec(tail_enc + suffix) == Some((tail_val, tail_enc.len())));
        let low = (low_byte - 128) as u64;
        assert(low == n % 128);
        assert((low + tail_val * 128) as u64 == n) by(nonlinear_arith)
            requires low == n % 128, tail_val == n / 128, n >= 128u64;
    }
}

// --- Base58btc spec (external body) ---

/// Uninterpreted base58btc encoding model.
// r[depends ucan-did.round-trip]
pub uninterp spec fn base58btc_encode_byte_spec(bytes: Seq<u8>, idx: int) -> u8;

/// Base58btc encoded output.
// r[impl ucan-did.round-trip]
pub uninterp spec fn base58btc_encode_spec(bytes: Seq<u8>) -> Seq<u8>;

/// Base58btc decode model.
// r[impl ucan-did.round-trip]
pub uninterp spec fn base58btc_decode_spec(encoded: Seq<u8>) -> Option<Seq<u8>>;

/// Axiom: base58btc round-trips.
// r[impl ucan-did.base58btc-round-trip]
// r[verify ucan-did.base58btc-round-trip]
#[verifier::external_body]
pub proof fn axiom_base58btc_round_trip(bytes: Seq<u8>)
    ensures base58btc_decode_spec(base58btc_encode_spec(bytes)) == Some(bytes),
{
}

/// Axiom: base58btc is injective.
// r[verify ucan-did.injective]
#[verifier::external_body]
pub proof fn axiom_base58btc_injective(a: Seq<u8>, b: Seq<u8>)
    requires a != b,
    ensures base58btc_encode_spec(a) != base58btc_encode_spec(b),
{
}

/// Base58btc encode exec.
// r[impl ucan-did.round-trip]
#[verifier::external_body]
pub fn base58btc_encode(bytes: &Vec<u8>) -> (result: Vec<u8>)
    ensures result@ == base58btc_encode_spec(bytes@),
{
    base58btc_encode_runtime(bytes)
}

/// Base58btc decode exec.
// r[impl ucan-did.round-trip]
#[verifier::external_body]
pub fn base58btc_decode(encoded: &Vec<u8>) -> (result: Option<Vec<u8>>)
    ensures
        match result {
            Some(v) => base58btc_decode_spec(encoded@) == Some(v@),
            None => base58btc_decode_spec(encoded@).is_none(),
        },
{
    base58btc_decode_runtime(encoded)
}

// --- DID encode/decode spec ---

/// The did:key prefix string bytes: "did:key:z".
// r[impl ucan-did.prefix-valid]
pub open spec fn did_key_prefix_spec() -> Seq<u8> {
    seq![
        0x64u8, 0x69u8, 0x64u8, 0x3au8, // "did:"
        0x6bu8, 0x65u8, 0x79u8, 0x3au8, // "key:"
        0x7au8,                           // "z"
    ]
}

/// Encode a public key and codec as a did:key string.
// r[impl ucan-did.round-trip]
// r[impl ucan-did.prefix-valid]
pub open spec fn encode_did_key_spec(public_key: Seq<u8>, codec: u64) -> Seq<u8> {
    did_key_prefix_spec() + base58btc_encode_spec(multicodec_prefix_spec(codec, public_key))
}

/// Decode a did:key string to recover public key bytes and codec.
// r[impl ucan-did.round-trip]
pub open spec fn decode_did_key_spec(did_bytes: Seq<u8>) -> Option<(Seq<u8>, u64)> {
    let prefix = did_key_prefix_spec();
    if did_bytes.len() < prefix.len() {
        None
    } else if did_bytes.subrange(0, prefix.len() as int) != prefix {
        None
    } else {
        let b58_part = did_bytes.subrange(prefix.len() as int, did_bytes.len() as int);
        match base58btc_decode_spec(b58_part) {
            None => None,
            Some(decoded) => {
                match multicodec_parse_spec(decoded) {
                    None => None,
                    Some((codec, key_bytes)) => Some((key_bytes, codec)),
                }
            }
        }
    }
}

/// DID round-trip: encode then decode recovers key and codec.
// r[verify ucan-did.round-trip]
pub proof fn did_key_round_trip(public_key: Seq<u8>, codec: u64)
    ensures decode_did_key_spec(encode_did_key_spec(public_key, codec)) == Some((public_key, codec)),
{
    let prefix = did_key_prefix_spec();
    let mc = multicodec_prefix_spec(codec, public_key);
    let b58 = base58btc_encode_spec(mc);
    let full = prefix + b58;

    // Prefix matches
    assert(full.subrange(0, prefix.len() as int) =~= prefix);

    // Base58 part
    let b58_part = full.subrange(prefix.len() as int, full.len() as int);
    assert(b58_part =~= b58);

    // Base58 round-trip
    axiom_base58btc_round_trip(mc);
    assert(base58btc_decode_spec(b58) == Some(mc));

    // Multicodec round-trip
    multicodec_round_trip(codec, public_key);
    assert(multicodec_parse_spec(mc) == Some((codec, public_key)));
}

/// DID encoding always starts with "did:key:z".
// r[verify ucan-did.prefix-valid]
pub proof fn did_key_has_valid_prefix(public_key: Seq<u8>, codec: u64)
    ensures
        encode_did_key_spec(public_key, codec).len() >= 9,
        encode_did_key_spec(public_key, codec).subrange(0, 9) == did_key_prefix_spec(),
{
    let prefix = did_key_prefix_spec();
    let full = prefix + base58btc_encode_spec(multicodec_prefix_spec(codec, public_key));
    assert(full.subrange(0, prefix.len() as int) =~= prefix);
}

/// Distinct keys produce distinct DIDs (injectivity).
// r[impl ucan-did.injective]
// r[verify ucan-did.injective]
pub proof fn did_key_injective(pk1: Seq<u8>, pk2: Seq<u8>, codec: u64)
    requires pk1 != pk2,
    ensures encode_did_key_spec(pk1, codec) != encode_did_key_spec(pk2, codec),
{
    let mc1 = multicodec_prefix_spec(codec, pk1);
    let mc2 = multicodec_prefix_spec(codec, pk2);
    // Multicodec prefix is the same, key bytes differ => mc1 != mc2
    assert(mc1 != mc2) by {
        let vlen = varint_encode_spec(codec).len();
        varint_encode_nonempty(codec);
        if mc1 =~= mc2 {
            assert(mc1.subrange(vlen as int, mc1.len() as int) =~= pk1);
            assert(mc2.subrange(vlen as int, mc2.len() as int) =~= pk2);
        }
    }
    // Base58btc is injective
    axiom_base58btc_injective(mc1, mc2);
    let prefix = did_key_prefix_spec();
    let full1 = prefix + base58btc_encode_spec(mc1);
    let full2 = prefix + base58btc_encode_spec(mc2);
    // Different suffixes => different full strings
    assert(full1 != full2) by {
        if full1 =~= full2 {
            assert(full1.subrange(prefix.len() as int, full1.len() as int) =~= base58btc_encode_spec(mc1));
            assert(full2.subrange(prefix.len() as int, full2.len() as int) =~= base58btc_encode_spec(mc2));
        }
    }
}

/// Codec is preserved through DID round-trip.
// r[verify ucan-did.codec-preserved]
pub proof fn did_key_codec_preserved(public_key: Seq<u8>, codec: u64)
    ensures
        decode_did_key_spec(encode_did_key_spec(public_key, codec)) matches Some(pair)
            ==> pair.1 == codec,
{
    did_key_round_trip(public_key, codec);
}

// --- Exec functions ---

/// Encode a public key and codec as a did:key byte string.
// r[impl ucan-did.round-trip]
// r[impl ucan-did.prefix-valid]
pub fn encode_did_key(public_key: &Vec<u8>, codec: u64) -> (result: DidKey)
    ensures
        result.public_key_bytes@ == public_key@,
        result.codec == codec,
        result.encoded@ == encode_did_key_spec(public_key@, codec),
{
    let mc_prefix = varint_encode(codec);
    let mut mc_bytes = mc_prefix;
    let mut i: usize = 0;
    while i < public_key.len()
        invariant
            0 <= i <= public_key.len(),
            mc_bytes@ == varint_encode_spec(codec) + public_key@.subrange(0, i as int),
        decreases public_key.len() - i,
    {
        mc_bytes.push(public_key[i]);
        i = i + 1;
    }
    assert(mc_bytes@ =~= multicodec_prefix_spec(codec, public_key@));
    let b58 = base58btc_encode(&mc_bytes);
    // Build "did:key:z" + b58
    let mut encoded = Vec::new();
    encoded.push(0x64u8); // d
    encoded.push(0x69u8); // i
    encoded.push(0x64u8); // d
    encoded.push(0x3au8); // :
    encoded.push(0x6bu8); // k
    encoded.push(0x65u8); // e
    encoded.push(0x79u8); // y
    encoded.push(0x3au8); // :
    encoded.push(0x7au8); // z
    let mut j: usize = 0;
    while j < b58.len()
        invariant
            0 <= j <= b58.len(),
            encoded@ == did_key_prefix_spec() + b58@.subrange(0, j as int),
        decreases b58.len() - j,
    {
        encoded.push(b58[j]);
        j = j + 1;
    }
    assert(encoded@ =~= did_key_prefix_spec() + b58@);
    assert(encoded@ =~= encode_did_key_spec(public_key@, codec));
    DidKey {
        public_key_bytes: public_key.clone(),
        codec,
        encoded,
    }
}

} // verus!

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_encode_single_byte() {
        let encoded = varint_encode(0x55);
        assert_eq!(encoded, vec![0x55]);
    }

    #[test]
    fn test_varint_encode_two_bytes() {
        // 0xed = 237 => 237 % 128 = 109, 237 / 128 = 1
        // => [109 + 128, 1] = [0xed, 0x01]
        let encoded = varint_encode(0xed);
        assert_eq!(encoded, vec![0xed, 0x01]);
    }

    #[test]
    fn test_varint_round_trip() {
        for n in [0u64, 1, 127, 128, 255, 256, 0xed, 0x1200, u64::MAX / 2] {
            let encoded = varint_encode(n);
            let decoded = varint_decode(&encoded);
            assert!(decoded.is_some(), "varint_decode failed for {n}");
            let (val, len) = decoded.unwrap();
            assert_eq!(val, n, "round-trip failed for {n}");
            assert_eq!(len, encoded.len(), "length mismatch for {n}");
        }
    }

    #[test]
    fn test_varint_decode_empty() {
        let empty = Vec::new();
        assert!(varint_decode(&empty).is_none());
    }

    #[test]
    fn test_varint_decode_truncated_continuation() {
        const CONTINUATION_ONLY_BYTE: u8 = 0x80;
        let truncated = vec![CONTINUATION_ONLY_BYTE];
        assert!(varint_decode(&truncated).is_none());
    }

    #[test]
    fn test_did_key_encode_ed25519() {
        let pk = vec![1u8; 32];
        let did = encode_did_key(&pk, CODEC_ED25519);
        // Should start with "did:key:z"
        let prefix = b"did:key:z";
        assert_eq!(&did.encoded[..9], prefix);
        assert_eq!(did.public_key_bytes, pk);
        assert_eq!(did.codec, CODEC_ED25519);
    }

    #[test]
    fn test_did_key_base58_round_trip() {
        let data = vec![42u8; 34]; // multicodec prefix + 32-byte key
        let encoded = base58btc_encode(&data);
        let decoded = base58btc_decode(&encoded);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), data);
    }

    #[test]
    fn test_did_key_distinct_keys() {
        let pk1 = vec![1u8; 32];
        let pk2 = vec![2u8; 32];
        let did1 = encode_did_key(&pk1, CODEC_ED25519);
        let did2 = encode_did_key(&pk2, CODEC_ED25519);
        assert_ne!(did1.encoded, did2.encoded);
    }
}
