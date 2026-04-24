//! Verified Ed25519 signature primitives for UCAN tokens.
//!
//! Models sign/verify as an external-body pair with verified structural
//! contracts: round-trip, key binding, message binding, determinism, and
//! fixed output lengths. The cryptographic implementation is trusted;
//! this module proves the rest of the system uses the contract correctly.

#![allow(clippy::ptr_arg)]

use vstd::prelude::*;

// --- Runtime crypto (invisible to Verus) ---

#[cfg(not(verus_keep_ghost))]
fn sign_runtime(secret_key: &[u8], message: &[u8]) -> Vec<u8> {
    use ed25519_dalek::{Signer, SigningKey};
    let sk_bytes: [u8; 32] = secret_key.try_into().expect("secret key must be 32 bytes");
    let signing_key = SigningKey::from_bytes(&sk_bytes);
    let sig = signing_key.sign(message);
    sig.to_bytes().to_vec()
}

#[cfg(verus_keep_ghost)]
fn sign_runtime(_secret_key: &[u8], _message: &[u8]) -> Vec<u8> {
    vec![0u8; 64]
}

#[cfg(not(verus_keep_ghost))]
fn verify_runtime(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};
    let pk_bytes: [u8; 32] = match public_key.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_bytes: [u8; 64] = match signature.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else {
        return false;
    };
    vk.verify(message, &Signature::from_bytes(&sig_bytes)).is_ok()
}

#[cfg(verus_keep_ghost)]
fn verify_runtime(_public_key: &[u8], _message: &[u8], _signature: &[u8]) -> bool {
    false
}

#[cfg(not(verus_keep_ghost))]
fn public_from_secret_runtime(secret_key: &[u8]) -> Vec<u8> {
    use ed25519_dalek::SigningKey;
    let sk_bytes: [u8; 32] = secret_key.try_into().expect("secret key must be 32 bytes");
    let signing_key = SigningKey::from_bytes(&sk_bytes);
    signing_key.verifying_key().to_bytes().to_vec()
}

#[cfg(verus_keep_ghost)]
fn public_from_secret_runtime(_secret_key: &[u8]) -> Vec<u8> {
    vec![0u8; 32]
}

verus! {

pub const SECRET_KEY_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

/// Ed25519 secret key (32-byte seed).
pub struct SecretKey {
    pub bytes: Vec<u8>,
}

/// Ed25519 public key (32 bytes).
pub struct PublicKey {
    pub bytes: Vec<u8>,
}

/// Ed25519 signature (64 bytes).
pub struct Ed25519Signature {
    pub bytes: Vec<u8>,
}

// --- Spec functions ---

/// Uninterpreted per-byte signature model.
// r[depends ucan-signature.round-trip]
pub uninterp spec fn sign_byte_spec(secret_key: Seq<u8>, message: Seq<u8>, idx: int) -> u8;

/// Full 64-byte signature spec from secret key and message.
// r[impl ucan-signature.round-trip]
pub open spec fn sign_spec(secret_key: Seq<u8>, message: Seq<u8>) -> Seq<u8> {
    Seq::new(SIGNATURE_LEN as nat, |i: int| sign_byte_spec(secret_key, message, i))
}

/// Uninterpreted per-byte public-key derivation model.
// r[depends ucan-signature.public-key-length]
pub uninterp spec fn public_from_secret_byte_spec(secret_key: Seq<u8>, idx: int) -> u8;

/// Full 32-byte public key derived from secret key.
// r[impl ucan-signature.public-key-length]
pub open spec fn public_from_secret_spec(secret_key: Seq<u8>) -> Seq<u8> {
    Seq::new(PUBLIC_KEY_LEN as nat, |i: int| public_from_secret_byte_spec(secret_key, i))
}

/// Verification spec: true iff the signature matches the public key and message.
// r[impl ucan-signature.round-trip]
pub uninterp spec fn verify_spec(public_key: Seq<u8>, message: Seq<u8>, signature: Seq<u8>) -> bool;

/// Well-formed secret key: exactly 32 bytes.
// r[impl ucan-signature.round-trip]
pub open spec fn secret_key_valid_spec(sk: SecretKey) -> bool {
    sk.bytes.len() == SECRET_KEY_LEN
}

/// Well-formed public key: exactly 32 bytes.
// r[impl ucan-signature.public-key-length]
pub open spec fn public_key_valid_spec(pk: PublicKey) -> bool {
    pk.bytes.len() == PUBLIC_KEY_LEN
}

/// Well-formed signature: exactly 64 bytes.
// r[impl ucan-signature.signature-length]
pub open spec fn signature_valid_spec(sig: Ed25519Signature) -> bool {
    sig.bytes.len() == SIGNATURE_LEN
}

// --- Axioms modeling Ed25519 contracts ---

/// Axiom: signing with sk then verifying with the derived pk succeeds.
// r[verify ucan-signature.round-trip]
#[verifier::external_body]
pub proof fn axiom_sign_verify_round_trip(sk: Seq<u8>, msg: Seq<u8>)
    requires sk.len() == SECRET_KEY_LEN,
    ensures verify_spec(public_from_secret_spec(sk), msg, sign_spec(sk, msg)) == true,
{
}

/// Axiom: wrong public key rejects.
// r[verify ucan-signature.key-binding]
#[verifier::external_body]
pub proof fn axiom_wrong_key_rejects(sk: Seq<u8>, pk: Seq<u8>, msg: Seq<u8>)
    requires
        sk.len() == SECRET_KEY_LEN,
        pk.len() == PUBLIC_KEY_LEN,
        pk != public_from_secret_spec(sk),
    ensures verify_spec(pk, msg, sign_spec(sk, msg)) == false,
{
}

/// Axiom: wrong message rejects.
// r[verify ucan-signature.message-binding]
#[verifier::external_body]
pub proof fn axiom_wrong_message_rejects(sk: Seq<u8>, msg1: Seq<u8>, msg2: Seq<u8>)
    requires
        sk.len() == SECRET_KEY_LEN,
        msg1 != msg2,
    ensures verify_spec(public_from_secret_spec(sk), msg2, sign_spec(sk, msg1)) == false,
{
}

// --- Exec functions ---

/// Sign a message with a secret key, producing a 64-byte signature.
// r[impl ucan-signature.round-trip]
// r[impl ucan-signature.signature-length]
#[verifier::external_body]
pub fn sign(sk: &SecretKey, message: &Vec<u8>) -> (result: Ed25519Signature)
    requires secret_key_valid_spec(*sk),
    ensures
        result.bytes@ == sign_spec(sk.bytes@, message@),
        result.bytes.len() == SIGNATURE_LEN,
{
    Ed25519Signature { bytes: sign_runtime(&sk.bytes, message) }
}

/// Verify a signature against a public key and message.
// r[impl ucan-signature.round-trip]
// r[impl ucan-signature.key-binding]
// r[impl ucan-signature.message-binding]
#[verifier::external_body]
pub fn verify(pk: &PublicKey, message: &Vec<u8>, sig: &Ed25519Signature) -> (result: bool)
    requires
        public_key_valid_spec(*pk),
        signature_valid_spec(*sig),
    ensures result == verify_spec(pk.bytes@, message@, sig.bytes@),
{
    verify_runtime(&pk.bytes, message, &sig.bytes)
}

/// Derive the public key from a secret key.
// r[impl ucan-signature.public-key-length]
#[verifier::external_body]
pub fn public_from_secret(sk: &SecretKey) -> (result: PublicKey)
    requires secret_key_valid_spec(*sk),
    ensures
        result.bytes@ == public_from_secret_spec(sk.bytes@),
        result.bytes.len() == PUBLIC_KEY_LEN,
{
    PublicKey { bytes: public_from_secret_runtime(&sk.bytes) }
}

// --- Derived proofs ---

/// Sign-then-verify round-trip for well-formed keys.
// r[verify ucan-signature.round-trip]
pub proof fn sign_verify_round_trip(sk: SecretKey, msg: Seq<u8>)
    requires secret_key_valid_spec(sk),
    ensures
        verify_spec(
            public_from_secret_spec(sk.bytes@),
            msg,
            sign_spec(sk.bytes@, msg),
        ) == true,
{
    axiom_sign_verify_round_trip(sk.bytes@, msg);
}

/// Wrong public key rejects — derived from axiom.
// r[verify ucan-signature.key-binding]
pub proof fn wrong_key_rejects(sk: SecretKey, pk: PublicKey, msg: Seq<u8>)
    requires
        secret_key_valid_spec(sk),
        public_key_valid_spec(pk),
        pk.bytes@ != public_from_secret_spec(sk.bytes@),
    ensures
        verify_spec(pk.bytes@, msg, sign_spec(sk.bytes@, msg)) == false,
{
    axiom_wrong_key_rejects(sk.bytes@, pk.bytes@, msg);
}

/// Wrong message rejects — derived from axiom.
// r[verify ucan-signature.message-binding]
pub proof fn wrong_message_rejects(sk: SecretKey, msg1: Seq<u8>, msg2: Seq<u8>)
    requires
        secret_key_valid_spec(sk),
        msg1 != msg2,
    ensures
        verify_spec(
            public_from_secret_spec(sk.bytes@),
            msg2,
            sign_spec(sk.bytes@, msg1),
        ) == false,
{
    axiom_wrong_message_rejects(sk.bytes@, msg1, msg2);
}

/// Sign is deterministic: same inputs always produce the same spec output.
// r[impl ucan-signature.deterministic]
// r[verify ucan-signature.deterministic]
pub proof fn sign_deterministic(sk: Seq<u8>, msg: Seq<u8>)
    ensures sign_spec(sk, msg) == sign_spec(sk, msg),
{
}

/// Signature length is always 64 bytes.
// r[verify ucan-signature.signature-length]
pub proof fn signature_length(sk: Seq<u8>, msg: Seq<u8>)
    ensures sign_spec(sk, msg).len() == SIGNATURE_LEN,
{
}

/// Public key length is always 32 bytes.
// r[verify ucan-signature.public-key-length]
pub proof fn public_key_length(sk: Seq<u8>)
    ensures public_from_secret_spec(sk).len() == PUBLIC_KEY_LEN,
{
}

} // verus!

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_round_trip() {
        use ed25519_dalek::SigningKey;
        let sk_seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&sk_seed);
        let pk_bytes = signing_key.verifying_key().to_bytes().to_vec();

        let sk = SecretKey { bytes: sk_seed.to_vec() };
        let pk = PublicKey { bytes: pk_bytes };
        let message = vec![1u8, 2, 3, 4, 5];

        let sig = sign(&sk, &message);
        assert_eq!(sig.bytes.len(), 64);
        assert!(verify(&pk, &message, &sig));
    }

    #[test]
    fn test_wrong_key_rejects() {
        let sk1 = SecretKey { bytes: vec![1u8; 32] };
        let sk2 = SecretKey { bytes: vec![2u8; 32] };
        let pk2 = public_from_secret(&sk2);
        let message = vec![10u8, 20, 30];

        let sig = sign(&sk1, &message);
        assert!(!verify(&pk2, &message, &sig));
    }

    #[test]
    fn test_wrong_message_rejects() {
        let sk = SecretKey { bytes: vec![7u8; 32] };
        let pk = public_from_secret(&sk);
        let msg1 = vec![1u8, 2, 3];
        let msg2 = vec![4u8, 5, 6];

        let sig = sign(&sk, &msg1);
        assert!(!verify(&pk, &msg2, &sig));
    }

    #[test]
    fn test_sign_deterministic() {
        let sk = SecretKey { bytes: vec![99u8; 32] };
        let message = vec![0u8; 100];

        let sig1 = sign(&sk, &message);
        let sig2 = sign(&sk, &message);
        assert_eq!(sig1.bytes, sig2.bytes);
    }

    #[test]
    fn test_public_key_length() {
        let sk = SecretKey { bytes: vec![55u8; 32] };
        let pk = public_from_secret(&sk);
        assert_eq!(pk.bytes.len(), 32);
    }
}
