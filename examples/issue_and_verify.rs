use std::error::Error;

use ucan::AudienceDid;
use ucan::CapabilitySet;
use ucan::ED25519_SECRET_KEY_BYTES;
use ucan::Ed25519InMemorySigner;
use ucan::KeyResolutionContext;
use ucan::ProofCollection;
use ucan::TokenSigner;
use ucan::TokenTimeBounds;
use ucan::VerificationContext;
use ucan::VerificationTime;
use ucan::issue_token_with_signer;
use ucan::verify_compact_token;

const ISSUER_KEY_BYTE: u8 = 7;
const AUDIENCE_KEY_BYTE: u8 = 9;
const NOT_BEFORE_SECONDS: u64 = 1_000;
const EXPIRES_AT_SECONDS: u64 = 2_000;
const VERIFY_AT_SECONDS: u64 = 1_500;
const RESOURCE_DID: &str = "did:key:z6Mkresource";
const ABILITY: &str = "store/add";

fn main() -> Result<(), Box<dyn Error>> {
    let issuer = Ed25519InMemorySigner::from_seed_bytes([ISSUER_KEY_BYTE; ED25519_SECRET_KEY_BYTES]);
    let audience_key = Ed25519InMemorySigner::from_seed_bytes([AUDIENCE_KEY_BYTE; ED25519_SECRET_KEY_BYTES]);
    let audience = AudienceDid::from(audience_key.issuer()?);
    let capabilities = CapabilitySet::single(RESOURCE_DID, ABILITY)?;
    let proofs = ProofCollection::empty();
    let time_bounds = TokenTimeBounds::new(NOT_BEFORE_SECONDS, EXPIRES_AT_SECONDS)?;

    let token = issue_token_with_signer(&issuer, &audience, &capabilities, &proofs, time_bounds)?;
    let keys = KeyResolutionContext::new(vec![issuer.verification_key()?]);
    let context = VerificationContext::new(
        VerificationTime::from_unix_seconds(VERIFY_AT_SECONDS),
        keys,
        ProofCollection::empty(),
    );
    let verified = verify_compact_token(&token, &context)?;

    println!("issued token: {token}");
    println!("issuer: {}", verified.issuer());
    println!("audience: {}", verified.audience());
    println!("capability count: {}", verified.capabilities().as_slice().len());
    Ok(())
}
