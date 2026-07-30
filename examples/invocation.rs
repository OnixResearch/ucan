use std::cell::RefCell;
use std::collections::HashSet;
use std::error::Error;

use ucan::AudienceDid;
use ucan::AuthorizationRequest;
use ucan::CapabilitySet;
use ucan::CaveatDecision;
use ucan::CaveatDocument;
use ucan::CaveatIdentifier;
use ucan::CaveatPolicy;
use ucan::CaveatPolicySet;
use ucan::ED25519_SECRET_KEY_BYTES;
use ucan::Ed25519InMemorySigner;
use ucan::InvocationRequest;
use ucan::InvocationResult;
use ucan::KeyResolutionContext;
use ucan::ProofCollection;
use ucan::ProofReference;
use ucan::ProofReferences;
use ucan::ReplayAdmission;
use ucan::ReplayAdmissionError;
use ucan::TokenSigner;
use ucan::TokenTimeBounds;
use ucan::VerificationContext;
use ucan::VerificationTime;
use ucan::issue_token_with_signer;
use ucan::verify_invocation_with_replay;

const ISSUER_KEY_BYTE: u8 = 7;
const AUDIENCE_KEY_BYTE: u8 = 9;
const VERIFY_AT_SECONDS: u64 = 1_500;

struct PayloadEqualsPolicy;

impl CaveatPolicy for PayloadEqualsPolicy {
    fn evaluate(&self, caveat: &CaveatDocument, _request: &AuthorizationRequest) -> CaveatDecision {
        if caveat.payload() == b"allow" {
            CaveatDecision::Satisfied
        } else {
            CaveatDecision::Rejected {
                message: "payload did not equal allow".to_owned(),
            }
        }
    }
}

struct ExamplePolicies {
    identity: CaveatIdentifier,
    policy: PayloadEqualsPolicy,
}

#[derive(Default)]
struct ExampleReplayAdmission {
    seen: RefCell<HashSet<(ProofReference, String, String)>>,
}

impl ReplayAdmission for ExampleReplayAdmission {
    fn admit_invocation(
        &self,
        token_reference: &ProofReference,
        resource: &str,
        ability: &str,
    ) -> Result<(), ReplayAdmissionError> {
        let key = (token_reference.clone(), resource.to_owned(), ability.to_owned());
        if self.seen.borrow_mut().insert(key) {
            Ok(())
        } else {
            Err(ReplayAdmissionError::Duplicate {
                reference: token_reference.clone(),
            })
        }
    }
}

impl CaveatPolicySet for ExamplePolicies {
    fn policy_for(&self, caveat: &CaveatIdentifier) -> Option<&dyn CaveatPolicy> {
        if caveat == &self.identity {
            Some(&self.policy)
        } else {
            None
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let issuer = Ed25519InMemorySigner::from_seed_bytes([ISSUER_KEY_BYTE; ED25519_SECRET_KEY_BYTES]);
    let audience_key = Ed25519InMemorySigner::from_seed_bytes([AUDIENCE_KEY_BYTE; ED25519_SECRET_KEY_BYTES]);
    let audience = AudienceDid::from(audience_key.issuer()?);
    let caveat =
        CaveatDocument::new("example".to_owned(), "payload-equals".to_owned(), "gate".to_owned(), b"allow".to_vec())?;
    let capabilities = CapabilitySet::new(vec![ucan::CapabilityDocument::with_caveats(
        "did:key:z6Mkresource".to_owned(),
        "store/*".to_owned(),
        vec![caveat],
    )?])?;
    let token = issue_token_with_signer(
        &issuer,
        &audience,
        &capabilities,
        &ProofReferences::empty(),
        TokenTimeBounds::new(1_000, 2_000)?,
    )?;
    let context = VerificationContext::new(
        VerificationTime::from_unix_seconds(VERIFY_AT_SECONDS),
        KeyResolutionContext::new(vec![issuer.verification_key()?]),
        ProofCollection::empty(),
    );
    let policies = ExamplePolicies {
        identity: CaveatIdentifier::new("example", "payload-equals", "gate")?,
        policy: PayloadEqualsPolicy,
    };
    let replay = ExampleReplayAdmission::default();
    let result = verify_invocation_with_replay(
        &InvocationRequest::new(&token, &context, "did:key:z6Mkresource/photos", "store/add", &policies),
        &replay,
    );

    match result {
        InvocationResult::Allowed { invocation } => {
            println!(
                "invocation allowed for {} via {}",
                invocation.audience(),
                invocation.matched_capability().ability
            );
        }
        InvocationResult::Denied { reason } => println!("invocation denied: {reason:?}"),
    }
    Ok(())
}
