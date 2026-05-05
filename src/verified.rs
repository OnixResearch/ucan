use core::fmt;

use verified_logic::scope;
use verified_logic::token_timestamp;
use verified_logic::ucan_ability;
use verified_logic::ucan_backend_transcript;
use verified_logic::ucan_capability_merge;
use verified_logic::ucan_caveat;
use verified_logic::ucan_chain;
use verified_logic::ucan_compact;
use verified_logic::ucan_delegation_depth;
use verified_logic::ucan_did;
use verified_logic::ucan_invocation;
use verified_logic::ucan_proof_traversal;
use verified_logic::ucan_revocation;
use verified_logic::ucan_signature;
use verified_logic::ucan_temporal;
use verified_logic::ucan_token;
use verified_logic::ucan_verification_stage;
use verified_logic::web_of_trust_attestation;
use verified_logic::web_of_trust_policy;
use verified_logic::web_of_trust_principal;
use verified_logic::web_of_trust_revocation;
use verified_logic::web_of_trust_ucan_authorizer;

use crate::shell::CapabilityDocument;

const ABILITY_SEGMENT_SEPARATOR: char = '/';
const WILDCARD_ABILITY_SEGMENT: &[u8] = b"*";
const DEFAULT_CLOCK_SKEW_SECONDS: u64 = 60;

pub type VerifiedResult<T> = std::result::Result<T, VerifiedPrimitiveError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedPrimitiveError {
    InvalidCapability { source: ucan_core::CapabilityError },
    EmptyTimeWindowChain,
    InvalidSecretKeyLength { actual: usize },
    InvalidPublicKeyLength { actual: usize },
    InvalidSignatureLength { actual: usize },
    InvalidPrincipalDigestLength { actual: usize },
    TokenValidation { failure: TokenValidationFailure },
}

impl fmt::Display for VerifiedPrimitiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCapability { source } => write!(formatter, "invalid capability: {source}"),
            Self::EmptyTimeWindowChain => formatter.write_str("time window chain must not be empty"),
            Self::InvalidSecretKeyLength { actual } => {
                write!(formatter, "ed25519 secret keys must be {} bytes, got {actual}", ucan_signature::SECRET_KEY_LEN)
            }
            Self::InvalidPublicKeyLength { actual } => {
                write!(formatter, "ed25519 public keys must be {} bytes, got {actual}", ucan_signature::PUBLIC_KEY_LEN)
            }
            Self::InvalidSignatureLength { actual } => {
                write!(formatter, "ed25519 signatures must be {} bytes, got {actual}", ucan_signature::SIGNATURE_LEN)
            }
            Self::InvalidPrincipalDigestLength { actual } => {
                write!(
                    formatter,
                    "web-of-trust principal digests must be {} bytes, got {actual}",
                    web_of_trust_principal::PRINCIPAL_ID_LEN
                )
            }
            Self::TokenValidation { failure } => write!(formatter, "token validation failed: {failure}"),
        }
    }
}

impl std::error::Error for VerifiedPrimitiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidCapability { source } => Some(source),
            Self::EmptyTimeWindowChain
            | Self::InvalidSecretKeyLength { .. }
            | Self::InvalidPublicKeyLength { .. }
            | Self::InvalidSignatureLength { .. }
            | Self::InvalidPrincipalDigestLength { .. }
            | Self::TokenValidation { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenValidationFailure {
    ExpiredToken,
    NotYetValid,
    SelfDelegation,
    MissingIssuer,
    MissingAudience,
    MissingAttenuations,
    InvalidSignature,
}

impl fmt::Display for TokenValidationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExpiredToken => formatter.write_str("token expired"),
            Self::NotYetValid => formatter.write_str("token not yet valid"),
            Self::SelfDelegation => formatter.write_str("issuer and audience must differ"),
            Self::MissingIssuer => formatter.write_str("issuer must be present"),
            Self::MissingAudience => formatter.write_str("audience must be present"),
            Self::MissingAttenuations => formatter.write_str("at least one capability must be present"),
            Self::InvalidSignature => formatter.write_str("signature must verify"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenTimeWindow {
    pub not_before_seconds: u64,
    pub expires_at_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenEnvelopeInput {
    pub issuer_did: String,
    pub audience_did: String,
    pub capabilities: Vec<CapabilityDocument>,
    pub proofs: Vec<Vec<u8>>,
    pub expires_at_seconds: u64,
    pub not_before_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCompactTokenParts {
    pub header: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCompactTokenEnvelope {
    pub compact: Vec<u8>,
    pub parts: VerifiedCompactTokenParts,
    pub signing_input: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedVerificationStage {
    Parse,
    Structural,
    KeyResolution,
    Signature,
    Envelope,
    Revocation,
    ProofLoad,
    ProofChain,
    Authorization,
    Accepted,
}

impl VerifiedVerificationStage {
    const fn from_verified_logic(stage: u8) -> Self {
        match stage {
            ucan_verification_stage::STAGE_PARSE => Self::Parse,
            ucan_verification_stage::STAGE_STRUCTURAL => Self::Structural,
            ucan_verification_stage::STAGE_KEY_RESOLUTION => Self::KeyResolution,
            ucan_verification_stage::STAGE_SIGNATURE => Self::Signature,
            ucan_verification_stage::STAGE_ENVELOPE => Self::Envelope,
            ucan_verification_stage::STAGE_REVOCATION => Self::Revocation,
            ucan_verification_stage::STAGE_PROOF_LOAD => Self::ProofLoad,
            ucan_verification_stage::STAGE_PROOF_CHAIN => Self::ProofChain,
            ucan_verification_stage::STAGE_AUTHORIZATION => Self::Authorization,
            _ => Self::Accepted,
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedVerificationStageTranscript {
    pub parse_ok: bool,
    pub structural_ok: bool,
    pub key_resolved: bool,
    pub signature_valid: bool,
    pub envelope_valid: bool,
    pub revocation_clear: bool,
    pub proofs_loaded: bool,
    pub proof_chain_valid: bool,
    pub authorized: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedVerificationStageOutcome {
    pub accepted: bool,
    pub first_failed_stage: VerifiedVerificationStage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChainEntry {
    pub issuer_did: String,
    pub audience_did: String,
    pub capabilities: Vec<CapabilityDocument>,
    pub expires_at_seconds: u64,
    pub not_before_seconds: u64,
    pub signature_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedInvocationChainRequest {
    pub authorization_reference: Vec<u8>,
    pub invoker_did: String,
    pub resource: String,
    pub ability: String,
    pub leaf_capability_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProofTraversalEntry {
    pub proof_reference: Vec<u8>,
    pub issuer_did: String,
    pub audience_did: String,
    pub capabilities: Vec<CapabilityDocument>,
    pub caveat_ids: Vec<Vec<u8>>,
    pub expires_at_seconds: u64,
    pub not_before_seconds: u64,
    pub signature_valid: bool,
    pub revoked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedProofTraversalBudget {
    pub max_depth: u64,
    pub max_proofs: u64,
    pub max_input_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProofTraversalTarget {
    pub resource: String,
    pub ability: String,
    pub now_seconds: u64,
    pub tolerance_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProofTraversalTranscript {
    pub entries: Vec<VerifiedProofTraversalEntry>,
    pub visited_references: Vec<Vec<u8>>,
    pub total_input_bytes: u64,
    pub target: VerifiedProofTraversalTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProofTraversalDagTranscript {
    pub entries: Vec<VerifiedProofTraversalEntry>,
    pub parent_indices: Vec<Vec<usize>>,
    pub visited_references: Vec<Vec<u8>>,
    pub total_input_bytes: u64,
    pub target: VerifiedProofTraversalTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDidKey {
    pub public_key_bytes: Vec<u8>,
    pub codec: u64,
    pub encoded: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedWebOfTrustAuthorization {
    Authorized,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedWebOfTrustCaveat {
    TimeBound { not_after_seconds: u64 },
    RateLimit { max_count: u64, window_seconds: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedWebOfTrustCaveatContext {
    pub now_seconds: u64,
    pub count_in_window: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedWebOfTrustAttestation {
    pub issuer_key_bytes: Vec<u8>,
    pub issuer_digest: Vec<u8>,
    pub subject_key_bytes: Vec<u8>,
    pub subject_digest: Vec<u8>,
    pub role_tag: u8,
    pub not_before_seconds: u64,
    pub not_after_seconds: u64,
    pub sequence_no: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedWebOfTrustRevocation {
    pub issuer_key_bytes: Vec<u8>,
    pub issuer_digest: Vec<u8>,
    pub target_kind_tag: u8,
    pub exact_payload_target: Vec<u8>,
    pub family_subject_key_bytes: Vec<u8>,
    pub family_subject_digest: Vec<u8>,
    pub family_role_tag: u8,
    pub effective_time_seconds: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct VerifiedWebOfTrustUcanAuthorizationRequest {
    pub token_envelope: TokenEnvelopeInput,
    pub signature_valid: bool,
    pub now_seconds: u64,
    pub tolerance_seconds: u64,
    pub ability_allowed: bool,
    pub caveats_contained: bool,
    pub active_caveats: Vec<VerifiedWebOfTrustCaveat>,
    pub caveat_context: VerifiedWebOfTrustCaveatContext,
    pub did_cid_linked: bool,
    pub root_principal_digests: Vec<Vec<u8>>,
    pub attestations: Vec<VerifiedWebOfTrustAttestation>,
    pub revocations: Vec<VerifiedWebOfTrustRevocation>,
    pub subject_principal_digest: Vec<u8>,
    pub threshold: usize,
    pub depth: usize,
    pub trust_time_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCapability {
    document: CapabilityDocument,
    ability_segments: Vec<Vec<u8>>,
}

impl VerifiedCapability {
    /// Build a verified-logic-backed capability wrapper.
    ///
    /// # Errors
    ///
    /// Returns [`VerifiedPrimitiveError::InvalidCapability`] when the resource
    /// or ability violates the core capability rules.
    pub fn new(resource: String, ability: String) -> VerifiedResult<Self> {
        let document = CapabilityDocument::new(resource, ability).map_err(|error| match error {
            crate::Error::Capability { source } => VerifiedPrimitiveError::InvalidCapability { source },
            crate::Error::Io { .. } => unreachable!("CapabilityDocument::new performs validation only"),
            crate::Error::Caveat { .. } | crate::Error::TokenClaims { .. } => {
                unreachable!("CapabilityDocument::new does not include caveats")
            }
        })?;
        build_verified_capability(document)
    }

    /// Convert an owned capability document into a verified-logic wrapper.
    ///
    /// # Errors
    ///
    /// Returns [`VerifiedPrimitiveError::InvalidCapability`] when the document
    /// fails core validation.
    pub fn from_document(document: CapabilityDocument) -> VerifiedResult<Self> {
        validate_capability_document(&document)?;
        build_verified_capability(document)
    }

    #[must_use]
    pub const fn document(&self) -> &CapabilityDocument {
        &self.document
    }

    #[must_use]
    pub const fn resource(&self) -> &str {
        self.document.resource.as_str()
    }

    #[must_use]
    pub const fn ability(&self) -> &str {
        self.document.ability.as_str()
    }

    #[must_use]
    pub fn contains(&self, child: &Self) -> bool {
        let resource_covers = scope::covers(self.resource().as_bytes(), child.resource().as_bytes());
        let ability_subsumes = ucan_ability::ability_subsumes(&self.verified_ability(), &child.verified_ability());
        resource_covers && ability_subsumes
    }

    /// Return whether the verified ability contains a wildcard segment.
    #[must_use]
    pub fn has_wildcard_segment(&self) -> bool {
        self.ability_segments.iter().any(|segment| segment.as_slice() == WILDCARD_ABILITY_SEGMENT)
    }

    /// Return whether this capability can represent a concrete operation request.
    #[must_use]
    pub fn is_concrete(&self) -> bool {
        !self.has_wildcard_segment()
    }

    /// Check whether this capability authorizes a concrete resource/ability.
    ///
    /// # Errors
    ///
    /// Returns [`VerifiedPrimitiveError::InvalidCapability`] when the
    /// requested resource or ability is not a valid capability input.
    pub fn authorizes(&self, resource: &str, ability: &str) -> VerifiedResult<bool> {
        let requested = Self::new(resource.to_owned(), ability.to_owned())?;
        Ok(self.contains(&requested))
    }

    fn verified_ability(&self) -> ucan_ability::Ability {
        ucan_ability::Ability {
            segments: self.ability_segments.clone(),
        }
    }
}

#[must_use]
pub fn token_time_valid_at(
    issued_at_seconds: u64,
    expires_at_seconds: u64,
    now_seconds: u64,
    tolerance_seconds: u64,
) -> bool {
    token_timestamp::token_time_valid(issued_at_seconds, expires_at_seconds, now_seconds, tolerance_seconds)
}

#[must_use]
pub fn token_time_valid(issued_at_seconds: u64, expires_at_seconds: u64, now_seconds: u64) -> bool {
    token_time_valid_at(issued_at_seconds, expires_at_seconds, now_seconds, DEFAULT_CLOCK_SKEW_SECONDS)
}

#[must_use]
pub fn token_needs_refresh(issued_at_seconds: u64, expires_at_seconds: u64, now_seconds: u64) -> bool {
    token_timestamp::needs_refresh(issued_at_seconds, expires_at_seconds, now_seconds)
}

/// Intersect a UCAN delegation time-window chain.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::EmptyTimeWindowChain`] when no windows are
/// provided.
pub fn compose_time_window_chain(windows: &[TokenTimeWindow]) -> VerifiedResult<TokenTimeWindow> {
    if windows.is_empty() {
        return Err(VerifiedPrimitiveError::EmptyTimeWindowChain);
    }

    let verified_windows = windows.iter().map(to_verified_time_window).collect();
    let composed = ucan_temporal::compose_chain(&verified_windows);
    Ok(from_verified_time_window(&composed))
}

/// Check whether a child capability list is a valid attenuation of a parent.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::InvalidCapability`] when any capability in
/// either list fails core validation.
pub fn attenuation_chain_is_valid(
    parent_capabilities: &[CapabilityDocument],
    child_capabilities: &[CapabilityDocument],
) -> VerifiedResult<bool> {
    let parent_capabilities = build_token_capabilities(parent_capabilities)?;
    let child_capabilities = build_token_capabilities(child_capabilities)?;
    Ok(ucan_token::check_attenuation_chain(&parent_capabilities, &child_capabilities))
}

/// Check whether a finite capability set authorizes an exact resource/ability request.
///
/// This advanced helper mirrors the vendored capability-merge authorizer: it
/// accepts when any supplied capability has a resource byte-prefix that contains
/// the requested resource and an ability that exactly equals the requested
/// ability. It intentionally does not perform wildcard ability subsumption;
/// callers needing full UCAN token/effective-delegation semantics should use the
/// shell authorization APIs instead.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::InvalidCapability`] when any supplied
/// capability or the requested resource/ability pair fails core validation.
pub fn capability_set_authorizes(
    capabilities: &[CapabilityDocument],
    resource: &str,
    ability: &str,
) -> VerifiedResult<bool> {
    let requested = CapabilityDocument::new(resource.to_owned(), ability.to_owned()).map_err(|error| match error {
        crate::Error::Capability { source } => VerifiedPrimitiveError::InvalidCapability { source },
        crate::Error::Io { .. } => unreachable!("CapabilityDocument::new performs validation only"),
        crate::Error::Caveat { .. } | crate::Error::TokenClaims { .. } => {
            unreachable!("CapabilityDocument::new does not include caveats")
        }
    })?;
    let capability_set = build_capability_merge_entries(capabilities)?;
    Ok(ucan_capability_merge::check_authorized_by(
        &capability_set,
        &requested.resource.as_bytes().to_vec(),
        &requested.ability.as_bytes().to_vec(),
    ))
}

/// Check whether a parent proof audience links to a child token issuer.
///
/// This is the two-entry proof-link slice of the verified UCAN chain checker;
/// it does not perform proof resolution, signature verification, revocation, or
/// temporal validation.
#[must_use]
pub fn proof_link_is_valid(parent_audience_did: &str, child_issuer_did: &str) -> bool {
    let chain = vec![
        ucan_chain::ChainEntry {
            iss: Vec::new(),
            aud: parent_audience_did.as_bytes().to_vec(),
            att: Vec::new(),
            exp: 0,
            nbf: 0,
            sig_valid: true,
        },
        ucan_chain::ChainEntry {
            iss: child_issuer_did.as_bytes().to_vec(),
            aud: Vec::new(),
            att: Vec::new(),
            exp: 0,
            nbf: 0,
            sig_valid: true,
        },
    ];
    ucan_chain::check_chain_linked(&chain)
}

/// Check structural validity for caller-supplied resolved UCAN chain entries.
///
/// This is the shell bridge to verified-logic's composed structural chain
/// checker. It checks finite issuer/audience linkage, caller-provided
/// signature-valid flags, exact attenuation narrowing, and temporal validity.
/// It does not perform proof resolution, cryptographic signature verification,
/// DID/key lookup, revocation checks, caveat policy evaluation, wildcard
/// containment replacement, networking, persistence, or ambient clock reads.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::InvalidCapability`] when any supplied
/// capability fails core capability validation.
pub fn structural_chain_is_valid(
    entries: &[VerifiedChainEntry],
    now_seconds: u64,
    tolerance_seconds: u64,
) -> VerifiedResult<bool> {
    let chain = entries.iter().map(to_verified_chain_entry).collect::<VerifiedResult<Vec<_>>>()?;
    Ok(ucan_chain::check_chain_structural_valid(&chain, now_seconds, tolerance_seconds))
}

/// Check structural validity and non-revocation for caller-supplied resolved chain data.
///
/// This is the shell bridge to verified-logic's composed revocation-chain
/// checker. It checks finite structural chain validity, one-to-one alignment
/// between chain entries and proof-reference bytes, and finite revoked-reference
/// non-membership.
///
/// It does not resolve proofs, derive references from compact tokens, check
/// backend availability or revocation freshness, perform cryptographic signature
/// verification, evaluate caveat policy, access registries, use storage/network
/// backends, or read an ambient clock.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::InvalidCapability`] when any supplied
/// chain capability fails core capability validation.
pub fn structural_chain_not_revoked_is_valid(
    entries: &[VerifiedChainEntry],
    chain_references: &[Vec<u8>],
    revoked_references: &[Vec<u8>],
    now_seconds: u64,
    tolerance_seconds: u64,
) -> VerifiedResult<bool> {
    let chain = entries.iter().map(to_verified_chain_entry).collect::<VerifiedResult<Vec<_>>>()?;
    let revocation_set = ucan_revocation::RevocationSet {
        entries: revoked_references.to_vec(),
    };
    let chain_references = chain_references.to_vec();
    Ok(ucan_revocation::check_chain_structural_valid_not_revoked(
        &revocation_set,
        &chain,
        &chain_references,
        now_seconds,
        tolerance_seconds,
    ))
}

/// Check resolved chain authorization for a concrete invocation request.
///
/// This is the shell bridge to verified-logic's composed invocation-chain
/// checker. It checks finite structural chain validity, aligned proof-reference
/// non-revocation, explicit authorization-reference binding to the chain leaf,
/// leaf capability index admission, invoker/audience equality, request-resource
/// refinement, and exact ability equality.
///
/// It does not resolve proofs, parse or verify compact UCANs, perform
/// cryptographic signature verification, evaluate caveat policy, replace
/// wildcard containment semantics, check revocation backend availability or
/// freshness, access registries/storage/network backends, persist receipts, or
/// read an ambient clock.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::InvalidCapability`] when any supplied
/// chain capability fails core capability validation.
pub fn invocation_chain_is_authorized(
    entries: &[VerifiedChainEntry],
    chain_references: &[Vec<u8>],
    revoked_references: &[Vec<u8>],
    request: &VerifiedInvocationChainRequest,
    now_seconds: u64,
    tolerance_seconds: u64,
) -> VerifiedResult<bool> {
    let chain = entries.iter().map(to_verified_chain_entry).collect::<VerifiedResult<Vec<_>>>()?;
    let chain_references = chain_references.to_vec();
    let revocation_set = ucan_revocation::RevocationSet {
        entries: revoked_references.to_vec(),
    };
    let invocation = ucan_invocation::Invocation {
        auth_cid: request.authorization_reference.clone(),
        invoker: request.invoker_did.as_bytes().to_vec(),
        resource: request.resource.as_bytes().to_vec(),
        ability: request.ability.as_bytes().to_vec(),
        timestamp: now_seconds,
    };

    Ok(ucan_invocation::check_invocation_chain_authorized(
        &revocation_set,
        &chain,
        &chain_references,
        &invocation,
        request.leaf_capability_index,
        now_seconds,
        tolerance_seconds,
    ))
}

/// Check that compact-token bytes match a verified separator-free three-part split.
///
/// This is a data-only bridge to vendored verified-logic. It checks that the
/// caller/shell-supplied encoded compact-token parts contain no embedded compact
/// separators and that the compact bytes equal `header.payload.signature`.
///
/// It does not perform the string split, decode base64url, parse JSON, derive
/// proof references, hash, sign, verify signatures, resolve keys, fetch proofs,
/// query revocation backends, access storage/network backends, persist state,
/// replay-protect, or read an ambient clock.
#[must_use]
pub fn compact_token_split_is_valid(compact: &[u8], parts: &VerifiedCompactTokenParts) -> bool {
    let parts = ucan_compact::CompactTokenParts {
        header: parts.header.clone(),
        payload: parts.payload.clone(),
        signature: parts.signature.clone(),
    };
    ucan_compact::compact_split_matches_parts(&compact.to_vec(), &parts)
}

/// Check that compact-token bytes and signing input match verified framing.
///
/// This is a data-only bridge to vendored verified-logic. It checks only the
/// canonical byte framing over already-encoded compact-token parts:
/// `header.payload.signature` for the compact token and `header.payload` for
/// the signing input.
///
/// It does not split compact strings, decode base64url, parse JSON, derive
/// proof references, hash, sign, verify signatures, resolve keys, fetch proofs,
/// query revocation backends, access storage/network backends, persist state,
/// replay-protect, or read an ambient clock.
#[must_use]
pub fn compact_token_envelope_is_valid(envelope: &VerifiedCompactTokenEnvelope) -> bool {
    let parts = ucan_compact::CompactTokenParts {
        header: envelope.parts.header.clone(),
        payload: envelope.parts.payload.clone(),
        signature: envelope.parts.signature.clone(),
    };
    ucan_compact::compact_envelope_matches_parts(&envelope.compact, &parts, &envelope.signing_input)
}

/// Evaluate a finite verification-stage transcript through vendored verified logic.
///
/// This bridge consumes only caller/shell-supplied stage facts. It does not parse
/// tokens, decode base64url or JSON, hash proof references, verify Ed25519
/// signatures, fetch proofs, query revocation state, evaluate caveat semantics,
/// persist state, replay-protect, or read an ambient clock.
#[must_use]
pub fn verification_stage_transcript_outcome(
    transcript: &VerifiedVerificationStageTranscript,
) -> VerifiedVerificationStageOutcome {
    let transcript = ucan_verification_stage::VerificationStageTranscript {
        parse_ok: transcript.parse_ok,
        structural_ok: transcript.structural_ok,
        key_resolved: transcript.key_resolved,
        signature_valid: transcript.signature_valid,
        envelope_valid: transcript.envelope_valid,
        revocation_clear: transcript.revocation_clear,
        proofs_loaded: transcript.proofs_loaded,
        proof_chain_valid: transcript.proof_chain_valid,
        authorized: transcript.authorized,
    };
    VerifiedVerificationStageOutcome {
        accepted: ucan_verification_stage::stage_transcript_accepts(&transcript),
        first_failed_stage: VerifiedVerificationStage::from_verified_logic(
            ucan_verification_stage::first_failed_stage(&transcript),
        ),
    }
}

/// Check a finite proof traversal transcript produced by the shell.
///
/// This is the shell bridge to verified-logic's traversal-transcript model. It
/// checks caller-supplied resolved entries, visited-reference alignment,
/// duplicate-reference/cycle rejection, depth/proof/input-byte budgets,
/// issuer/audience linkage, attenuation narrowing, ordered caveat-id
/// preservation, leaf authorization, evaluation-time validity, and supplied
/// revocation-denial facts.
///
/// It does not resolve proofs, parse compact UCANs, verify signatures from
/// bytes, derive proof references, query revocation backends, evaluate opaque
/// caveat policies, access storage/network backends, persist state, sign,
/// replay-protect, or read an ambient clock.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::InvalidCapability`] when any supplied
/// traversal capability fails core capability validation.
pub fn proof_traversal_transcript_is_valid(
    transcript: &VerifiedProofTraversalTranscript,
    budget: &VerifiedProofTraversalBudget,
) -> VerifiedResult<bool> {
    let transcript = to_proof_traversal_transcript(transcript)?;
    let budget = ucan_proof_traversal::TraversalBudget {
        max_depth: budget.max_depth,
        max_proofs: budget.max_proofs,
        max_input_bytes: budget.max_input_bytes,
    };
    Ok(ucan_proof_traversal::traversal_transcript_valid(&transcript, &budget))
}

/// Validate a finite multi-parent proof DAG transcript with verified logic.
///
/// This is the DAG-shaped shell bridge to verified-logic's traversal-transcript
/// model. It checks caller-supplied resolved entries, topologically ordered
/// parent indices, depth/proof/input-byte budgets, issuer/audience linkage,
/// capability attenuation, ordered caveat-id preservation, leaf authorization,
/// evaluation-time validity, and supplied revocation-denial facts.
///
/// It does not resolve proofs, parse compact UCANs, verify signatures from
/// bytes, derive proof references, query revocation backends, evaluate opaque
/// caveat policies, access storage/network backends, persist state, sign,
/// replay-protect, or read an ambient clock.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::InvalidCapability`] when any supplied
/// traversal capability fails core capability validation.
pub fn proof_traversal_dag_transcript_is_valid(
    transcript: &VerifiedProofTraversalDagTranscript,
    budget: &VerifiedProofTraversalBudget,
) -> VerifiedResult<bool> {
    let transcript = to_proof_traversal_dag_transcript(transcript)?;
    let budget = ucan_proof_traversal::TraversalBudget {
        max_depth: budget.max_depth,
        max_proofs: budget.max_proofs,
        max_input_bytes: budget.max_input_bytes,
    };
    Ok(ucan_proof_traversal::dag_traversal_transcript_valid(&transcript, &budget))
}

/// Derive a Web-of-Trust principal digest from public key bytes.
///
/// This is a deterministic data-only bridge to the vendored WOT principal
/// primitive. It returns the fixed-width principal digest bytes used by
/// [`web_of_trust_ucan_authorization`] inputs, but it does not resolve
/// identities, fetch or validate trust records, check revocations, authorize
/// UCANs, access storage/network backends, or read an ambient clock.
#[must_use]
pub fn web_of_trust_principal_digest(public_key_bytes: &[u8]) -> Vec<u8> {
    web_of_trust_principal::principal_id_from_bytes(public_key_bytes).digest
}

/// Check whether raw Web-of-Trust principal digest bytes are admissible.
///
/// This is a deterministic data-only bridge to the vendored WOT principal
/// digest admission primitive. It accepts exactly the fixed-width digest bytes
/// used by [`web_of_trust_ucan_authorization`] inputs, but it does not resolve
/// identities, fetch or validate trust records, validate attestations, check
/// revocation freshness, authorize UCANs, access storage/network backends,
/// sign, replay-protect, or read an ambient clock.
#[must_use]
pub fn web_of_trust_principal_digest_is_valid(digest: &[u8]) -> bool {
    web_of_trust_principal::principal_id_from_digest_bytes(digest.to_vec()).is_some()
}

/// Check whether one typed caveat is satisfied by explicit caller-supplied context.
///
/// This is an opt-in data-only bridge for callers that choose the vendored typed
/// caveat semantics. It does not interpret opaque shell caveat payloads, install
/// default caveat policies, access storage/network backends, or read an ambient
/// clock.
#[must_use]
pub fn typed_caveat_is_satisfied(caveat: &VerifiedWebOfTrustCaveat, context: &VerifiedWebOfTrustCaveatContext) -> bool {
    let caveat = to_web_of_trust_caveat(caveat);
    let context = to_web_of_trust_caveat_context(context);
    ucan_caveat::caveat_satisfied(&caveat, &context)
}

/// Check whether every supplied typed caveat is satisfied by explicit context.
///
/// This helper is an opt-in bridge to the vendored finite caveat-set predicate.
/// It does not replace shell-owned [`crate::token::CaveatPolicy`] evaluation or
/// allow unknown opaque caveats by default.
#[must_use]
pub fn typed_caveat_set_is_satisfied(
    caveats: &[VerifiedWebOfTrustCaveat],
    context: &VerifiedWebOfTrustCaveatContext,
) -> bool {
    let caveats = caveats.iter().map(to_web_of_trust_caveat).collect::<Vec<_>>();
    let context = to_web_of_trust_caveat_context(context);
    ucan_caveat::caveat_set_satisfied(&caveats, &context)
}

/// Return canonical payload bytes for caller-supplied public WOT attestation evidence.
///
/// This deterministic helper delegates to the vendored WOT attestation payload
/// primitive. It constructs public payload bytes only; it does not sign, resolve
/// identities, fetch evidence, persist state, or read an ambient clock.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::InvalidPrincipalDigestLength`] when a
/// supplied WOT principal digest is not full width.
pub fn web_of_trust_attestation_payload_bytes(
    attestation: &VerifiedWebOfTrustAttestation,
) -> VerifiedResult<Option<Vec<u8>>> {
    let attestation = to_web_of_trust_attestation(attestation)?;
    Ok(web_of_trust_attestation::attestation_payload_bytes(&attestation))
}

/// Check the vendored signature-valid predicate for public WOT attestation evidence.
///
/// This checks the deterministic public evidence fields and provided signature
/// bytes against the vendored facade. It does not derive keys, sign, fetch
/// evidence, or replace aggregate WOT UCAN authorization.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::InvalidPrincipalDigestLength`] when a
/// supplied WOT principal digest is not full width.
pub fn web_of_trust_attestation_signature_is_valid(
    attestation: &VerifiedWebOfTrustAttestation,
) -> VerifiedResult<bool> {
    let attestation = to_web_of_trust_attestation(attestation)?;
    Ok(web_of_trust_attestation::attestation_signature_valid(&attestation))
}

/// Check whether public WOT attestation evidence is active at an explicit time.
///
/// This helper delegates to vendored WOT attestation semantics over finite
/// caller-supplied revocations. It does not fetch revocations or read an ambient
/// clock.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::InvalidPrincipalDigestLength`] when any
/// supplied WOT principal digest is not full width.
pub fn web_of_trust_attestation_is_active_at(
    attestation: &VerifiedWebOfTrustAttestation,
    revocations: &[VerifiedWebOfTrustRevocation],
    time_seconds: u64,
) -> VerifiedResult<bool> {
    let attestation = to_web_of_trust_attestation(attestation)?;
    let revocations = revocations.iter().map(to_web_of_trust_revocation).collect::<VerifiedResult<Vec<_>>>()?;
    Ok(web_of_trust_attestation::attestation_active_at(&attestation, &revocations, time_seconds))
}

/// Return canonical payload bytes for caller-supplied public WOT revocation evidence.
///
/// This deterministic helper delegates to the vendored WOT revocation payload
/// primitive. It constructs public payload bytes only; it does not sign, fetch
/// evidence, persist state, or read an ambient clock.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::InvalidPrincipalDigestLength`] when a
/// supplied WOT principal digest is not full width.
pub fn web_of_trust_revocation_payload_bytes(
    revocation: &VerifiedWebOfTrustRevocation,
) -> VerifiedResult<Option<Vec<u8>>> {
    let revocation = to_web_of_trust_revocation(revocation)?;
    Ok(web_of_trust_revocation::revocation_payload_bytes(&revocation))
}

/// Check the vendored signature-valid predicate for public WOT revocation evidence.
///
/// This checks deterministic public evidence fields and provided signature bytes
/// only. It does not resolve identities, sign, fetch registries, or replace
/// aggregate WOT UCAN authorization.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::InvalidPrincipalDigestLength`] when a
/// supplied WOT principal digest is not full width.
pub fn web_of_trust_revocation_signature_is_valid(revocation: &VerifiedWebOfTrustRevocation) -> VerifiedResult<bool> {
    let revocation = to_web_of_trust_revocation(revocation)?;
    Ok(web_of_trust_revocation::revocation_signature_valid(&revocation))
}

/// Check whether public WOT revocation evidence matches public attestation evidence.
///
/// This helper delegates to the vendored exact/family target matching predicate
/// over finite caller-supplied evidence. It does not fetch evidence or check
/// registry freshness.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::InvalidPrincipalDigestLength`] when any
/// supplied WOT principal digest is not full width.
pub fn web_of_trust_revocation_matches_attestation(
    revocation: &VerifiedWebOfTrustRevocation,
    attestation: &VerifiedWebOfTrustAttestation,
) -> VerifiedResult<bool> {
    let revocation = to_web_of_trust_revocation(revocation)?;
    let attestation = to_web_of_trust_attestation(attestation)?;
    Ok(web_of_trust_revocation::revocation_matches(&revocation, &attestation))
}

/// Check whether public WOT revocation evidence is effective for an attestation at an explicit
/// time.
///
/// This helper delegates to the vendored composed revocation predicate over
/// finite caller-supplied evidence. It does not fetch revocations, consult a
/// registry, or read an ambient clock.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::InvalidPrincipalDigestLength`] when any
/// supplied WOT principal digest is not full width.
pub fn web_of_trust_revocation_is_effective_at(
    revocation: &VerifiedWebOfTrustRevocation,
    attestation: &VerifiedWebOfTrustAttestation,
    time_seconds: u64,
) -> VerifiedResult<bool> {
    let revocation = to_web_of_trust_revocation(revocation)?;
    let attestation = to_web_of_trust_attestation(attestation)?;
    Ok(web_of_trust_revocation::revocation_effective_at(&revocation, &attestation, time_seconds))
}

/// Check whether finite WOT evidence reaches a trust threshold for a subject.
///
/// This is an advanced data-only bridge to vendored WOT policy semantics. It
/// consumes already-materialized public roots, attestations, revocations,
/// subject digest, threshold, depth, and time. It does not resolve identities,
/// fetch trust records, check registry freshness, or authorize a UCAN envelope.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::InvalidPrincipalDigestLength`] when any
/// supplied WOT principal digest is not full width.
pub fn web_of_trust_threshold_accepts(
    root_principal_digests: &[Vec<u8>],
    attestations: &[VerifiedWebOfTrustAttestation],
    revocations: &[VerifiedWebOfTrustRevocation],
    subject_principal_digest: &[u8],
    threshold: usize,
    depth: usize,
    time_seconds: u64,
) -> VerifiedResult<bool> {
    let roots = root_principal_digests
        .iter()
        .map(|digest| build_web_of_trust_principal(digest.as_slice()))
        .collect::<VerifiedResult<Vec<_>>>()?;
    let attestations = attestations.iter().map(to_web_of_trust_attestation).collect::<VerifiedResult<Vec<_>>>()?;
    let revocations = revocations.iter().map(to_web_of_trust_revocation).collect::<VerifiedResult<Vec<_>>>()?;
    let subject = build_web_of_trust_principal(subject_principal_digest)?;
    Ok(web_of_trust_policy::threshold_accepts(
        &roots,
        &attestations,
        &revocations,
        &subject,
        threshold,
        depth,
        time_seconds,
    ))
}

/// Authorize a UCAN token envelope with caller-supplied Web-of-Trust evidence.
///
/// This is the shell bridge to verified-logic's Web-of-Trust UCAN authorizer.
/// It delegates a structurally valid token envelope, caller-supplied
/// ability/caveat/DID-CID facts, active caveats, root principals,
/// attestations, revocations, threshold, depth, and deterministic evaluation
/// times to the vendored composed checker.
///
/// It does not parse or verify compact UCANs, perform cryptographic signature
/// verification, decode DID/CID bytes, resolve proofs, fetch keys, check
/// revocation backend availability or freshness, evaluate application caveat
/// policy, access registries/storage/network backends, persist trust records,
/// perform replay checks, or read an ambient clock.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::InvalidCapability`] when a supplied UCAN
/// capability fails core validation, or
/// [`VerifiedPrimitiveError::InvalidPrincipalDigestLength`] when a supplied
/// Web-of-Trust principal digest is not full width.
pub fn web_of_trust_ucan_authorization(
    request: &VerifiedWebOfTrustUcanAuthorizationRequest,
) -> VerifiedResult<VerifiedWebOfTrustAuthorization> {
    let payload = build_token_payload(&request.token_envelope)?;
    let roots = request
        .root_principal_digests
        .iter()
        .map(|digest| build_web_of_trust_principal(digest.as_slice()))
        .collect::<VerifiedResult<Vec<_>>>()?;
    let attestations =
        request.attestations.iter().map(to_web_of_trust_attestation).collect::<VerifiedResult<Vec<_>>>()?;
    let revocations = request.revocations.iter().map(to_web_of_trust_revocation).collect::<VerifiedResult<Vec<_>>>()?;
    let subject = build_web_of_trust_principal(request.subject_principal_digest.as_slice())?;
    let active_caveats = request.active_caveats.iter().map(to_web_of_trust_caveat).collect::<Vec<_>>();
    let caveat_context = to_web_of_trust_caveat_context(&request.caveat_context);

    let decision = web_of_trust_ucan_authorizer::web_of_trust_ucan_authorizer(
        &payload,
        request.signature_valid,
        request.now_seconds,
        request.tolerance_seconds,
        request.ability_allowed,
        request.caveats_contained,
        &active_caveats,
        &caveat_context,
        request.did_cid_linked,
        &roots,
        &attestations,
        &revocations,
        &subject,
        request.threshold,
        request.depth,
        request.trust_time_seconds,
    );

    Ok(match decision {
        web_of_trust_ucan_authorizer::WebOfTrustUcanAuthorization::Authorized => {
            VerifiedWebOfTrustAuthorization::Authorized
        }
        web_of_trust_ucan_authorizer::WebOfTrustUcanAuthorization::Denied => VerifiedWebOfTrustAuthorization::Denied,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedBackendOperation {
    KeyResolution,
    ProofLoad,
    Revocation,
}

impl VerifiedBackendOperation {
    const fn as_verified_code(self) -> u8 {
        match self {
            Self::KeyResolution => ucan_backend_transcript::BACKEND_KEY_RESOLUTION,
            Self::ProofLoad => ucan_backend_transcript::BACKEND_PROOF_LOAD,
            Self::Revocation => ucan_backend_transcript::BACKEND_REVOCATION,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBackendOperationFact {
    pub operation: VerifiedBackendOperation,
    pub succeeded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBackendTranscript {
    pub operations: Vec<VerifiedBackendOperationFact>,
}

fn to_backend_transcript(transcript: &VerifiedBackendTranscript) -> ucan_backend_transcript::BackendTranscript {
    ucan_backend_transcript::BackendTranscript {
        operations: transcript
            .operations
            .iter()
            .map(|operation| ucan_backend_transcript::BackendOperationFact {
                operation: operation.operation.as_verified_code(),
                succeeded: operation.succeeded,
            })
            .collect(),
    }
}

#[must_use]
pub fn backend_transcript_accepts(transcript: &VerifiedBackendTranscript) -> bool {
    ucan_backend_transcript::backend_transcript_accepts(&to_backend_transcript(transcript))
}

#[must_use]
pub fn backend_transcript_first_failed_operation(
    transcript: &VerifiedBackendTranscript,
) -> Option<VerifiedBackendOperation> {
    match ucan_backend_transcript::first_failed_backend_operation(&to_backend_transcript(transcript)) {
        ucan_backend_transcript::BACKEND_KEY_RESOLUTION => Some(VerifiedBackendOperation::KeyResolution),
        ucan_backend_transcript::BACKEND_PROOF_LOAD => Some(VerifiedBackendOperation::ProofLoad),
        ucan_backend_transcript::BACKEND_REVOCATION => Some(VerifiedBackendOperation::Revocation),
        _ => None,
    }
}

/// Check whether a proof-reference byte string is present in a finite revocation list.
///
/// This is the shell bridge to verified-logic's finite revocation-set lookup. It
/// does not perform revocation-registry lookup, freshness checks, persistence, or
/// proof-reference derivation.
#[must_use]
pub fn revocation_reference_is_listed(revoked_references: &[Vec<u8>], reference: &[u8]) -> bool {
    let revocation_set = ucan_revocation::RevocationSet {
        entries: revoked_references.to_vec(),
    };
    ucan_revocation::is_revoked(&revocation_set, &reference.to_vec())
}

/// Check concrete invocation admission against a leaf audience and concrete leaf capability.
///
/// This is the shell bridge to verified-logic's invocation authorization primitive. It
/// checks only the structural invoker/audience match, request-resource prefix refinement,
/// and exact ability equality. Wildcard ability containment, caveat policy evaluation,
/// proof traversal, signatures, and revocation checks remain in their existing shell paths.
#[must_use]
pub fn invocation_request_is_authorized(
    invoker_did: &str,
    leaf_audience_did: &str,
    request_resource: &str,
    request_ability: &str,
    leaf_resource: &str,
    leaf_ability: &str,
) -> bool {
    ucan_invocation::check_invocation_authorized(
        &invoker_did.as_bytes().to_vec(),
        &leaf_audience_did.as_bytes().to_vec(),
        &request_resource.as_bytes().to_vec(),
        &request_ability.as_bytes().to_vec(),
        &leaf_resource.as_bytes().to_vec(),
        &leaf_ability.as_bytes().to_vec(),
    )
}

/// Check a proof traversal depth against a maximum delegation-depth budget.
///
/// The shell's `depth` value is the number of proof hops from the leaf token.
/// The verified primitive models a chain length where a leaf-only chain has
/// length one and depth zero, so this bridge translates `depth` to
/// `chain_len = depth + 1` before checking the budget. Overflow cannot be a
/// valid finite chain length and is rejected.
#[must_use]
pub fn proof_depth_within_budget(depth: usize, max_depth: usize) -> bool {
    let Some(chain_len) = depth.checked_add(1) else {
        return false;
    };
    ucan_delegation_depth::check_depth_budget(chain_len, max_depth)
}

/// Check deterministic invocation receipt execution fields.
///
/// This is the shell bridge to verified-logic's receipt-validity primitive. It
/// checks only that the receipt executor matches the invocation invoker and that
/// the receipt timestamp is not earlier than the invocation timestamp. It does
/// not perform receipt signing, persistence, replay protection, output/error
/// serialization, or ambient clock reads.
#[must_use]
pub fn receipt_execution_is_valid(
    invocation_invoker_did: &str,
    receipt_executor_did: &str,
    invocation_timestamp_seconds: u64,
    receipt_timestamp_seconds: u64,
) -> bool {
    let receipt = ucan_invocation::Receipt {
        invocation: ucan_invocation::Invocation {
            auth_cid: Vec::new(),
            invoker: invocation_invoker_did.as_bytes().to_vec(),
            resource: Vec::new(),
            ability: Vec::new(),
            timestamp: invocation_timestamp_seconds,
        },
        ran_by: receipt_executor_did.as_bytes().to_vec(),
        result: ucan_invocation::InvocationResult::Ok { output: Vec::new() },
        receipt_timestamp: receipt_timestamp_seconds,
    };
    ucan_invocation::check_receipt_valid(&receipt)
}

/// Validate a UCAN envelope using verified-logic's checked pipeline.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::InvalidCapability`] when the envelope
/// contains invalid capability documents. Returns
/// [`VerifiedPrimitiveError::TokenValidation`] when the verified envelope
/// checks fail.
pub fn validate_token_envelope(
    envelope: &TokenEnvelopeInput,
    signature_valid: bool,
    now_seconds: u64,
) -> VerifiedResult<()> {
    let payload = build_token_payload(envelope)?;
    let tolerance_seconds = DEFAULT_CLOCK_SKEW_SECONDS;
    ucan_token::validate_envelope(&payload, signature_valid, now_seconds, tolerance_seconds)
        .map(|_| ())
        .map_err(|error| VerifiedPrimitiveError::TokenValidation {
            failure: map_validation_failure(&error),
        })
}

/// Encode an Ed25519 public key as a verified did:key.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::InvalidPublicKeyLength`] when the public
/// key is not 32 bytes long.
pub fn encode_ed25519_did_key(public_key_bytes: &[u8]) -> VerifiedResult<Vec<u8>> {
    validate_public_key_length(public_key_bytes)?;
    let did_key = ucan_did::encode_did_key(&public_key_bytes.to_vec(), ucan_did::CODEC_ED25519);
    Ok(did_key.encoded)
}

/// Decode a `did:key` byte string through the verified DID-key decoder.
///
/// Returns decoded public-key bytes, the multicodec value, and the original
/// encoded bytes when the supplied bytes satisfy the vendored structural
/// decoder. Malformed prefixes, base58btc payloads, or multicodec structures
/// return `None`.
///
/// This helper is a deterministic structural decoder only. It does not perform
/// remote DID resolution, key lookup, cryptographic signature verification,
/// trust-chain checks, proof fetching, file or network lookup,
/// persistence, or ambient clock reads.
#[must_use]
pub fn decode_did_key(encoded: &[u8]) -> Option<VerifiedDidKey> {
    ucan_did::decode_did_key(&encoded.to_vec()).map(|did_key| VerifiedDidKey {
        public_key_bytes: did_key.public_key_bytes,
        codec: did_key.codec,
        encoded: did_key.encoded,
    })
}

/// Derive an Ed25519 public key from a secret key.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::InvalidSecretKeyLength`] when the secret
/// key is not 32 bytes long.
pub fn derive_ed25519_public_key(secret_key_bytes: &[u8]) -> VerifiedResult<Vec<u8>> {
    let secret_key = build_secret_key(secret_key_bytes)?;
    Ok(ucan_signature::public_from_secret(&secret_key).bytes)
}

/// Sign a message with an Ed25519 secret key.
///
/// # Errors
///
/// Returns [`VerifiedPrimitiveError::InvalidSecretKeyLength`] when the secret
/// key is not 32 bytes long.
pub fn sign_ed25519(secret_key_bytes: &[u8], message: &[u8]) -> VerifiedResult<Vec<u8>> {
    let secret_key = build_secret_key(secret_key_bytes)?;
    Ok(ucan_signature::sign(&secret_key, &message.to_vec()).bytes)
}

/// Verify an Ed25519 signature against a public key and message.
///
/// # Errors
///
/// Returns a length error when the public key or signature bytes are the wrong
/// size for Ed25519.
pub fn verify_ed25519_signature(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> VerifiedResult<bool> {
    let public_key = build_public_key(public_key_bytes)?;
    let signature = build_signature(signature_bytes)?;
    Ok(ucan_signature::verify(&public_key, &message.to_vec(), &signature))
}

fn validate_capability_document(document: &CapabilityDocument) -> VerifiedResult<()> {
    document.view().map(|_| ()).map_err(|error| match error {
        crate::Error::Capability { source } => VerifiedPrimitiveError::InvalidCapability { source },
        crate::Error::Io { .. } | crate::Error::Caveat { .. } | crate::Error::TokenClaims { .. } => {
            unreachable!("capability document view validates resource/ability only")
        }
    })
}

fn collect_ability_segments(ability: &str) -> VerifiedResult<Vec<Vec<u8>>> {
    ucan_core::validate_ability_value(ability)
        .map_err(|source| VerifiedPrimitiveError::InvalidCapability { source })?;
    Ok(ability.split(ABILITY_SEGMENT_SEPARATOR).map(|segment| segment.as_bytes().to_vec()).collect())
}

fn build_verified_capability(document: CapabilityDocument) -> VerifiedResult<VerifiedCapability> {
    let ability_segments = collect_ability_segments(document.ability.as_str())?;
    Ok(VerifiedCapability {
        document,
        ability_segments,
    })
}

const fn to_verified_time_window(window: &TokenTimeWindow) -> ucan_temporal::TimeWindow {
    ucan_temporal::TimeWindow {
        nbf: window.not_before_seconds,
        exp: window.expires_at_seconds,
    }
}

const fn from_verified_time_window(window: &ucan_temporal::TimeWindow) -> TokenTimeWindow {
    TokenTimeWindow {
        not_before_seconds: window.nbf,
        expires_at_seconds: window.exp,
    }
}

fn build_token_capability(document: &CapabilityDocument) -> VerifiedResult<ucan_token::UcanCapability> {
    validate_capability_document(document)?;
    Ok(ucan_token::UcanCapability {
        resource: document.resource.as_bytes().to_vec(),
        ability: document.ability.as_bytes().to_vec(),
    })
}

fn build_token_capabilities(documents: &[CapabilityDocument]) -> VerifiedResult<Vec<ucan_token::UcanCapability>> {
    documents.iter().map(build_token_capability).collect()
}

fn build_capability_merge_entry(document: &CapabilityDocument) -> VerifiedResult<ucan_capability_merge::CapEntry> {
    validate_capability_document(document)?;
    Ok(ucan_capability_merge::CapEntry {
        resource: document.resource.as_bytes().to_vec(),
        ability: document.ability.as_bytes().to_vec(),
    })
}

fn build_capability_merge_entries(
    documents: &[CapabilityDocument],
) -> VerifiedResult<Vec<ucan_capability_merge::CapEntry>> {
    documents.iter().map(build_capability_merge_entry).collect()
}

fn to_chain_capability(document: &CapabilityDocument) -> VerifiedResult<(Vec<u8>, Vec<u8>)> {
    validate_capability_document(document)?;
    Ok((document.resource.as_bytes().to_vec(), document.ability.as_bytes().to_vec()))
}

fn to_verified_chain_entry(entry: &VerifiedChainEntry) -> VerifiedResult<ucan_chain::ChainEntry> {
    let att = entry.capabilities.iter().map(to_chain_capability).collect::<VerifiedResult<Vec<_>>>()?;
    Ok(ucan_chain::ChainEntry {
        iss: entry.issuer_did.as_bytes().to_vec(),
        aud: entry.audience_did.as_bytes().to_vec(),
        att,
        exp: entry.expires_at_seconds,
        nbf: entry.not_before_seconds,
        sig_valid: entry.signature_valid,
    })
}

fn to_proof_traversal_capability(
    document: &CapabilityDocument,
) -> VerifiedResult<ucan_proof_traversal::TraversalCapability> {
    validate_capability_document(document)?;
    Ok(ucan_proof_traversal::TraversalCapability {
        resource: document.resource.as_bytes().to_vec(),
        ability: ucan_ability::Ability {
            segments: collect_ability_segments(document.ability.as_str())?,
        },
    })
}

fn to_proof_traversal_entry(
    entry: &VerifiedProofTraversalEntry,
) -> VerifiedResult<ucan_proof_traversal::TraversalEntry> {
    let capabilities =
        entry.capabilities.iter().map(to_proof_traversal_capability).collect::<VerifiedResult<Vec<_>>>()?;
    Ok(ucan_proof_traversal::TraversalEntry {
        proof_ref: entry.proof_reference.clone(),
        issuer: entry.issuer_did.as_bytes().to_vec(),
        audience: entry.audience_did.as_bytes().to_vec(),
        capabilities,
        caveat_ids: entry.caveat_ids.clone(),
        nbf: entry.not_before_seconds,
        exp: entry.expires_at_seconds,
        signature_valid: entry.signature_valid,
        revoked: entry.revoked,
    })
}

fn to_proof_traversal_transcript(
    transcript: &VerifiedProofTraversalTranscript,
) -> VerifiedResult<ucan_proof_traversal::TraversalTranscript> {
    let entries = transcript.entries.iter().map(to_proof_traversal_entry).collect::<VerifiedResult<Vec<_>>>()?;
    Ok(ucan_proof_traversal::TraversalTranscript {
        entries,
        visited_refs: transcript.visited_references.clone(),
        total_input_bytes: transcript.total_input_bytes,
        target: to_proof_traversal_target(&transcript.target)?,
    })
}

fn to_proof_traversal_dag_transcript(
    transcript: &VerifiedProofTraversalDagTranscript,
) -> VerifiedResult<ucan_proof_traversal::TraversalDagTranscript> {
    let entries = transcript.entries.iter().map(to_proof_traversal_entry).collect::<VerifiedResult<Vec<_>>>()?;
    Ok(ucan_proof_traversal::TraversalDagTranscript {
        entries,
        parent_indices: transcript.parent_indices.clone(),
        visited_refs: transcript.visited_references.clone(),
        total_input_bytes: transcript.total_input_bytes,
        target: to_proof_traversal_target(&transcript.target)?,
    })
}

fn to_proof_traversal_target(
    target: &VerifiedProofTraversalTarget,
) -> VerifiedResult<ucan_proof_traversal::TraversalAuthorizationTarget> {
    Ok(ucan_proof_traversal::TraversalAuthorizationTarget {
        resource: target.resource.as_bytes().to_vec(),
        ability: ucan_ability::Ability {
            segments: collect_ability_segments(target.ability.as_str())?,
        },
        now: target.now_seconds,
        tolerance: target.tolerance_seconds,
    })
}

fn build_token_payload(envelope: &TokenEnvelopeInput) -> VerifiedResult<ucan_token::UcanPayload> {
    let capabilities = build_token_capabilities(envelope.capabilities.as_slice())?;
    Ok(ucan_token::UcanPayload {
        iss: envelope.issuer_did.as_bytes().to_vec(),
        aud: envelope.audience_did.as_bytes().to_vec(),
        att: capabilities,
        prf: envelope.proofs.clone(),
        exp: envelope.expires_at_seconds,
        nbf: envelope.not_before_seconds,
    })
}

fn build_web_of_trust_principal(digest: &[u8]) -> VerifiedResult<web_of_trust_principal::PrincipalId> {
    let actual = digest.len();
    web_of_trust_principal::principal_id_from_digest_bytes(digest.to_vec())
        .ok_or(VerifiedPrimitiveError::InvalidPrincipalDigestLength { actual })
}

const fn to_web_of_trust_caveat(caveat: &VerifiedWebOfTrustCaveat) -> ucan_caveat::Caveat {
    match caveat {
        VerifiedWebOfTrustCaveat::TimeBound { not_after_seconds } => ucan_caveat::Caveat::TimeBound {
            not_after: *not_after_seconds,
        },
        VerifiedWebOfTrustCaveat::RateLimit {
            max_count,
            window_seconds,
        } => ucan_caveat::Caveat::RateLimit {
            max_count: *max_count,
            window_secs: *window_seconds,
        },
    }
}

const fn to_web_of_trust_caveat_context(context: &VerifiedWebOfTrustCaveatContext) -> ucan_caveat::CaveatContext {
    ucan_caveat::CaveatContext {
        now: context.now_seconds,
        count_in_window: context.count_in_window,
    }
}

fn to_web_of_trust_attestation(
    attestation: &VerifiedWebOfTrustAttestation,
) -> VerifiedResult<web_of_trust_attestation::Attestation> {
    Ok(web_of_trust_attestation::Attestation {
        issuer_key_bytes: attestation.issuer_key_bytes.clone(),
        issuer: build_web_of_trust_principal(attestation.issuer_digest.as_slice())?,
        subject_key_bytes: attestation.subject_key_bytes.clone(),
        subject: build_web_of_trust_principal(attestation.subject_digest.as_slice())?,
        role_tag: attestation.role_tag,
        not_before: attestation.not_before_seconds,
        not_after: attestation.not_after_seconds,
        sequence_no: attestation.sequence_no,
        signature: attestation.signature.clone(),
    })
}

fn to_web_of_trust_revocation(
    revocation: &VerifiedWebOfTrustRevocation,
) -> VerifiedResult<web_of_trust_revocation::Revocation> {
    Ok(web_of_trust_revocation::Revocation {
        issuer_key_bytes: revocation.issuer_key_bytes.clone(),
        issuer: build_web_of_trust_principal(revocation.issuer_digest.as_slice())?,
        target_kind_tag: revocation.target_kind_tag,
        exact_payload_target: revocation.exact_payload_target.clone(),
        family_subject_key_bytes: revocation.family_subject_key_bytes.clone(),
        family_subject: build_web_of_trust_principal(revocation.family_subject_digest.as_slice())?,
        family_role_tag: revocation.family_role_tag,
        effective_time: revocation.effective_time_seconds,
        signature: revocation.signature.clone(),
    })
}

const fn map_validation_failure(error: &ucan_token::ValidationError) -> TokenValidationFailure {
    match error {
        ucan_token::ValidationError::ExpiredToken => TokenValidationFailure::ExpiredToken,
        ucan_token::ValidationError::NotYetValid => TokenValidationFailure::NotYetValid,
        ucan_token::ValidationError::SelfDelegation => TokenValidationFailure::SelfDelegation,
        ucan_token::ValidationError::MissingIssuer => TokenValidationFailure::MissingIssuer,
        ucan_token::ValidationError::MissingAudience => TokenValidationFailure::MissingAudience,
        ucan_token::ValidationError::MissingAttenuations => TokenValidationFailure::MissingAttenuations,
        ucan_token::ValidationError::InvalidSignature => TokenValidationFailure::InvalidSignature,
    }
}

fn build_secret_key(secret_key_bytes: &[u8]) -> VerifiedResult<ucan_signature::SecretKey> {
    validate_secret_key_length(secret_key_bytes)?;
    Ok(ucan_signature::SecretKey {
        bytes: secret_key_bytes.to_vec(),
    })
}

fn build_public_key(public_key_bytes: &[u8]) -> VerifiedResult<ucan_signature::PublicKey> {
    validate_public_key_length(public_key_bytes)?;
    Ok(ucan_signature::PublicKey {
        bytes: public_key_bytes.to_vec(),
    })
}

fn build_signature(signature_bytes: &[u8]) -> VerifiedResult<ucan_signature::Ed25519Signature> {
    validate_signature_length(signature_bytes)?;
    Ok(ucan_signature::Ed25519Signature {
        bytes: signature_bytes.to_vec(),
    })
}

const fn validate_secret_key_length(secret_key_bytes: &[u8]) -> VerifiedResult<()> {
    let actual = secret_key_bytes.len();
    if actual == ucan_signature::SECRET_KEY_LEN {
        return Ok(());
    }
    Err(VerifiedPrimitiveError::InvalidSecretKeyLength { actual })
}

const fn validate_public_key_length(public_key_bytes: &[u8]) -> VerifiedResult<()> {
    let actual = public_key_bytes.len();
    if actual == ucan_signature::PUBLIC_KEY_LEN {
        return Ok(());
    }
    Err(VerifiedPrimitiveError::InvalidPublicKeyLength { actual })
}

const fn validate_signature_length(signature_bytes: &[u8]) -> VerifiedResult<()> {
    let actual = signature_bytes.len();
    if actual == ucan_signature::SIGNATURE_LEN {
        return Ok(());
    }
    Err(VerifiedPrimitiveError::InvalidSignatureLength { actual })
}

#[cfg(test)]
mod tests {
    use verified_logic::ucan_signature;
    use verified_logic::web_of_trust_attestation as verified_wot_attestation;
    use verified_logic::web_of_trust_principal as verified_wot_principal;
    use verified_logic::web_of_trust_revocation as verified_wot_revocation;

    use super::TokenEnvelopeInput;
    use super::TokenTimeWindow;
    use super::TokenValidationFailure;
    use super::VerifiedBackendOperation;
    use super::VerifiedBackendOperationFact;
    use super::VerifiedBackendTranscript;
    use super::VerifiedCapability;
    use super::VerifiedChainEntry;
    use super::VerifiedCompactTokenEnvelope;
    use super::VerifiedCompactTokenParts;
    use super::VerifiedInvocationChainRequest;
    use super::VerifiedPrimitiveError;
    use super::VerifiedProofTraversalBudget;
    use super::VerifiedProofTraversalDagTranscript;
    use super::VerifiedProofTraversalEntry;
    use super::VerifiedProofTraversalTarget;
    use super::VerifiedProofTraversalTranscript;
    use super::VerifiedVerificationStage;
    use super::VerifiedVerificationStageTranscript;
    use super::VerifiedWebOfTrustAttestation;
    use super::VerifiedWebOfTrustAuthorization;
    use super::VerifiedWebOfTrustCaveat;
    use super::VerifiedWebOfTrustCaveatContext;
    use super::VerifiedWebOfTrustRevocation;
    use super::VerifiedWebOfTrustUcanAuthorizationRequest;
    use super::attenuation_chain_is_valid;
    use super::backend_transcript_accepts;
    use super::backend_transcript_first_failed_operation;
    use super::capability_set_authorizes;
    use super::compact_token_envelope_is_valid;
    use super::compact_token_split_is_valid;
    use super::compose_time_window_chain;
    use super::decode_did_key;
    use super::derive_ed25519_public_key;
    use super::encode_ed25519_did_key;
    use super::invocation_chain_is_authorized;
    use super::invocation_request_is_authorized;
    use super::proof_depth_within_budget;
    use super::proof_link_is_valid;
    use super::proof_traversal_dag_transcript_is_valid;
    use super::proof_traversal_transcript_is_valid;
    use super::receipt_execution_is_valid;
    use super::revocation_reference_is_listed;
    use super::sign_ed25519;
    use super::structural_chain_is_valid;
    use super::structural_chain_not_revoked_is_valid;
    use super::token_needs_refresh;
    use super::token_time_valid;
    use super::typed_caveat_is_satisfied;
    use super::typed_caveat_set_is_satisfied;
    use super::validate_token_envelope;
    use super::verification_stage_transcript_outcome;
    use super::verify_ed25519_signature;
    use super::web_of_trust_attestation_is_active_at;
    use super::web_of_trust_attestation_payload_bytes;
    use super::web_of_trust_attestation_signature_is_valid;
    use super::web_of_trust_principal_digest;
    use super::web_of_trust_principal_digest_is_valid;
    use super::web_of_trust_revocation_is_effective_at;
    use super::web_of_trust_revocation_matches_attestation;
    use super::web_of_trust_revocation_payload_bytes;
    use super::web_of_trust_revocation_signature_is_valid;
    use super::web_of_trust_threshold_accepts;
    use super::web_of_trust_ucan_authorization;
    use crate::shell::CapabilityDocument;

    const VALID_RESOURCE: &str = "did:key:z6Mkexample";
    const VALID_RESOURCE_CHILD: &str = "did:key:z6Mkexample/photos";
    const VALID_ABILITY_GLOB: &str = "store/*";
    const VALID_ABILITY_CHILD: &str = "store/add";
    const VALID_ABILITY_OTHER_NAMESPACE: &str = "upload/add";
    const ISSUED_AT_SECONDS: u64 = 1_000;
    const EXPIRES_AT_SECONDS: u64 = 2_000;
    const NOW_SECONDS: u64 = 1_500;
    const FRESH_NOW_SECONDS: u64 = 1_000;
    const EXPIRED_NOW_SECONDS: u64 = 2_061;
    const SKEW_VALID_NOW_SECONDS: u64 = 2_060;
    const REFRESH_NOW_SECONDS: u64 = 1_800;
    const WINDOW_ONE_NOT_BEFORE_SECONDS: u64 = 100;
    const WINDOW_ONE_EXPIRES_AT_SECONDS: u64 = 400;
    const WINDOW_TWO_NOT_BEFORE_SECONDS: u64 = 200;
    const WINDOW_TWO_EXPIRES_AT_SECONDS: u64 = 300;
    const SIGNING_KEY_BYTE: u8 = 7;
    const INVALID_LENGTH_BYTES: usize = 1;
    const MESSAGE: &[u8] = b"ucan verified primitives";
    const WRONG_MESSAGE: &[u8] = b"wrong message";

    #[test]
    fn backend_transcript_accepts_successful_backend_operations() {
        let transcript = VerifiedBackendTranscript {
            operations: vec![
                VerifiedBackendOperationFact {
                    operation: VerifiedBackendOperation::Revocation,
                    succeeded: true,
                },
                VerifiedBackendOperationFact {
                    operation: VerifiedBackendOperation::KeyResolution,
                    succeeded: true,
                },
                VerifiedBackendOperationFact {
                    operation: VerifiedBackendOperation::ProofLoad,
                    succeeded: true,
                },
            ],
        };

        assert!(backend_transcript_accepts(&transcript));
        assert_eq!(backend_transcript_first_failed_operation(&transcript), None);
    }

    #[test]
    fn backend_transcript_reports_first_failed_backend_operation() {
        let transcript = VerifiedBackendTranscript {
            operations: vec![
                VerifiedBackendOperationFact {
                    operation: VerifiedBackendOperation::Revocation,
                    succeeded: true,
                },
                VerifiedBackendOperationFact {
                    operation: VerifiedBackendOperation::ProofLoad,
                    succeeded: false,
                },
                VerifiedBackendOperationFact {
                    operation: VerifiedBackendOperation::KeyResolution,
                    succeeded: false,
                },
            ],
        };

        assert!(!backend_transcript_accepts(&transcript));
        assert_eq!(backend_transcript_first_failed_operation(&transcript), Some(VerifiedBackendOperation::ProofLoad));
    }

    #[test]
    fn compact_token_split_uses_verified_separator_admission() {
        let parts = VerifiedCompactTokenParts {
            header: b"header".to_vec(),
            payload: b"payload".to_vec(),
            signature: b"signature".to_vec(),
        };
        assert!(compact_token_split_is_valid(b"header.payload.signature", &parts));

        let embedded_separator = VerifiedCompactTokenParts {
            header: b"header".to_vec(),
            payload: b"pay.load".to_vec(),
            signature: b"signature".to_vec(),
        };
        assert!(!compact_token_split_is_valid(b"header.pay.load.signature", &embedded_separator));
        assert!(!compact_token_split_is_valid(b"header.payload", &parts));
    }

    #[test]
    fn compact_token_envelope_uses_verified_framing() {
        let envelope = VerifiedCompactTokenEnvelope {
            compact: b"header.payload.signature".to_vec(),
            parts: VerifiedCompactTokenParts {
                header: b"header".to_vec(),
                payload: b"payload".to_vec(),
                signature: b"signature".to_vec(),
            },
            signing_input: b"header.payload".to_vec(),
        };
        assert!(compact_token_envelope_is_valid(&envelope));

        let mut bad_signing = envelope.clone();
        bad_signing.signing_input = b"header.payload.signature".to_vec();
        assert!(!compact_token_envelope_is_valid(&bad_signing));

        let mut bad_compact = envelope;
        bad_compact.compact = b"header.payload".to_vec();
        assert!(!compact_token_envelope_is_valid(&bad_compact));
    }

    #[test]
    fn verification_stage_transcript_accepts_all_successful_stages() {
        let transcript = accepting_stage_transcript();
        let outcome = verification_stage_transcript_outcome(&transcript);
        assert!(outcome.accepted);
        assert_eq!(outcome.first_failed_stage, VerifiedVerificationStage::Accepted);
    }

    #[test]
    fn verification_stage_transcript_reports_first_failure() {
        let mut transcript = accepting_stage_transcript();
        transcript.signature_valid = false;
        transcript.proofs_loaded = false;
        let outcome = verification_stage_transcript_outcome(&transcript);
        assert!(!outcome.accepted);
        assert_eq!(outcome.first_failed_stage, VerifiedVerificationStage::Signature);

        let mut transcript = accepting_stage_transcript();
        transcript.proofs_loaded = false;
        let outcome = verification_stage_transcript_outcome(&transcript);
        assert!(!outcome.accepted);
        assert_eq!(outcome.first_failed_stage, VerifiedVerificationStage::ProofLoad);
    }

    fn accepting_stage_transcript() -> VerifiedVerificationStageTranscript {
        VerifiedVerificationStageTranscript {
            parse_ok: true,
            structural_ok: true,
            key_resolved: true,
            signature_valid: true,
            envelope_valid: true,
            revocation_clear: true,
            proofs_loaded: true,
            proof_chain_valid: true,
            authorized: true,
        }
    }

    #[test]
    fn verified_capability_contains_narrower_resource_and_globbed_ability() {
        let parent = VerifiedCapability::new(VALID_RESOURCE.to_owned(), VALID_ABILITY_GLOB.to_owned())
            .expect("parent capability should validate");
        let child = VerifiedCapability::new(VALID_RESOURCE_CHILD.to_owned(), VALID_ABILITY_CHILD.to_owned())
            .expect("child capability should validate");

        assert!(parent.contains(&child));
        assert!(!child.contains(&parent));
    }

    #[test]
    fn verified_capability_rejects_other_namespace() {
        let parent = VerifiedCapability::new(VALID_RESOURCE.to_owned(), VALID_ABILITY_GLOB.to_owned())
            .expect("parent capability should validate");
        let authorized = parent
            .authorizes(VALID_RESOURCE_CHILD, VALID_ABILITY_OTHER_NAMESPACE)
            .expect("requested capability should validate");

        assert!(!authorized);
    }

    #[test]
    fn verified_capability_reports_concrete_ability_admission() {
        let wildcard = VerifiedCapability::new(VALID_RESOURCE.to_owned(), VALID_ABILITY_GLOB.to_owned())
            .expect("wildcard delegated capability should validate");
        let concrete = VerifiedCapability::new(VALID_RESOURCE_CHILD.to_owned(), VALID_ABILITY_CHILD.to_owned())
            .expect("concrete requested capability should validate");

        assert!(wildcard.has_wildcard_segment());
        assert!(!wildcard.is_concrete());
        assert!(!concrete.has_wildcard_segment());
        assert!(concrete.is_concrete());
    }

    #[test]
    fn verified_capability_rejects_embedded_wildcard_segment() {
        let error = VerifiedCapability::new(VALID_RESOURCE.to_owned(), "store*/add".to_owned())
            .expect_err("embedded wildcard should fail core validation");

        assert!(matches!(error, VerifiedPrimitiveError::InvalidCapability { .. }));
    }

    #[test]
    fn composes_time_window_chain_by_intersection() {
        let windows = [
            TokenTimeWindow {
                not_before_seconds: WINDOW_ONE_NOT_BEFORE_SECONDS,
                expires_at_seconds: WINDOW_ONE_EXPIRES_AT_SECONDS,
            },
            TokenTimeWindow {
                not_before_seconds: WINDOW_TWO_NOT_BEFORE_SECONDS,
                expires_at_seconds: WINDOW_TWO_EXPIRES_AT_SECONDS,
            },
        ];
        let composed = compose_time_window_chain(&windows).expect("window chain should compose");

        assert_eq!(composed.not_before_seconds, WINDOW_TWO_NOT_BEFORE_SECONDS);
        assert_eq!(composed.expires_at_seconds, WINDOW_TWO_EXPIRES_AT_SECONDS);
    }

    #[test]
    fn rejects_empty_time_window_chain() {
        let error = compose_time_window_chain(&[]).expect_err("empty chain should fail");

        assert_eq!(error, VerifiedPrimitiveError::EmptyTimeWindowChain);
    }

    #[test]
    fn token_time_valid_respects_verified_clock_skew() {
        assert!(token_time_valid(ISSUED_AT_SECONDS, EXPIRES_AT_SECONDS, FRESH_NOW_SECONDS));
        assert!(token_time_valid(ISSUED_AT_SECONDS, EXPIRES_AT_SECONDS, SKEW_VALID_NOW_SECONDS));
        assert!(!token_time_valid(ISSUED_AT_SECONDS, EXPIRES_AT_SECONDS, EXPIRED_NOW_SECONDS));
    }

    #[test]
    fn token_refresh_threshold_matches_verified_logic() {
        assert!(!token_needs_refresh(ISSUED_AT_SECONDS, EXPIRES_AT_SECONDS, FRESH_NOW_SECONDS));
        assert!(token_needs_refresh(ISSUED_AT_SECONDS, EXPIRES_AT_SECONDS, REFRESH_NOW_SECONDS));
    }

    #[test]
    fn verified_attenuation_chain_accepts_narrower_resource() {
        let parent = vec![valid_capability(VALID_RESOURCE, VALID_ABILITY_CHILD)];
        let child = vec![valid_capability(VALID_RESOURCE_CHILD, VALID_ABILITY_CHILD)];
        let valid = attenuation_chain_is_valid(parent.as_slice(), child.as_slice())
            .expect("attenuation chain should validate capability inputs");

        assert!(valid);
    }

    #[test]
    fn verified_attenuation_chain_rejects_ability_change() {
        let parent = vec![valid_capability(VALID_RESOURCE, VALID_ABILITY_CHILD)];
        let child = vec![valid_capability(VALID_RESOURCE_CHILD, VALID_ABILITY_OTHER_NAMESPACE)];
        let valid = attenuation_chain_is_valid(parent.as_slice(), child.as_slice())
            .expect("attenuation chain should validate capability inputs");

        assert!(!valid);
    }

    #[test]
    fn capability_set_authorizes_exact_resource_prefix_request() {
        let capabilities = vec![
            valid_capability(VALID_RESOURCE, VALID_ABILITY_CHILD),
            valid_capability("resource:other", VALID_ABILITY_OTHER_NAMESPACE),
        ];

        let valid = capability_set_authorizes(capabilities.as_slice(), VALID_RESOURCE_CHILD, VALID_ABILITY_CHILD)
            .expect("capability-set inputs should validate");

        assert!(valid);
    }

    #[test]
    fn capability_set_authorizer_rejects_escalation_or_wildcard_subsumption() {
        let capabilities = vec![valid_capability(VALID_RESOURCE, VALID_ABILITY_GLOB)];

        assert!(
            !capability_set_authorizes(capabilities.as_slice(), VALID_RESOURCE_CHILD, VALID_ABILITY_CHILD)
                .expect("wildcard capability-set inputs should validate")
        );
        assert!(
            !capability_set_authorizes(capabilities.as_slice(), "resource:other/child", VALID_ABILITY_GLOB)
                .expect("resource-escalation inputs should validate")
        );
    }

    #[test]
    fn proof_link_uses_verified_chain_link_semantics() {
        let parent_audience = "did:key:z6MkparentAudience";
        let child_issuer = parent_audience;
        let wrong_child_issuer = "did:key:z6MkotherIssuer";

        assert!(proof_link_is_valid(parent_audience, child_issuer));
        assert!(!proof_link_is_valid(parent_audience, wrong_child_issuer));
    }

    #[test]
    fn structural_chain_uses_verified_chain_composition() {
        let parent = chain_entry(
            "did:key:z6Mkissuer",
            "did:key:z6Mkdelegate",
            VALID_RESOURCE,
            VALID_ABILITY_CHILD,
            100,
            400,
            true,
        );
        let child = chain_entry(
            "did:key:z6Mkdelegate",
            "did:key:z6Mkleaf",
            VALID_RESOURCE_CHILD,
            VALID_ABILITY_CHILD,
            150,
            350,
            true,
        );
        let valid = structural_chain_is_valid(&[parent.clone(), child.clone()], 200, 0)
            .expect("structural chain inputs should validate");

        assert!(valid);

        let broken_link = chain_entry(
            "did:key:z6Mkwrong",
            "did:key:z6Mkleaf",
            VALID_RESOURCE_CHILD,
            VALID_ABILITY_CHILD,
            150,
            350,
            true,
        );
        let valid = structural_chain_is_valid(&[parent.clone(), broken_link], 200, 0)
            .expect("structural chain inputs should validate");
        assert!(!valid);

        let ability_escalation = chain_entry(
            "did:key:z6Mkdelegate",
            "did:key:z6Mkleaf",
            VALID_RESOURCE_CHILD,
            VALID_ABILITY_OTHER_NAMESPACE,
            150,
            350,
            true,
        );
        let valid = structural_chain_is_valid(&[parent, ability_escalation], 200, 0)
            .expect("structural chain inputs should validate");
        assert!(!valid);

        let valid = structural_chain_is_valid(&[child], 500, 0).expect("structural chain inputs should validate");
        assert!(!valid);
    }

    #[test]
    fn structural_chain_not_revoked_uses_verified_revocation_composition() {
        let parent = chain_entry(
            "did:key:z6Mkissuer",
            "did:key:z6Mkdelegate",
            VALID_RESOURCE,
            VALID_ABILITY_CHILD,
            100,
            400,
            true,
        );
        let child = chain_entry(
            "did:key:z6Mkdelegate",
            "did:key:z6Mkleaf",
            VALID_RESOURCE_CHILD,
            VALID_ABILITY_CHILD,
            150,
            350,
            true,
        );
        let chain = vec![parent.clone(), child];
        let references = vec![b"parent-proof".to_vec(), b"child-proof".to_vec()];
        let revoked = vec![b"other-proof".to_vec()];

        let valid = structural_chain_not_revoked_is_valid(&chain, &references, &revoked, 200, 0)
            .expect("chain inputs should validate");
        assert!(valid);

        let revoked = vec![b"child-proof".to_vec()];
        let valid = structural_chain_not_revoked_is_valid(&chain, &references, &revoked, 200, 0)
            .expect("chain inputs should validate");
        assert!(!valid);

        let missing_reference = vec![b"parent-proof".to_vec()];
        let valid = structural_chain_not_revoked_is_valid(&chain, &missing_reference, &[], 200, 0)
            .expect("chain inputs should validate");
        assert!(!valid);

        let broken_child = chain_entry(
            "did:key:z6Mkwrong",
            "did:key:z6Mkleaf",
            VALID_RESOURCE_CHILD,
            VALID_ABILITY_CHILD,
            150,
            350,
            true,
        );
        let valid = structural_chain_not_revoked_is_valid(&[parent, broken_child], &references, &[], 200, 0)
            .expect("chain inputs should validate");
        assert!(!valid);
    }

    #[test]
    fn invocation_chain_uses_verified_authorization_composition() {
        let parent = chain_entry(
            "did:key:z6Mkissuer",
            "did:key:z6Mkdelegate",
            VALID_RESOURCE,
            VALID_ABILITY_CHILD,
            100,
            400,
            true,
        );
        let child = chain_entry(
            "did:key:z6Mkdelegate",
            "did:key:z6Mkleaf",
            VALID_RESOURCE_CHILD,
            VALID_ABILITY_CHILD,
            150,
            350,
            true,
        );
        let chain = vec![parent.clone(), child];
        let references = vec![b"parent-proof".to_vec(), b"child-proof".to_vec()];
        let request = invocation_chain_request(
            b"child-proof",
            "did:key:z6Mkleaf",
            "did:key:z6Mkexample/photos/2026",
            VALID_ABILITY_CHILD,
            0,
        );

        let valid = invocation_chain_is_authorized(&chain, &references, &[], &request, 200, 0)
            .expect("invocation chain inputs should validate");
        assert!(valid);

        let revoked = vec![b"child-proof".to_vec()];
        let valid = invocation_chain_is_authorized(&chain, &references, &revoked, &request, 200, 0)
            .expect("invocation chain inputs should validate");
        assert!(!valid);

        let broken_child = chain_entry(
            "did:key:z6Mkwrong",
            "did:key:z6Mkleaf",
            VALID_RESOURCE_CHILD,
            VALID_ABILITY_CHILD,
            150,
            350,
            true,
        );
        let valid = invocation_chain_is_authorized(&[parent, broken_child], &references, &[], &request, 200, 0)
            .expect("invocation chain inputs should validate");
        assert!(!valid);

        let wrong_reference = invocation_chain_request(
            b"other-proof",
            "did:key:z6Mkleaf",
            "did:key:z6Mkexample/photos/2026",
            VALID_ABILITY_CHILD,
            0,
        );
        let valid = invocation_chain_is_authorized(&chain, &references, &[], &wrong_reference, 200, 0)
            .expect("invocation chain inputs should validate");
        assert!(!valid);

        let escalated_resource = invocation_chain_request(
            b"child-proof",
            "did:key:z6Mkleaf",
            "did:key:z6Mkother/photos",
            VALID_ABILITY_CHILD,
            0,
        );
        let valid = invocation_chain_is_authorized(&chain, &references, &[], &escalated_resource, 200, 0)
            .expect("invocation chain inputs should validate");
        assert!(!valid);

        let escalated_ability = invocation_chain_request(
            b"child-proof",
            "did:key:z6Mkleaf",
            "did:key:z6Mkexample/photos/2026",
            VALID_ABILITY_OTHER_NAMESPACE,
            0,
        );
        let valid = invocation_chain_is_authorized(&chain, &references, &[], &escalated_ability, 200, 0)
            .expect("invocation chain inputs should validate");
        assert!(!valid);

        let bad_index = invocation_chain_request(
            b"child-proof",
            "did:key:z6Mkleaf",
            "did:key:z6Mkexample/photos/2026",
            VALID_ABILITY_CHILD,
            1,
        );
        let valid = invocation_chain_is_authorized(&chain, &references, &[], &bad_index, 200, 0)
            .expect("invocation chain inputs should validate");
        assert!(!valid);
    }

    #[test]
    fn web_of_trust_principal_digest_uses_verified_principal_derivation() {
        let key_bytes = b"example public key bytes";
        let digest = web_of_trust_principal_digest(key_bytes);
        let repeated = web_of_trust_principal_digest(key_bytes);
        let other = web_of_trust_principal_digest(b"different public key bytes");

        assert_eq!(digest, repeated);
        assert_eq!(digest.len(), verified_wot_principal::PRINCIPAL_ID_LEN);
        assert_ne!(digest, other);
    }

    #[test]
    fn web_of_trust_principal_digest_admission_uses_verified_constructor() {
        let digest = web_of_trust_principal_digest(b"example public key bytes");
        let mut short = digest.clone();
        short.pop();
        let mut long = digest.clone();
        long.push(0);

        assert!(web_of_trust_principal_digest_is_valid(&digest));
        assert!(!web_of_trust_principal_digest_is_valid(&short));
        assert!(!web_of_trust_principal_digest_is_valid(&long));
    }

    #[test]
    fn typed_caveat_helpers_use_verified_caveat_semantics() {
        let context = VerifiedWebOfTrustCaveatContext {
            now_seconds: 5,
            count_in_window: 2,
        };
        let active = VerifiedWebOfTrustCaveat::TimeBound { not_after_seconds: 10 };
        let expired = VerifiedWebOfTrustCaveat::TimeBound { not_after_seconds: 4 };
        let rate_limit = VerifiedWebOfTrustCaveat::RateLimit {
            max_count: 3,
            window_seconds: 60,
        };
        let exceeded_rate_limit = VerifiedWebOfTrustCaveat::RateLimit {
            max_count: 1,
            window_seconds: 60,
        };

        assert!(typed_caveat_is_satisfied(&active, &context));
        assert!(!typed_caveat_is_satisfied(&expired, &context));
        assert!(typed_caveat_set_is_satisfied(&[active, rate_limit], &context));
        assert!(!typed_caveat_set_is_satisfied(&[exceeded_rate_limit], &context));
    }

    #[test]
    fn web_of_trust_evidence_helpers_route_to_verified_primitives() {
        let root_key = vec![1, 2, 3];
        let subject_key = vec![7, 8, 9];
        let attestation = signed_wot_attestation(root_key.clone(), subject_key.clone(), 1, 0, 20, 1);
        let revocation = signed_wot_family_revocation(root_key.clone(), subject_key.clone(), 1, 5);

        let attestation_payload = web_of_trust_attestation_payload_bytes(&attestation)
            .expect("attestation input should validate")
            .expect("valid attestation payload should encode");
        assert!(!attestation_payload.is_empty());
        assert_eq!(
            web_of_trust_attestation_payload_bytes(&attestation)
                .expect("attestation input should validate")
                .expect("valid attestation payload should encode"),
            attestation_payload
        );
        assert!(web_of_trust_attestation_signature_is_valid(&attestation).expect("attestation input should validate"));
        assert!(
            web_of_trust_attestation_is_active_at(&attestation, &[], 4).expect("attestation input should validate")
        );
        assert!(
            !web_of_trust_attestation_is_active_at(&attestation, std::slice::from_ref(&revocation), 6)
                .expect("revocation input should validate")
        );

        let revocation_payload = web_of_trust_revocation_payload_bytes(&revocation)
            .expect("revocation input should validate")
            .expect("valid revocation payload should encode");
        assert!(!revocation_payload.is_empty());
        assert_eq!(
            web_of_trust_revocation_payload_bytes(&revocation)
                .expect("revocation input should validate")
                .expect("valid revocation payload should encode"),
            revocation_payload
        );
        assert!(web_of_trust_revocation_signature_is_valid(&revocation).expect("revocation input should validate"));
        assert!(
            web_of_trust_revocation_matches_attestation(&revocation, &attestation)
                .expect("evidence input should validate")
        );
        assert!(
            web_of_trust_revocation_is_effective_at(&revocation, &attestation, 5)
                .expect("evidence input should validate")
        );
        assert!(
            !web_of_trust_revocation_is_effective_at(&revocation, &attestation, 4)
                .expect("evidence input should validate")
        );

        let threshold = web_of_trust_threshold_accepts(
            &[principal_digest(&root_key)],
            std::slice::from_ref(&attestation),
            &[],
            &principal_digest(&subject_key),
            1,
            1,
            4,
        )
        .expect("threshold evidence should validate");
        assert!(threshold);

        let mut invalid_digest = attestation;
        invalid_digest.subject_digest = vec![1, 2, 3];
        let error =
            web_of_trust_attestation_signature_is_valid(&invalid_digest).expect_err("short digest should reject");
        assert_eq!(error, VerifiedPrimitiveError::InvalidPrincipalDigestLength { actual: 3 });
    }

    #[test]
    fn web_of_trust_ucan_authorization_uses_verified_facade() {
        let root_key = vec![1, 2, 3];
        let subject_key = vec![7, 8, 9];
        let attestation = signed_wot_attestation(root_key.clone(), subject_key.clone(), 1, 0, 20, 1);
        let request = wot_authorization_request(
            vec![principal_digest(&root_key)],
            vec![attestation],
            Vec::new(),
            principal_digest(&subject_key),
            1,
        );

        let decision = web_of_trust_ucan_authorization(&request).expect("WOT UCAN inputs should validate");
        assert_eq!(decision, VerifiedWebOfTrustAuthorization::Authorized);

        let mut denied_fact = request.clone();
        denied_fact.did_cid_linked = false;
        let decision = web_of_trust_ucan_authorization(&denied_fact).expect("WOT UCAN inputs should validate");
        assert_eq!(decision, VerifiedWebOfTrustAuthorization::Denied);

        let mut unsatisfied_caveat = request.clone();
        unsatisfied_caveat.active_caveats = vec![VerifiedWebOfTrustCaveat::TimeBound { not_after_seconds: 1 }];
        let decision = web_of_trust_ucan_authorization(&unsatisfied_caveat).expect("WOT UCAN inputs should validate");
        assert_eq!(decision, VerifiedWebOfTrustAuthorization::Denied);

        let mut invalid_digest = request;
        invalid_digest.subject_principal_digest = vec![1, 2, 3];
        let error = web_of_trust_ucan_authorization(&invalid_digest).expect_err("short digest should reject");
        assert_eq!(error, VerifiedPrimitiveError::InvalidPrincipalDigestLength { actual: 3 });
    }

    #[test]
    fn web_of_trust_ucan_authorization_denies_revoked_or_under_threshold_trust() {
        let alpha_root_key = vec![1, 2, 3];
        let beta_root_key = vec![4, 5, 6];
        let subject_key = vec![7, 8, 9];
        let attestation_a = signed_wot_attestation(alpha_root_key.clone(), subject_key.clone(), 1, 0, 20, 1);
        let attestation_b = signed_wot_attestation(beta_root_key.clone(), subject_key.clone(), 1, 0, 20, 2);
        let roots = vec![principal_digest(&alpha_root_key), principal_digest(&beta_root_key)];
        let subject = principal_digest(&subject_key);

        let under_threshold =
            wot_authorization_request(roots.clone(), vec![attestation_a.clone()], Vec::new(), subject.clone(), 2);
        let decision = web_of_trust_ucan_authorization(&under_threshold).expect("WOT UCAN inputs should validate");
        assert_eq!(decision, VerifiedWebOfTrustAuthorization::Denied);

        let revoked = wot_authorization_request(
            roots,
            vec![attestation_a, attestation_b],
            vec![signed_wot_family_revocation(beta_root_key, subject_key, 1, 5)],
            subject,
            2,
        );
        let decision = web_of_trust_ucan_authorization(&revoked).expect("WOT UCAN inputs should validate");
        assert_eq!(decision, VerifiedWebOfTrustAuthorization::Denied);
    }

    #[test]
    fn revocation_reference_lookup_uses_verified_set_semantics() {
        let revoked = vec![b"root-proof".to_vec(), b"leaf-proof".to_vec()];

        assert!(revocation_reference_is_listed(&revoked, b"leaf-proof"));
        assert!(!revocation_reference_is_listed(&revoked, b"other-proof"));
    }

    #[test]
    fn invocation_request_uses_verified_invocation_semantics() {
        let audience = "did:key:z6Mkaudience";

        assert!(invocation_request_is_authorized(
            audience,
            audience,
            "did:key:z6Mkresource/photos",
            "store/add",
            "did:key:z6Mkresource",
            "store/add",
        ));
        assert!(!invocation_request_is_authorized(
            "did:key:z6Mkwrong",
            audience,
            "did:key:z6Mkresource/photos",
            "store/add",
            "did:key:z6Mkresource",
            "store/add",
        ));
        assert!(!invocation_request_is_authorized(
            audience,
            audience,
            "did:key:z6Mkother/photos",
            "store/add",
            "did:key:z6Mkresource",
            "store/add",
        ));
        assert!(!invocation_request_is_authorized(
            audience,
            audience,
            "did:key:z6Mkresource/photos",
            "store/remove",
            "did:key:z6Mkresource",
            "store/add",
        ));
    }

    #[test]
    fn proof_depth_budget_uses_verified_delegation_depth_semantics() {
        assert!(proof_depth_within_budget(0, 0));
        assert!(proof_depth_within_budget(3, 3));
        assert!(!proof_depth_within_budget(4, 3));
        assert!(!proof_depth_within_budget(usize::MAX, usize::MAX));
    }

    #[test]
    fn receipt_execution_uses_verified_receipt_semantics() {
        let invoker = "did:key:z6Mkaudience";

        assert!(receipt_execution_is_valid(invoker, invoker, 1_000, 1_000));
        assert!(receipt_execution_is_valid(invoker, invoker, 1_000, 1_001));
        assert!(!receipt_execution_is_valid(invoker, "did:key:z6Mkwrong", 1_000, 1_001));
        assert!(!receipt_execution_is_valid(invoker, invoker, 1_001, 1_000));
    }

    #[test]
    fn validates_token_envelope_with_verified_logic() {
        let envelope = TokenEnvelopeInput {
            issuer_did: "did:key:zIssuer".to_owned(),
            audience_did: "did:key:zAudience".to_owned(),
            capabilities: vec![valid_capability(VALID_RESOURCE, VALID_ABILITY_CHILD)],
            proofs: Vec::new(),
            expires_at_seconds: EXPIRES_AT_SECONDS,
            not_before_seconds: ISSUED_AT_SECONDS,
        };
        let result = validate_token_envelope(&envelope, true, NOW_SECONDS);

        assert!(result.is_ok());
    }

    #[test]
    fn token_envelope_rejects_missing_issuer() {
        let envelope = TokenEnvelopeInput {
            issuer_did: String::new(),
            audience_did: "did:key:zAudience".to_owned(),
            capabilities: vec![valid_capability(VALID_RESOURCE, VALID_ABILITY_CHILD)],
            proofs: Vec::new(),
            expires_at_seconds: EXPIRES_AT_SECONDS,
            not_before_seconds: ISSUED_AT_SECONDS,
        };
        let error = validate_token_envelope(&envelope, true, NOW_SECONDS).expect_err("missing issuer should fail");

        assert_eq!(error, VerifiedPrimitiveError::TokenValidation {
            failure: TokenValidationFailure::MissingIssuer,
        });
    }

    #[test]
    fn encodes_ed25519_did_key_with_verified_logic() {
        let public_key = derive_ed25519_public_key(&[SIGNING_KEY_BYTE; ucan_signature::SECRET_KEY_LEN])
            .expect("secret key should derive a public key");
        let did_key = encode_ed25519_did_key(&public_key).expect("public key should encode");

        assert!(did_key.starts_with(b"did:key:z"));
    }

    #[test]
    fn decodes_did_key_with_verified_logic() {
        let public_key = derive_ed25519_public_key(&[SIGNING_KEY_BYTE; ucan_signature::SECRET_KEY_LEN])
            .expect("secret key should derive a public key");
        let encoded = encode_ed25519_did_key(&public_key).expect("public key should encode");

        let decoded = decode_did_key(&encoded).expect("encoded DID key should decode");

        assert_eq!(decoded.public_key_bytes, public_key);
        assert_eq!(decoded.codec, verified_logic::ucan_did::CODEC_ED25519);
        assert_eq!(decoded.encoded, encoded);
    }

    #[test]
    fn did_key_decoder_rejects_malformed_inputs() {
        assert_eq!(decode_did_key(b"did:web:example"), None);
        assert_eq!(decode_did_key(b"did:key:z0"), None);
        assert_eq!(decode_did_key(b"did:key:z"), None);
    }

    #[test]
    fn rejects_wrong_public_key_length_for_did_encoding() {
        let error = encode_ed25519_did_key(&[SIGNING_KEY_BYTE; INVALID_LENGTH_BYTES])
            .expect_err("short public key should fail");

        assert!(matches!(error, VerifiedPrimitiveError::InvalidPublicKeyLength {
            actual: INVALID_LENGTH_BYTES,
        }));
    }

    #[test]
    fn signs_and_verifies_ed25519_messages() {
        let secret_key = [SIGNING_KEY_BYTE; ucan_signature::SECRET_KEY_LEN];
        let public_key = derive_ed25519_public_key(&secret_key).expect("public key derivation should succeed");
        let signature = sign_ed25519(&secret_key, MESSAGE).expect("signing should succeed");
        let verified = verify_ed25519_signature(&public_key, MESSAGE, &signature).expect("verification should succeed");

        assert!(verified);
    }

    #[test]
    fn proof_traversal_transcript_uses_verified_finite_traversal_model() {
        let transcript = proof_traversal_transcript();
        let budget = VerifiedProofTraversalBudget {
            max_depth: 4,
            max_proofs: 8,
            max_input_bytes: 1024,
        };

        let valid =
            proof_traversal_transcript_is_valid(&transcript, &budget).expect("proof traversal inputs should validate");
        assert!(valid);

        let mut duplicate_reference = transcript.clone();
        duplicate_reference.visited_references[1] = duplicate_reference.visited_references[0].clone();
        let valid = proof_traversal_transcript_is_valid(&duplicate_reference, &budget)
            .expect("proof traversal inputs should validate");
        assert!(!valid);

        let mut revoked = transcript;
        revoked.entries[0].revoked = true;
        let valid =
            proof_traversal_transcript_is_valid(&revoked, &budget).expect("proof traversal inputs should validate");
        assert!(!valid);
    }

    #[test]
    fn proof_traversal_transcript_rejects_link_budget_and_caveat_failures() {
        let transcript = proof_traversal_transcript();
        let budget = VerifiedProofTraversalBudget {
            max_depth: 4,
            max_proofs: 8,
            max_input_bytes: 1024,
        };

        let mut broken_link = transcript.clone();
        broken_link.entries[1].issuer_did = "did:key:zMallory".to_owned();
        let valid =
            proof_traversal_transcript_is_valid(&broken_link, &budget).expect("proof traversal inputs should validate");
        assert!(!valid);

        let tight_depth = VerifiedProofTraversalBudget { max_depth: 0, ..budget };
        let valid = proof_traversal_transcript_is_valid(&transcript, &tight_depth)
            .expect("proof traversal inputs should validate");
        assert!(!valid);

        let tight_count = VerifiedProofTraversalBudget {
            max_proofs: 1,
            ..budget
        };
        let valid = proof_traversal_transcript_is_valid(&transcript, &tight_count)
            .expect("proof traversal inputs should validate");
        assert!(!valid);

        let tight_input = VerifiedProofTraversalBudget {
            max_input_bytes: 128,
            ..budget
        };
        let valid = proof_traversal_transcript_is_valid(&transcript, &tight_input)
            .expect("proof traversal inputs should validate");
        assert!(!valid);

        let mut missing_caveat = transcript;
        missing_caveat.entries[1].caveat_ids.clear();
        let valid = proof_traversal_transcript_is_valid(&missing_caveat, &budget)
            .expect("proof traversal inputs should validate");
        assert!(!valid);
    }

    #[test]
    fn proof_traversal_transcript_rejects_overbroad_or_mismatched_targets() {
        let transcript = proof_traversal_transcript();
        let budget = VerifiedProofTraversalBudget {
            max_depth: 4,
            max_proofs: 8,
            max_input_bytes: 1024,
        };

        let mut overbroad_child = transcript.clone();
        overbroad_child.entries[1].capabilities[0] = valid_capability("did:key:zOther", "store/add");
        let valid = proof_traversal_transcript_is_valid(&overbroad_child, &budget)
            .expect("proof traversal inputs should validate");
        assert!(!valid);

        let mut mismatched_target = transcript;
        mismatched_target.target.ability = "store/remove".to_owned();
        let valid = proof_traversal_transcript_is_valid(&mismatched_target, &budget)
            .expect("proof traversal inputs should validate");
        assert!(!valid);
    }

    #[test]
    fn proof_traversal_dag_transcript_uses_verified_multi_parent_model() {
        let transcript = proof_traversal_dag_transcript();
        let budget = VerifiedProofTraversalBudget {
            max_depth: 4,
            max_proofs: 8,
            max_input_bytes: 1024,
        };

        let valid = proof_traversal_dag_transcript_is_valid(&transcript, &budget)
            .expect("proof DAG traversal inputs should validate");
        assert!(valid);

        let mut cycle = transcript.clone();
        cycle.parent_indices[1] = vec![1];
        let valid = proof_traversal_dag_transcript_is_valid(&cycle, &budget)
            .expect("proof DAG traversal inputs should validate");
        assert!(!valid);

        let mut missing_parent_caveat = transcript.clone();
        missing_parent_caveat.entries[3].caveat_ids.retain(|id| id != b"region");
        let valid = proof_traversal_dag_transcript_is_valid(&missing_parent_caveat, &budget)
            .expect("proof DAG traversal inputs should validate");
        assert!(!valid);

        let mut wrong_parent_link = transcript.clone();
        wrong_parent_link.entries[2].audience_did = "did:key:zMallory".to_owned();
        let valid = proof_traversal_dag_transcript_is_valid(&wrong_parent_link, &budget)
            .expect("proof DAG traversal inputs should validate");
        assert!(!valid);

        let mut duplicate_reference = transcript;
        duplicate_reference.visited_references[2] = duplicate_reference.visited_references[1].clone();
        let valid = proof_traversal_dag_transcript_is_valid(&duplicate_reference, &budget)
            .expect("proof DAG traversal inputs should validate");
        assert!(!valid);
    }

    #[test]
    fn ed25519_verification_rejects_wrong_message() {
        let secret_key = [SIGNING_KEY_BYTE; ucan_signature::SECRET_KEY_LEN];
        let public_key = derive_ed25519_public_key(&secret_key).expect("public key derivation should succeed");
        let signature = sign_ed25519(&secret_key, MESSAGE).expect("signing should succeed");
        let verified =
            verify_ed25519_signature(&public_key, WRONG_MESSAGE, &signature).expect("verification should succeed");

        assert!(!verified);
    }

    fn valid_capability(resource: &str, ability: &str) -> CapabilityDocument {
        CapabilityDocument::new(resource.to_owned(), ability.to_owned()).expect("capability fixture should validate")
    }

    fn invocation_chain_request(
        authorization_reference: &[u8],
        invoker_did: &str,
        resource: &str,
        ability: &str,
        leaf_capability_index: usize,
    ) -> VerifiedInvocationChainRequest {
        VerifiedInvocationChainRequest {
            authorization_reference: authorization_reference.to_vec(),
            invoker_did: invoker_did.to_owned(),
            resource: resource.to_owned(),
            ability: ability.to_owned(),
            leaf_capability_index,
        }
    }

    fn proof_traversal_entry(
        proof_reference: &[u8],
        issuer_did: &str,
        audience_did: &str,
        resource: &str,
        caveat_ids: Vec<Vec<u8>>,
    ) -> VerifiedProofTraversalEntry {
        VerifiedProofTraversalEntry {
            proof_reference: proof_reference.to_vec(),
            issuer_did: issuer_did.to_owned(),
            audience_did: audience_did.to_owned(),
            capabilities: vec![valid_capability(resource, "store/add")],
            caveat_ids,
            expires_at_seconds: EXPIRES_AT_SECONDS,
            not_before_seconds: ISSUED_AT_SECONDS,
            signature_valid: true,
            revoked: false,
        }
    }

    fn proof_traversal_transcript() -> VerifiedProofTraversalTranscript {
        let parent = proof_traversal_entry(b"root-proof", "did:key:zRoot", "did:key:zLeaf", VALID_RESOURCE, vec![
            b"geo".to_vec(),
        ]);
        let child =
            proof_traversal_entry(b"leaf-proof", "did:key:zLeaf", "did:key:zInvoker", VALID_RESOURCE_CHILD, vec![
                b"geo".to_vec(),
                b"rate".to_vec(),
            ]);
        VerifiedProofTraversalTranscript {
            entries: vec![parent, child],
            visited_references: vec![b"root-proof".to_vec(), b"leaf-proof".to_vec()],
            total_input_bytes: 256,
            target: VerifiedProofTraversalTarget {
                resource: VALID_RESOURCE_CHILD.to_owned(),
                ability: "store/add".to_owned(),
                now_seconds: NOW_SECONDS,
                tolerance_seconds: 0,
            },
        }
    }

    fn proof_traversal_dag_transcript() -> VerifiedProofTraversalDagTranscript {
        let root = proof_traversal_entry(b"root-proof", "did:key:zRoot", "did:key:zBob", VALID_RESOURCE, Vec::new());
        let proof_a = proof_traversal_entry(b"proof-a", "did:key:zBob", "did:key:zCarol", VALID_RESOURCE_CHILD, vec![
            b"geo".to_vec(),
            b"rate".to_vec(),
        ]);
        let proof_b = proof_traversal_entry(b"proof-b", "did:key:zBob", "did:key:zCarol", VALID_RESOURCE_CHILD, vec![
            b"geo".to_vec(),
            b"rate".to_vec(),
            b"region".to_vec(),
        ]);
        let leaf = proof_traversal_entry(
            b"leaf-proof",
            "did:key:zCarol",
            "did:key:zInvoker",
            "did:key:z6Mkexample/photos/grandchild",
            vec![b"geo".to_vec(), b"rate".to_vec(), b"region".to_vec(), b"ttl".to_vec()],
        );
        VerifiedProofTraversalDagTranscript {
            entries: vec![root, proof_a, proof_b, leaf],
            parent_indices: vec![vec![], vec![0], vec![0], vec![1, 2]],
            visited_references: vec![
                b"root-proof".to_vec(),
                b"proof-a".to_vec(),
                b"proof-b".to_vec(),
                b"leaf-proof".to_vec(),
            ],
            total_input_bytes: 512,
            target: VerifiedProofTraversalTarget {
                resource: "did:key:z6Mkexample/photos/grandchild/item".to_owned(),
                ability: "store/add".to_owned(),
                now_seconds: NOW_SECONDS,
                tolerance_seconds: 0,
            },
        }
    }

    fn principal_digest(key_bytes: &[u8]) -> Vec<u8> {
        web_of_trust_principal_digest(key_bytes)
    }

    fn sign_wot_bytes(domain_tag: u8, issuer_key_bytes: &[u8], payload_bytes: &[u8]) -> Vec<u8> {
        let mut signature = Vec::new();
        signature.push(domain_tag);
        let issuer_len = u32::try_from(issuer_key_bytes.len()).expect("fixture issuer key length fits u32");
        signature.extend_from_slice(&issuer_len.to_le_bytes());
        signature.extend_from_slice(issuer_key_bytes);
        signature.extend_from_slice(payload_bytes);
        signature
    }

    fn signed_wot_attestation(
        issuer_key_bytes: Vec<u8>,
        subject_key_bytes: Vec<u8>,
        role_tag: u8,
        not_before_seconds: u64,
        not_after_seconds: u64,
        sequence_no: u64,
    ) -> VerifiedWebOfTrustAttestation {
        let issuer = verified_wot_principal::principal_id_from_bytes(issuer_key_bytes.as_slice());
        let subject = verified_wot_principal::principal_id_from_bytes(subject_key_bytes.as_slice());
        let unsigned = verified_wot_attestation::Attestation {
            issuer_key_bytes: issuer_key_bytes.clone(),
            issuer,
            subject_key_bytes: subject_key_bytes.clone(),
            subject,
            role_tag,
            not_before: not_before_seconds,
            not_after: not_after_seconds,
            sequence_no,
            signature: Vec::new(),
        };
        let payload = verified_wot_attestation::attestation_payload_bytes(&unsigned)
            .expect("fixture attestation payload should encode");
        let signature = sign_wot_bytes(0xa1, issuer_key_bytes.as_slice(), payload.as_slice());
        VerifiedWebOfTrustAttestation {
            issuer_key_bytes,
            issuer_digest: unsigned.issuer.digest,
            subject_key_bytes,
            subject_digest: unsigned.subject.digest,
            role_tag,
            not_before_seconds,
            not_after_seconds,
            sequence_no,
            signature,
        }
    }

    fn signed_wot_family_revocation(
        issuer_key_bytes: Vec<u8>,
        subject_key_bytes: Vec<u8>,
        role_tag: u8,
        effective_time_seconds: u64,
    ) -> VerifiedWebOfTrustRevocation {
        let issuer = verified_wot_principal::principal_id_from_bytes(issuer_key_bytes.as_slice());
        let family_subject = verified_wot_principal::principal_id_from_bytes(subject_key_bytes.as_slice());
        let unsigned = verified_wot_revocation::Revocation {
            issuer_key_bytes: issuer_key_bytes.clone(),
            issuer,
            target_kind_tag: 0x02,
            exact_payload_target: Vec::new(),
            family_subject_key_bytes: subject_key_bytes.clone(),
            family_subject,
            family_role_tag: role_tag,
            effective_time: effective_time_seconds,
            signature: Vec::new(),
        };
        let payload = verified_wot_revocation::revocation_payload_bytes(&unsigned)
            .expect("fixture revocation payload should encode");
        let signature = sign_wot_bytes(0xa2, issuer_key_bytes.as_slice(), payload.as_slice());
        VerifiedWebOfTrustRevocation {
            issuer_key_bytes,
            issuer_digest: unsigned.issuer.digest,
            target_kind_tag: 0x02,
            exact_payload_target: Vec::new(),
            family_subject_key_bytes: subject_key_bytes,
            family_subject_digest: unsigned.family_subject.digest,
            family_role_tag: role_tag,
            effective_time_seconds,
            signature,
        }
    }

    fn wot_authorization_request(
        root_principal_digests: Vec<Vec<u8>>,
        attestations: Vec<VerifiedWebOfTrustAttestation>,
        revocations: Vec<VerifiedWebOfTrustRevocation>,
        subject_principal_digest: Vec<u8>,
        threshold: usize,
    ) -> VerifiedWebOfTrustUcanAuthorizationRequest {
        VerifiedWebOfTrustUcanAuthorizationRequest {
            token_envelope: TokenEnvelopeInput {
                issuer_did: "did:key:zIssuer".to_owned(),
                audience_did: "did:key:zAudience".to_owned(),
                capabilities: vec![valid_capability(VALID_RESOURCE, VALID_ABILITY_CHILD)],
                proofs: vec![b"bafy-proof".to_vec()],
                expires_at_seconds: 100,
                not_before_seconds: 0,
            },
            signature_valid: true,
            now_seconds: 5,
            tolerance_seconds: 0,
            ability_allowed: true,
            caveats_contained: true,
            active_caveats: vec![VerifiedWebOfTrustCaveat::TimeBound { not_after_seconds: 50 }],
            caveat_context: VerifiedWebOfTrustCaveatContext {
                now_seconds: 5,
                count_in_window: 0,
            },
            did_cid_linked: true,
            root_principal_digests,
            attestations,
            revocations,
            subject_principal_digest,
            threshold,
            depth: 1,
            trust_time_seconds: 5,
        }
    }

    fn chain_entry(
        issuer_did: &str,
        audience_did: &str,
        resource: &str,
        ability: &str,
        not_before_seconds: u64,
        expires_at_seconds: u64,
        signature_valid: bool,
    ) -> VerifiedChainEntry {
        VerifiedChainEntry {
            issuer_did: issuer_did.to_owned(),
            audience_did: audience_did.to_owned(),
            capabilities: vec![valid_capability(resource, ability)],
            expires_at_seconds,
            not_before_seconds,
            signature_valid,
        }
    }
}
