use core::fmt;

use verified_logic::scope;
use verified_logic::token_timestamp;
use verified_logic::ucan_ability;
use verified_logic::ucan_chain;
use verified_logic::ucan_did;
use verified_logic::ucan_signature;
use verified_logic::ucan_temporal;
use verified_logic::ucan_token;

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

    use super::TokenEnvelopeInput;
    use super::TokenTimeWindow;
    use super::TokenValidationFailure;
    use super::VerifiedCapability;
    use super::VerifiedPrimitiveError;
    use super::attenuation_chain_is_valid;
    use super::compose_time_window_chain;
    use super::derive_ed25519_public_key;
    use super::encode_ed25519_did_key;
    use super::proof_link_is_valid;
    use super::sign_ed25519;
    use super::token_needs_refresh;
    use super::token_time_valid;
    use super::validate_token_envelope;
    use super::verify_ed25519_signature;
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
    fn proof_link_uses_verified_chain_link_semantics() {
        let parent_audience = "did:key:z6MkparentAudience";
        let child_issuer = parent_audience;
        let wrong_child_issuer = "did:key:z6MkotherIssuer";

        assert!(proof_link_is_valid(parent_audience, child_issuer));
        assert!(!proof_link_is_valid(parent_audience, wrong_child_issuer));
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
}
