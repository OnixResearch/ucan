#![allow(clippy::module_name_repetitions)]

use core::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::shell::CapabilityDocument;
use crate::verified::TokenEnvelopeInput;
use crate::verified::TokenTimeWindow;
use crate::verified::TokenValidationFailure;
use crate::verified::VerifiedCapability;
use crate::verified::VerifiedPrimitiveError;
use crate::verified::compose_time_window_chain;
use crate::verified::derive_ed25519_public_key;
use crate::verified::encode_ed25519_did_key;
use crate::verified::sign_ed25519;
use crate::verified::validate_token_envelope;
use crate::verified::verify_ed25519_signature;

const COMPACT_TOKEN_PART_COUNT: usize = 3;
const COMPACT_HEADER_INDEX: usize = 0;
const COMPACT_PAYLOAD_INDEX: usize = 1;
const COMPACT_SIGNATURE_INDEX: usize = 2;
const COMPACT_SEPARATOR: char = '.';
const TOKEN_TYPE_JWT: &str = "JWT";
const TOKEN_ALGORITHM_EDDSA: &str = "EdDSA";
const REDACTED_SECRET_MATERIAL_DEBUG: &str = "<redacted>";
const CAPABILITY_RESOURCE_FIELD: &str = "with";
const CAPABILITY_ABILITY_FIELD: &str = "can";
const PROOF_REFERENCE_DIGEST_LEN: usize = blake3::OUT_LEN;
pub const ED25519_SECRET_KEY_BYTES: usize = verified_logic::ucan_signature::SECRET_KEY_LEN;
pub const ED25519_PUBLIC_KEY_BYTES: usize = verified_logic::ucan_signature::PUBLIC_KEY_LEN;

pub type TokenResult<T> = std::result::Result<T, TokenError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactPart {
    Header,
    Payload,
    Signature,
}

impl CompactPart {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Payload => "payload",
            Self::Signature => "signature",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    EmptyCompactToken,
    CompactTokenMustBeTrimmed,
    InvalidCompactTokenStructure { actual_parts: usize },
    Base64Decode { part: CompactPart, message: String },
    JsonDecode { part: CompactPart, message: String },
    JsonEncode { message: String },
    UnsupportedHeader { algorithm: String, token_type: String },
    Capability { message: String },
    MissingCapabilityField { index: usize, field: &'static str },
    CoreClaims { source: ucan_core::token::Error },
    InvalidSecretKeyLength { actual: usize },
    InvalidPublicKeyLength { actual: usize },
    DidEncodingUtf8,
    MissingVerificationKey { issuer: String },
    Signature { issuer: String },
    Temporal { message: String },
    SelfDelegation { did: String },
    ProofChain { message: String },
    Attenuation { resource: String, ability: String },
    VerifiedPrimitive { source: VerifiedPrimitiveError },
}

impl fmt::Display for TokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCompactToken => formatter.write_str("compact token must not be empty"),
            Self::CompactTokenMustBeTrimmed => {
                formatter.write_str("compact token must not contain surrounding whitespace")
            }
            Self::InvalidCompactTokenStructure { actual_parts } => {
                write!(formatter, "compact token must contain {COMPACT_TOKEN_PART_COUNT} parts, got {actual_parts}")
            }
            Self::Base64Decode { part, message } => {
                write!(formatter, "{} part is not valid base64url: {message}", part.as_str())
            }
            Self::JsonDecode { part, message } => {
                write!(formatter, "{} part is not valid JSON: {message}", part.as_str())
            }
            Self::JsonEncode { message } => write!(formatter, "token JSON encoding failed: {message}"),
            Self::UnsupportedHeader { algorithm, token_type } => {
                write!(formatter, "unsupported token header alg={algorithm:?}, typ={token_type:?}")
            }
            Self::Capability { message } => write!(formatter, "capability validation failed: {message}"),
            Self::MissingCapabilityField { index, field } => {
                write!(formatter, "capability at index {index} is missing field {field:?}")
            }
            Self::CoreClaims { source } => write!(formatter, "core claim validation failed: {source}"),
            Self::InvalidSecretKeyLength { actual } => {
                write!(formatter, "ed25519 secret key must be {ED25519_SECRET_KEY_BYTES} bytes, got {actual}")
            }
            Self::InvalidPublicKeyLength { actual } => {
                write!(formatter, "ed25519 public key must be {ED25519_PUBLIC_KEY_BYTES} bytes, got {actual}")
            }
            Self::DidEncodingUtf8 => formatter.write_str("verified did:key bytes were not utf-8"),
            Self::MissingVerificationKey { issuer } => {
                write!(formatter, "no verification key registered for issuer {issuer}")
            }
            Self::Signature { issuer } => write!(formatter, "signature failed for issuer {issuer}"),
            Self::Temporal { message } => write!(formatter, "temporal verification failed: {message}"),
            Self::SelfDelegation { did } => write!(formatter, "self-delegation rejected for {did}"),
            Self::ProofChain { message } => write!(formatter, "proof-chain verification failed: {message}"),
            Self::Attenuation { resource, ability } => {
                write!(formatter, "capability {resource} {ability} is not delegated by proofs")
            }
            Self::VerifiedPrimitive { source } => write!(formatter, "verified primitive failed: {source}"),
        }
    }
}

impl std::error::Error for TokenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CoreClaims { source } => Some(source),
            Self::VerifiedPrimitive { source } => Some(source),
            Self::EmptyCompactToken
            | Self::CompactTokenMustBeTrimmed
            | Self::InvalidCompactTokenStructure { .. }
            | Self::Base64Decode { .. }
            | Self::JsonDecode { .. }
            | Self::JsonEncode { .. }
            | Self::UnsupportedHeader { .. }
            | Self::Capability { .. }
            | Self::MissingCapabilityField { .. }
            | Self::InvalidSecretKeyLength { .. }
            | Self::InvalidPublicKeyLength { .. }
            | Self::DidEncodingUtf8
            | Self::MissingVerificationKey { .. }
            | Self::Signature { .. }
            | Self::Temporal { .. }
            | Self::SelfDelegation { .. }
            | Self::ProofChain { .. }
            | Self::Attenuation { .. } => None,
        }
    }
}

impl From<ucan_core::token::Error> for TokenError {
    fn from(source: ucan_core::token::Error) -> Self {
        Self::CoreClaims { source }
    }
}

impl From<VerifiedPrimitiveError> for TokenError {
    fn from(source: VerifiedPrimitiveError) -> Self {
        Self::VerifiedPrimitive { source }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactToken(String);

impl CompactToken {
    /// Build a compact-token wrapper from a string.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] when the token is empty or untrimmed.
    pub fn new(token: impl Into<String>) -> TokenResult<Self> {
        let token = token.into();
        validate_compact_token_string(token.as_str())?;
        Ok(Self(token))
    }

    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }

    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for CompactToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerDid(String);

impl IssuerDid {
    /// Build an issuer DID wrapper after core DID validation.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] when the DID value is empty or untrimmed.
    pub fn new(value: impl Into<String>) -> TokenResult<Self> {
        let value = value.into();
        ucan_core::token::DidView::new(ucan_core::token::DidField::Issuer, value.as_str())?;
        Ok(Self(value))
    }

    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for IssuerDid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudienceDid(String);

impl AudienceDid {
    /// Build an audience DID wrapper after core DID validation.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] when the DID value is empty or untrimmed.
    pub fn new(value: impl Into<String>) -> TokenResult<Self> {
        let value = value.into();
        ucan_core::token::DidView::new(ucan_core::token::DidField::Audience, value.as_str())?;
        Ok(Self(value))
    }

    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for AudienceDid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl From<IssuerDid> for AudienceDid {
    fn from(value: IssuerDid) -> Self {
        Self(value.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitySet(Vec<CapabilityDocument>);

impl CapabilitySet {
    /// Build a one-capability collection for token issuance or verification.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] when the capability or collection fails core validation.
    pub fn single(resource: impl Into<String>, ability: impl Into<String>) -> TokenResult<Self> {
        let capability =
            CapabilityDocument::new(resource.into(), ability.into()).map_err(|error| TokenError::Capability {
                message: error.to_string(),
            })?;
        Self::new(vec![capability])
    }

    /// Build a non-empty capability collection for token issuance or verification.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] when core claim validation rejects the collection.
    pub fn new(capabilities: Vec<CapabilityDocument>) -> TokenResult<Self> {
        let inputs = capability_inputs(capabilities.as_slice());
        let empty_proofs: [ucan_core::token::ProofReferenceInput<'_>; 0] = [];
        let input = ucan_core::token::ClaimsInput {
            issuer_did: Some("did:key:z6Mkissuer"),
            audience_did: Some("did:key:z6Mkaudience"),
            capabilities: Some(inputs.as_slice()),
            proofs: Some(empty_proofs.as_slice()),
            not_before_seconds: Some(TokenTimeBounds::SMOKE_NOT_BEFORE_SECONDS),
            expires_at_seconds: Some(TokenTimeBounds::SMOKE_EXPIRES_AT_SECONDS),
        };
        ucan_core::token::Claims::from_input(input)?;
        Ok(Self(capabilities))
    }

    #[must_use]
    pub const fn as_slice(&self) -> &[CapabilityDocument] {
        self.0.as_slice()
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<CapabilityDocument> {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProofCollection(Vec<CompactToken>);

impl ProofCollection {
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    #[must_use]
    pub const fn from_tokens(tokens: Vec<CompactToken>) -> Self {
        Self(tokens)
    }

    #[must_use]
    pub const fn as_slice(&self) -> &[CompactToken] {
        self.0.as_slice()
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<CompactToken> {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenTimeBounds {
    not_before_seconds: u64,
    expires_at_seconds: u64,
}

impl TokenTimeBounds {
    const SMOKE_NOT_BEFORE_SECONDS: u64 = 1;
    const SMOKE_EXPIRES_AT_SECONDS: u64 = 2;

    /// Build token time bounds with positive duration.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] when `nbf` is not earlier than `exp`.
    pub const fn new(not_before_seconds: u64, expires_at_seconds: u64) -> TokenResult<Self> {
        match ucan_core::token::TimeBounds::new(not_before_seconds, expires_at_seconds) {
            Ok(_) => Ok(Self {
                not_before_seconds,
                expires_at_seconds,
            }),
            Err(source) => Err(TokenError::CoreClaims { source }),
        }
    }

    #[must_use]
    pub const fn not_before_seconds(self) -> u64 {
        self.not_before_seconds
    }

    #[must_use]
    pub const fn expires_at_seconds(self) -> u64 {
        self.expires_at_seconds
    }

    const fn to_verified(self) -> TokenTimeWindow {
        TokenTimeWindow {
            not_before_seconds: self.not_before_seconds,
            expires_at_seconds: self.expires_at_seconds,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationTime {
    seconds: u64,
}

impl VerificationTime {
    #[must_use]
    pub const fn from_unix_seconds(seconds: u64) -> Self {
        Self { seconds }
    }

    #[must_use]
    pub const fn as_unix_seconds(self) -> u64 {
        self.seconds
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519SigningKey {
    bytes: [u8; ED25519_SECRET_KEY_BYTES],
}

impl fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("Ed25519SigningKey");
        debug.field("secret_key", &RedactedSecretMaterial);
        debug.finish()
    }
}

struct RedactedSecretMaterial;

impl fmt::Debug for RedactedSecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED_SECRET_MATERIAL_DEBUG)
    }
}

impl Ed25519SigningKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ED25519_SECRET_KEY_BYTES]) -> Self {
        Self { bytes }
    }

    /// Build a signing key from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::InvalidSecretKeyLength`] when the slice length is
    /// not the Ed25519 seed length.
    pub fn try_from_slice(bytes: &[u8]) -> TokenResult<Self> {
        let bytes = copy_secret_key(bytes)?;
        Ok(Self { bytes })
    }

    /// Derive the issuer DID for this signing key.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] if verified key derivation or DID encoding fails.
    pub fn issuer(&self) -> TokenResult<IssuerDid> {
        let public_key = self.public_key()?;
        public_key.issuer()
    }

    /// Derive the matching public key.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] if verified key derivation fails.
    pub fn public_key(&self) -> TokenResult<Ed25519PublicKey> {
        let bytes = derive_ed25519_public_key(self.bytes.as_slice())?;
        Ed25519PublicKey::try_from_slice(bytes.as_slice())
    }

    const fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519PublicKey {
    bytes: [u8; ED25519_PUBLIC_KEY_BYTES],
}

impl Ed25519PublicKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ED25519_PUBLIC_KEY_BYTES]) -> Self {
        Self { bytes }
    }

    /// Build a public key from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::InvalidPublicKeyLength`] when the slice length is
    /// not the Ed25519 public key length.
    pub fn try_from_slice(bytes: &[u8]) -> TokenResult<Self> {
        let bytes = copy_public_key(bytes)?;
        Ok(Self { bytes })
    }

    /// Encode this public key as an issuer DID.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] if verified DID encoding fails.
    pub fn issuer(&self) -> TokenResult<IssuerDid> {
        let did_bytes = encode_ed25519_did_key(self.bytes.as_slice())?;
        let did = String::from_utf8(did_bytes).map_err(|_| TokenError::DidEncodingUtf8)?;
        IssuerDid::new(did)
    }

    const fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519VerificationKey {
    issuer: IssuerDid,
    public_key: Ed25519PublicKey,
}

impl Ed25519VerificationKey {
    /// Build an issuer-bound verification key.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] when the public key does not encode to the issuer DID.
    pub fn new(issuer: IssuerDid, public_key: Ed25519PublicKey) -> TokenResult<Self> {
        let derived = public_key.issuer()?;
        if derived != issuer {
            return Err(TokenError::ProofChain {
                message: "verification key DID does not match its public key".to_owned(),
            });
        }
        Ok(Self { issuer, public_key })
    }

    /// Build a verification key from a signing key.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] if public-key derivation or DID encoding fails.
    pub fn from_signing_key(signing_key: &Ed25519SigningKey) -> TokenResult<Self> {
        let public_key = signing_key.public_key()?;
        let issuer = public_key.issuer()?;
        Ok(Self { issuer, public_key })
    }

    #[must_use]
    pub const fn issuer(&self) -> &IssuerDid {
        &self.issuer
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyResolutionContext {
    keys: Vec<Ed25519VerificationKey>,
}

impl KeyResolutionContext {
    #[must_use]
    pub const fn new(keys: Vec<Ed25519VerificationKey>) -> Self {
        Self { keys }
    }

    fn resolve(&self, issuer: &IssuerDid) -> Option<&Ed25519PublicKey> {
        self.keys.iter().find_map(|key| {
            if key.issuer() == issuer {
                Some(&key.public_key)
            } else {
                None
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueRequest {
    signing_key: Ed25519SigningKey,
    audience: AudienceDid,
    capabilities: CapabilitySet,
    proofs: ProofCollection,
    time_bounds: TokenTimeBounds,
}

impl IssueRequest {
    #[must_use]
    pub const fn new(
        signing_key: Ed25519SigningKey,
        audience: AudienceDid,
        capabilities: CapabilitySet,
        proofs: ProofCollection,
        time_bounds: TokenTimeBounds,
    ) -> Self {
        Self {
            signing_key,
            audience,
            capabilities,
            proofs,
            time_bounds,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationContext {
    time: VerificationTime,
    keys: KeyResolutionContext,
    proofs: ProofCollection,
}

impl VerificationContext {
    #[must_use]
    pub const fn new(time: VerificationTime, keys: KeyResolutionContext, proofs: ProofCollection) -> Self {
        Self { time, keys, proofs }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedToken {
    compact: CompactToken,
    header: DecodedHeader,
    claims: DecodedClaims,
    signature: Vec<u8>,
    signing_input: Vec<u8>,
}

impl DecodedToken {
    #[must_use]
    pub const fn compact(&self) -> &CompactToken {
        &self.compact
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructurallyValidToken {
    compact: CompactToken,
    claims: ucan_core::token::Claims,
    signature: Vec<u8>,
    signing_input: Vec<u8>,
}

impl StructurallyValidToken {
    #[must_use]
    pub const fn claims(&self) -> &ucan_core::token::Claims {
        &self.claims
    }

    #[must_use]
    pub const fn compact(&self) -> &CompactToken {
        &self.compact
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureVerifiedToken {
    token: StructurallyValidToken,
}

impl SignatureVerifiedToken {
    #[must_use]
    pub const fn claims(&self) -> &ucan_core::token::Claims {
        self.token.claims()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveDelegation {
    capabilities: CapabilitySet,
    time_bounds: TokenTimeBounds,
}

impl EffectiveDelegation {
    #[must_use]
    pub const fn capabilities(&self) -> &CapabilitySet {
        &self.capabilities
    }

    #[must_use]
    pub const fn time_bounds(&self) -> TokenTimeBounds {
        self.time_bounds
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedToken {
    issuer: IssuerDid,
    audience: AudienceDid,
    capabilities: CapabilitySet,
    proofs: ProofCollection,
    effective: EffectiveDelegation,
}

impl VerifiedToken {
    #[must_use]
    pub const fn issuer(&self) -> &IssuerDid {
        &self.issuer
    }

    #[must_use]
    pub const fn audience(&self) -> &AudienceDid {
        &self.audience
    }

    #[must_use]
    pub const fn capabilities(&self) -> &CapabilitySet {
        &self.capabilities
    }

    #[must_use]
    pub const fn proofs(&self) -> &ProofCollection {
        &self.proofs
    }

    #[must_use]
    pub const fn effective_delegation(&self) -> &EffectiveDelegation {
        &self.effective
    }
}

#[derive(Debug, Clone, Serialize)]
struct EncodedHeader<'a> {
    alg: &'a str,
    typ: &'a str,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct DecodedHeader {
    #[serde(default)]
    alg: String,
    #[serde(default)]
    typ: String,
}

#[derive(Debug, Clone, Serialize)]
struct EncodedCapability<'a> {
    #[serde(rename = "with")]
    resource: &'a str,
    #[serde(rename = "can")]
    ability: &'a str,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct DecodedCapability {
    #[serde(default, rename = "with")]
    resource: Option<String>,
    #[serde(default, rename = "can")]
    ability: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct EncodedClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    att: Vec<EncodedCapability<'a>>,
    prf: Vec<String>,
    exp: u64,
    nbf: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct DecodedClaims {
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    aud: Option<String>,
    #[serde(default)]
    att: Option<Vec<DecodedCapability>>,
    #[serde(default)]
    prf: Option<Vec<String>>,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    nbf: Option<u64>,
}

/// Issue and sign a compact UCAN token.
///
/// # Errors
///
/// Returns [`TokenError`] when signing, DID derivation, JSON encoding, or
/// structural validation fails.
pub fn issue_token(request: &IssueRequest) -> TokenResult<CompactToken> {
    let issuer = request.signing_key.issuer()?;
    let proof_references = encode_proof_references(request.proofs.as_slice());
    let header = EncodedHeader {
        alg: TOKEN_ALGORITHM_EDDSA,
        typ: TOKEN_TYPE_JWT,
    };
    let claims = encoded_claims(&issuer, request);
    let encoded_header = encode_json_part(&header)?;
    let encoded_payload = encode_json_part(&claims)?;
    let signing_input = signing_input(&encoded_header, &encoded_payload);
    let signature = sign_ed25519(request.signing_key.as_bytes(), signing_input.as_bytes())?;
    let encoded_signature = URL_SAFE_NO_PAD.encode(signature);
    let token = join_compact_parts(&encoded_header, &encoded_payload, &encoded_signature);
    let token = CompactToken::new(token)?;
    assert_issued_token_is_structurally_valid(&token, proof_references.as_slice())?;
    Ok(token)
}

/// Parse a compact token into decoded-but-unvalidated parts.
///
/// # Errors
///
/// Returns [`TokenError`] when compact structure, base64url decoding, or JSON
/// decoding fails.
pub fn parse_compact_token(token: &CompactToken) -> TokenResult<DecodedToken> {
    let parts = compact_parts(token.as_str())?;
    let header = decode_json_part::<DecodedHeader>(parts[COMPACT_HEADER_INDEX], CompactPart::Header)?;
    let claims = decode_json_part::<DecodedClaims>(parts[COMPACT_PAYLOAD_INDEX], CompactPart::Payload)?;
    let signature = decode_part(parts[COMPACT_SIGNATURE_INDEX], CompactPart::Signature)?;
    let signing_input = signing_input(parts[COMPACT_HEADER_INDEX], parts[COMPACT_PAYLOAD_INDEX]).into_bytes();
    Ok(DecodedToken {
        compact: token.clone(),
        header,
        claims,
        signature,
        signing_input,
    })
}

/// Validate decoded token claims through `ucan-core`.
///
/// # Errors
///
/// Returns [`TokenError`] when the token header or decoded claim shape is invalid.
pub fn validate_decoded_token(decoded: DecodedToken) -> TokenResult<StructurallyValidToken> {
    validate_header(&decoded.header)?;
    let capability_inputs = decoded_capability_inputs(&decoded.claims)?;
    let proof_bytes = decoded_proof_references(&decoded.claims)?;
    let proof_inputs = proof_bytes.as_ref().map(|references| proof_reference_inputs(references.as_slice()));
    let claims_input = ucan_core::token::ClaimsInput {
        issuer_did: decoded.claims.iss.as_deref(),
        audience_did: decoded.claims.aud.as_deref(),
        capabilities: capability_inputs.as_deref(),
        proofs: proof_inputs.as_deref(),
        not_before_seconds: decoded.claims.nbf,
        expires_at_seconds: decoded.claims.exp,
    };
    let claims = ucan_core::token::Claims::from_input(claims_input)?;
    Ok(StructurallyValidToken {
        compact: decoded.compact,
        claims,
        signature: decoded.signature,
        signing_input: decoded.signing_input,
    })
}

/// Verify the signature on a structurally valid token.
///
/// # Errors
///
/// Returns [`TokenError`] when key resolution fails or the signature is invalid.
pub fn verify_token_signature(
    token: StructurallyValidToken,
    keys: &KeyResolutionContext,
) -> TokenResult<SignatureVerifiedToken> {
    let issuer = IssuerDid::new(token.claims.issuer_did().to_owned())?;
    let public_key = keys.resolve(&issuer).ok_or_else(|| TokenError::MissingVerificationKey {
        issuer: issuer.as_str().to_owned(),
    })?;
    let valid =
        verify_ed25519_signature(public_key.as_bytes(), token.signing_input.as_slice(), token.signature.as_slice())?;
    if !valid {
        return Err(TokenError::Signature {
            issuer: issuer.as_str().to_owned(),
        });
    }
    Ok(SignatureVerifiedToken { token })
}

/// Verify a compact token from parse through authorization.
///
/// # Errors
///
/// Returns [`TokenError`] when parsing, structural validation, signature
/// validation, temporal validation, or proof-chain validation fails.
pub fn verify_compact_token(token: &CompactToken, context: &VerificationContext) -> TokenResult<VerifiedToken> {
    let mut trail = Vec::new();
    verify_compact_token_with_trail(token, context, &mut trail)
}

fn verify_compact_token_with_trail(
    token: &CompactToken,
    context: &VerificationContext,
    trail: &mut Vec<Vec<u8>>,
) -> TokenResult<VerifiedToken> {
    reject_cycle(token, trail)?;
    trail.push(proof_reference_for_token(token));
    let decoded = parse_compact_token(token)?;
    let valid = validate_decoded_token(decoded)?;
    let signed = verify_token_signature(valid, &context.keys)?;
    let verified = authorize_signed_token(signed, context, trail)?;
    let _removed = trail.pop();
    Ok(verified)
}

fn authorize_signed_token(
    signed: SignatureVerifiedToken,
    context: &VerificationContext,
    trail: &mut Vec<Vec<u8>>,
) -> TokenResult<VerifiedToken> {
    let token = signed.token;
    validate_envelope_for_token(&token, context.time)?;
    let issuer = IssuerDid::new(token.claims.issuer_did().to_owned())?;
    let audience = AudienceDid::new(token.claims.audience_did().to_owned())?;
    let capabilities = claims_capability_set(&token.claims)?;
    let time_bounds = claims_time_bounds(&token.claims)?;
    let proofs = direct_proofs(&token, context)?;
    let effective = effective_delegation(&issuer, &capabilities, time_bounds, &proofs, context, trail)?;
    Ok(VerifiedToken {
        issuer,
        audience,
        capabilities,
        proofs,
        effective,
    })
}

fn effective_delegation(
    child_issuer: &IssuerDid,
    capabilities: &CapabilitySet,
    time_bounds: TokenTimeBounds,
    proofs: &ProofCollection,
    context: &VerificationContext,
    trail: &mut Vec<Vec<u8>>,
) -> TokenResult<EffectiveDelegation> {
    if proofs.as_slice().is_empty() {
        return Ok(EffectiveDelegation {
            capabilities: capabilities.clone(),
            time_bounds,
        });
    }
    let parent_tokens = verify_parent_tokens(proofs, context, trail)?;
    verify_child_is_linked_to_parent_audience(child_issuer, &parent_tokens)?;
    let effective_time = verify_temporal_attenuation(time_bounds, parent_tokens.as_slice())?;
    let effective_capabilities = verify_capability_attenuation(capabilities, parent_tokens.as_slice())?;
    Ok(EffectiveDelegation {
        capabilities: effective_capabilities,
        time_bounds: effective_time,
    })
}

fn verify_parent_tokens(
    proofs: &ProofCollection,
    context: &VerificationContext,
    trail: &mut Vec<Vec<u8>>,
) -> TokenResult<Vec<VerifiedToken>> {
    let mut parents = Vec::with_capacity(proofs.as_slice().len());
    for proof in proofs.as_slice() {
        let parent = verify_compact_token_with_trail(proof, context, trail)?;
        parents.push(parent);
    }
    Ok(parents)
}

fn verify_child_is_linked_to_parent_audience(child_issuer: &IssuerDid, parents: &[VerifiedToken]) -> TokenResult<()> {
    for parent in parents {
        if parent.audience().as_str() != child_issuer.as_str() {
            return Err(TokenError::ProofChain {
                message: "child issuer does not match parent audience".to_owned(),
            });
        }
    }
    Ok(())
}

fn verify_temporal_attenuation(
    child_bounds: TokenTimeBounds,
    parents: &[VerifiedToken],
) -> TokenResult<TokenTimeBounds> {
    let mut windows = Vec::with_capacity(parents.len() + 1);
    for parent in parents {
        windows.push(parent.effective_delegation().time_bounds().to_verified());
    }
    windows.push(child_bounds.to_verified());
    let composed = compose_time_window_chain(windows.as_slice())?;
    if composed.not_before_seconds != child_bounds.not_before_seconds()
        || composed.expires_at_seconds != child_bounds.expires_at_seconds()
    {
        return Err(TokenError::Temporal {
            message: "child time window is wider than its proof chain".to_owned(),
        });
    }
    Ok(child_bounds)
}

fn verify_capability_attenuation(child: &CapabilitySet, parents: &[VerifiedToken]) -> TokenResult<CapabilitySet> {
    let parent_capabilities = parent_effective_capabilities(parents);
    for child_capability in child.as_slice() {
        if !capability_is_delegated(child_capability, parent_capabilities.as_slice())? {
            return Err(TokenError::Attenuation {
                resource: child_capability.resource.clone(),
                ability: child_capability.ability.clone(),
            });
        }
    }
    Ok(child.clone())
}

fn capability_is_delegated(child: &CapabilityDocument, parents: &[CapabilityDocument]) -> TokenResult<bool> {
    let child = VerifiedCapability::from_document(child.clone())?;
    for parent in parents {
        let parent = VerifiedCapability::from_document(parent.clone())?;
        if parent.contains(&child) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn parent_effective_capabilities(parents: &[VerifiedToken]) -> Vec<CapabilityDocument> {
    parents
        .iter()
        .flat_map(|parent| parent.effective_delegation().capabilities().as_slice().iter().cloned())
        .collect()
}

fn direct_proofs(token: &StructurallyValidToken, context: &VerificationContext) -> TokenResult<ProofCollection> {
    let mut proofs = Vec::with_capacity(token.claims.proofs().len());
    for reference in token.claims.proofs() {
        let proof = context
            .proofs
            .as_slice()
            .iter()
            .find(|candidate| proof_reference_for_token(candidate).as_slice() == reference.as_bytes())
            .cloned()
            .ok_or_else(|| TokenError::ProofChain {
                message: "required proof token was not supplied".to_owned(),
            })?;
        proofs.push(proof);
    }
    Ok(ProofCollection::from_tokens(proofs))
}

fn validate_envelope_for_token(token: &StructurallyValidToken, time: VerificationTime) -> TokenResult<()> {
    let envelope = token_envelope(token)?;
    validate_token_envelope(&envelope, true, time.as_unix_seconds())
        .map_err(|error| map_envelope_error(error, token.claims.issuer_did()))
}

fn map_envelope_error(error: VerifiedPrimitiveError, issuer_did: &str) -> TokenError {
    match error {
        VerifiedPrimitiveError::TokenValidation { failure } => match failure {
            TokenValidationFailure::ExpiredToken | TokenValidationFailure::NotYetValid => TokenError::Temporal {
                message: failure.to_string(),
            },
            TokenValidationFailure::SelfDelegation => TokenError::SelfDelegation {
                did: issuer_did.to_owned(),
            },
            TokenValidationFailure::InvalidSignature => TokenError::Signature {
                issuer: "unknown".to_owned(),
            },
            TokenValidationFailure::MissingIssuer
            | TokenValidationFailure::MissingAudience
            | TokenValidationFailure::MissingAttenuations => TokenError::VerifiedPrimitive {
                source: VerifiedPrimitiveError::TokenValidation { failure },
            },
        },
        other => TokenError::VerifiedPrimitive { source: other },
    }
}

fn token_envelope(token: &StructurallyValidToken) -> TokenResult<TokenEnvelopeInput> {
    Ok(TokenEnvelopeInput {
        issuer_did: token.claims.issuer_did().to_owned(),
        audience_did: token.claims.audience_did().to_owned(),
        capabilities: claims_capabilities(&token.claims)?,
        proofs: token.claims.proofs().iter().map(|proof| proof.as_bytes().to_vec()).collect(),
        expires_at_seconds: token.claims.time_bounds().expires_at_seconds(),
        not_before_seconds: token.claims.time_bounds().not_before_seconds(),
    })
}

fn claims_capability_set(claims: &ucan_core::token::Claims) -> TokenResult<CapabilitySet> {
    CapabilitySet::new(claims_capabilities(claims)?)
}

fn claims_capabilities(claims: &ucan_core::token::Claims) -> TokenResult<Vec<CapabilityDocument>> {
    claims
        .capabilities()
        .iter()
        .map(|capability| CapabilityDocument::new(capability.resource().to_owned(), capability.ability().to_owned()))
        .collect::<crate::Result<Vec<_>>>()
        .map_err(|error| TokenError::Capability {
            message: error.to_string(),
        })
}

const fn claims_time_bounds(claims: &ucan_core::token::Claims) -> TokenResult<TokenTimeBounds> {
    TokenTimeBounds::new(claims.time_bounds().not_before_seconds(), claims.time_bounds().expires_at_seconds())
}

fn reject_cycle(token: &CompactToken, trail: &[Vec<u8>]) -> TokenResult<()> {
    let current = proof_reference_for_token(token);
    if trail.iter().any(|reference| reference.as_slice() == current.as_slice()) {
        return Err(TokenError::ProofChain {
            message: "proof chain contains a cycle".to_owned(),
        });
    }
    Ok(())
}

fn assert_issued_token_is_structurally_valid(token: &CompactToken, proof_references: &[Vec<u8>]) -> TokenResult<()> {
    let decoded = parse_compact_token(token)?;
    let valid = validate_decoded_token(decoded)?;
    let actual: Vec<Vec<u8>> = valid.claims().proofs().iter().map(|proof| proof.as_bytes().to_vec()).collect();
    if actual != proof_references {
        return Err(TokenError::ProofChain {
            message: "issued proof references did not round-trip through core validation".to_owned(),
        });
    }
    Ok(())
}

fn encoded_claims<'a>(issuer: &'a IssuerDid, request: &'a IssueRequest) -> EncodedClaims<'a> {
    EncodedClaims {
        iss: issuer.as_str(),
        aud: request.audience.as_str(),
        att: request
            .capabilities
            .as_slice()
            .iter()
            .map(|capability| EncodedCapability {
                resource: capability.resource.as_str(),
                ability: capability.ability.as_str(),
            })
            .collect(),
        prf: encode_proof_references(request.proofs.as_slice())
            .into_iter()
            .map(|reference| URL_SAFE_NO_PAD.encode(reference))
            .collect(),
        exp: request.time_bounds.expires_at_seconds(),
        nbf: request.time_bounds.not_before_seconds(),
    }
}

fn encode_proof_references(proofs: &[CompactToken]) -> Vec<Vec<u8>> {
    proofs.iter().map(proof_reference_for_token).collect()
}

fn proof_reference_for_token(token: &CompactToken) -> Vec<u8> {
    let digest = blake3::hash(token.as_str().as_bytes());
    let bytes = digest.as_bytes();
    debug_assert_eq!(bytes.len(), PROOF_REFERENCE_DIGEST_LEN);
    bytes.to_vec()
}

fn compact_parts(token: &str) -> TokenResult<Vec<&str>> {
    let parts: Vec<&str> = token.split(COMPACT_SEPARATOR).collect();
    if parts.len() != COMPACT_TOKEN_PART_COUNT {
        return Err(TokenError::InvalidCompactTokenStructure {
            actual_parts: parts.len(),
        });
    }
    Ok(parts)
}

fn validate_compact_token_string(token: &str) -> TokenResult<()> {
    if token.is_empty() {
        return Err(TokenError::EmptyCompactToken);
    }
    if token.trim() != token {
        return Err(TokenError::CompactTokenMustBeTrimmed);
    }
    Ok(())
}

fn validate_header(header: &DecodedHeader) -> TokenResult<()> {
    if header.alg == TOKEN_ALGORITHM_EDDSA && header.typ == TOKEN_TYPE_JWT {
        return Ok(());
    }
    Err(TokenError::UnsupportedHeader {
        algorithm: header.alg.clone(),
        token_type: header.typ.clone(),
    })
}

fn encode_json_part<T: Serialize>(value: &T) -> TokenResult<String> {
    let bytes = serde_json::to_vec(value).map_err(|error| TokenError::JsonEncode {
        message: error.to_string(),
    })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_json_part<T: DeserializeOwned>(part: &str, compact_part: CompactPart) -> TokenResult<T> {
    let bytes = decode_part(part, compact_part)?;
    serde_json::from_slice(bytes.as_slice()).map_err(|error| TokenError::JsonDecode {
        part: compact_part,
        message: error.to_string(),
    })
}

fn decode_part(part: &str, compact_part: CompactPart) -> TokenResult<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(part).map_err(|error| TokenError::Base64Decode {
        part: compact_part,
        message: error.to_string(),
    })
}

fn signing_input(header: &str, payload: &str) -> String {
    format!("{header}{COMPACT_SEPARATOR}{payload}")
}

fn join_compact_parts(header: &str, payload: &str, signature: &str) -> String {
    format!("{header}{COMPACT_SEPARATOR}{payload}{COMPACT_SEPARATOR}{signature}")
}

fn decoded_capability_inputs(
    claims: &DecodedClaims,
) -> TokenResult<Option<Vec<ucan_core::token::CapabilityInput<'_>>>> {
    let Some(capabilities) = claims.att.as_ref() else {
        return Ok(None);
    };
    let mut inputs = Vec::with_capacity(capabilities.len());
    for (index, capability) in capabilities.iter().enumerate() {
        let resource = capability.resource.as_deref().ok_or(TokenError::MissingCapabilityField {
            index,
            field: CAPABILITY_RESOURCE_FIELD,
        })?;
        let ability = capability.ability.as_deref().ok_or(TokenError::MissingCapabilityField {
            index,
            field: CAPABILITY_ABILITY_FIELD,
        })?;
        inputs.push(ucan_core::token::CapabilityInput::new(resource, ability));
    }
    Ok(Some(inputs))
}

fn decoded_proof_references(claims: &DecodedClaims) -> TokenResult<Option<Vec<Vec<u8>>>> {
    let Some(proofs) = claims.prf.as_ref() else {
        return Ok(None);
    };
    proofs
        .iter()
        .map(|proof| decode_part(proof, CompactPart::Payload))
        .collect::<TokenResult<Vec<_>>>()
        .map(Some)
}

fn proof_reference_inputs(references: &[Vec<u8>]) -> Vec<ucan_core::token::ProofReferenceInput<'_>> {
    references
        .iter()
        .map(|reference| ucan_core::token::ProofReferenceInput::new(reference.as_slice()))
        .collect()
}

fn capability_inputs(capabilities: &[CapabilityDocument]) -> Vec<ucan_core::token::CapabilityInput<'_>> {
    capabilities
        .iter()
        .map(|capability| {
            ucan_core::token::CapabilityInput::new(capability.resource.as_str(), capability.ability.as_str())
        })
        .collect()
}

fn copy_secret_key(bytes: &[u8]) -> TokenResult<[u8; ED25519_SECRET_KEY_BYTES]> {
    bytes.try_into().map_err(|_| TokenError::InvalidSecretKeyLength { actual: bytes.len() })
}

fn copy_public_key(bytes: &[u8]) -> TokenResult<[u8; ED25519_PUBLIC_KEY_BYTES]> {
    bytes.try_into().map_err(|_| TokenError::InvalidPublicKeyLength { actual: bytes.len() })
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use serde_json::Value;

    use super::AudienceDid;
    use super::CapabilitySet;
    use super::CompactToken;
    use super::Ed25519SigningKey;
    use super::Ed25519VerificationKey;
    use super::IssueRequest;
    use super::KeyResolutionContext;
    use super::ProofCollection;
    use super::TokenError;
    use super::TokenTimeBounds;
    use super::VerificationContext;
    use super::VerificationTime;
    use super::issue_token;
    use super::parse_compact_token;
    use super::validate_decoded_token;
    use super::verify_compact_token;
    use crate::shell::CapabilityDocument;

    const ISSUER_SECRET_BYTE: u8 = 7;
    const AUDIENCE_SECRET_BYTE: u8 = 9;
    const OTHER_SECRET_BYTE: u8 = 11;
    const CHILD_SECRET_BYTE: u8 = AUDIENCE_SECRET_BYTE;
    const TOKEN_NOT_BEFORE_SECONDS: u64 = 1_000;
    const TOKEN_EXPIRES_AT_SECONDS: u64 = 2_000;
    const CHILD_NOT_BEFORE_SECONDS: u64 = 1_100;
    const CHILD_EXPIRES_AT_SECONDS: u64 = 1_900;
    const VERIFICATION_TIME_SECONDS: u64 = 1_500;
    const EXPIRED_TIME_SECONDS: u64 = 3_000;
    const INVALID_KEY_LEN: usize = 1;
    const COMPACT_PART_COUNT: usize = 3;
    const EXPECTED_CLAIM_COUNT: usize = 6;
    const REDACTION_TEST_SECRET_BYTE: u8 = 0xAA;
    const REDACTION_TEST_SECRET_DECIMAL: &str = "170";
    const REDACTION_TEST_SECRET_HEX_LOWER: &str = "aa";
    const REDACTION_TEST_DIRECT_ARRAY_PREFIX: &str = "[170, 170";

    #[test]
    fn issues_and_verifies_token_round_trip() {
        let issuer_key = signing_key(ISSUER_SECRET_BYTE);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let token = issue_token(&issue_request(&issuer_key, AudienceDid::from(audience), ProofCollection::empty()))
            .expect("token should issue");
        let context = verification_context(vec![&issuer_key], ProofCollection::empty(), VERIFICATION_TIME_SECONDS);

        let verified = verify_compact_token(&token, &context).expect("issued token should verify");

        assert_eq!(verified.issuer().as_str(), issuer_key.issuer().expect("issuer did should derive").as_str());
        assert_eq!(verified.capabilities().as_slice().len(), 1);
        assert!(verified.proofs().as_slice().is_empty());
        assert_eq!(verified.effective_delegation().time_bounds().not_before_seconds(), TOKEN_NOT_BEFORE_SECONDS);
    }

    #[test]
    fn issued_token_uses_required_compact_shape_and_claim_names() {
        let issuer_key = signing_key(ISSUER_SECRET_BYTE);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let token = issue_token(&issue_request(&issuer_key, AudienceDid::from(audience), ProofCollection::empty()))
            .expect("token should issue");
        let parts: Vec<&str> = token.as_str().split('.').collect();

        assert_eq!(parts.len(), COMPACT_PART_COUNT);
        let payload = super::decode_part(parts[1], super::CompactPart::Payload).expect("payload should decode");
        let json: Value = serde_json::from_slice(payload.as_slice()).expect("payload should be JSON");
        let object = json.as_object().expect("payload should be object");
        assert_eq!(object.len(), EXPECTED_CLAIM_COUNT);
        for key in ["iss", "aud", "att", "prf", "exp", "nbf"] {
            assert!(object.contains_key(key), "missing claim key {key}");
        }
    }

    #[test]
    fn malformed_compact_token_returns_structured_error() {
        let token = CompactToken::new("not.enough").expect("string wrapper should accept non-empty input");
        let error = parse_compact_token(&token).expect_err("two-part token should fail");

        assert_eq!(error, TokenError::InvalidCompactTokenStructure { actual_parts: 2 });
    }

    #[test]
    fn missing_required_claim_returns_core_error() {
        let token = token_with_payload(r#"{"aud":"did:key:zAudience","att":[],"prf":[],"exp":2,"nbf":1}"#);
        let decoded = parse_compact_token(&token).expect("token should decode");
        let error = validate_decoded_token(decoded).expect_err("missing issuer should fail");

        assert!(matches!(error, TokenError::CoreClaims { .. }));
    }

    #[test]
    fn signature_mismatch_is_rejected() {
        let issuer_key = signing_key(ISSUER_SECRET_BYTE);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let token = issue_token(&issue_request(&issuer_key, AudienceDid::from(audience), ProofCollection::empty()))
            .expect("token should issue");
        let tampered = tamper_signature(&token);
        let context = verification_context(vec![&issuer_key], ProofCollection::empty(), VERIFICATION_TIME_SECONDS);
        let error = verify_compact_token(&tampered, &context).expect_err("tampered signature should fail");

        assert!(matches!(error, TokenError::Signature { .. }));
    }

    #[test]
    fn malformed_public_api_inputs_fail_deterministically() {
        let short_key = [ISSUER_SECRET_BYTE; INVALID_KEY_LEN];
        let error = Ed25519SigningKey::try_from_slice(&short_key).expect_err("short key should fail");

        assert_eq!(error, TokenError::InvalidSecretKeyLength {
            actual: INVALID_KEY_LEN
        });
    }

    #[test]
    fn ed25519_signing_key_debug_redacts_secret_bytes() {
        let key = signing_key(REDACTION_TEST_SECRET_BYTE);
        let debug_output = format!("{key:?}");

        assert!(debug_output.contains("Ed25519SigningKey"));
        assert!(debug_output.contains(super::REDACTED_SECRET_MATERIAL_DEBUG));
        assert_secret_material_is_absent(debug_output.as_str());
    }

    #[test]
    fn issue_request_debug_redacts_embedded_signing_key() {
        let issuer_key = signing_key(REDACTION_TEST_SECRET_BYTE);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let request = issue_request(&issuer_key, AudienceDid::from(audience), ProofCollection::empty());
        let debug_output = format!("{request:?}");

        assert!(debug_output.contains("IssueRequest"));
        assert!(debug_output.contains(super::REDACTED_SECRET_MATERIAL_DEBUG));
        assert_secret_material_is_absent(debug_output.as_str());
    }

    #[test]
    fn invalid_secret_key_errors_do_not_echo_input_bytes() {
        let malformed_key = [REDACTION_TEST_SECRET_BYTE; INVALID_KEY_LEN];
        let error = Ed25519SigningKey::try_from_slice(&malformed_key).expect_err("short key should fail");
        let display_output = format!("{error}");
        let debug_output = format!("{error:?}");

        assert!(matches!(error, TokenError::InvalidSecretKeyLength { .. }));
        assert_secret_material_is_absent(display_output.as_str());
        assert_secret_material_is_absent(debug_output.as_str());
    }

    #[test]
    fn valid_delegation_chain_exposes_effective_constraints() {
        let parent_key = signing_key(ISSUER_SECRET_BYTE);
        let child_key = signing_key(CHILD_SECRET_BYTE);
        let child_issuer = child_key.issuer().expect("child issuer should derive");
        let parent =
            issue_token(&issue_request(&parent_key, AudienceDid::from(child_issuer.clone()), ProofCollection::empty()))
                .expect("parent should issue");
        let child = issue_token(&child_request(&child_key, parent.clone())).expect("child should issue");
        let context = verification_context(
            vec![&parent_key, &child_key],
            ProofCollection::from_tokens(vec![parent]),
            VERIFICATION_TIME_SECONDS,
        );

        let verified = verify_compact_token(&child, &context).expect("delegation chain should verify");

        assert_eq!(verified.issuer().as_str(), child_issuer.as_str());
        assert_eq!(verified.proofs().as_slice().len(), 1);
        assert_eq!(verified.effective_delegation().time_bounds().expires_at_seconds(), CHILD_EXPIRES_AT_SECONDS);
    }

    #[test]
    fn over_broad_child_capability_is_rejected() {
        let parent_key = signing_key(ISSUER_SECRET_BYTE);
        let child_key = signing_key(CHILD_SECRET_BYTE);
        let child_issuer = child_key.issuer().expect("child issuer should derive");
        let parent =
            issue_token(&issue_request(&parent_key, AudienceDid::from(child_issuer), ProofCollection::empty()))
                .expect("parent should issue");
        let child = issue_token(&over_broad_child_request(&child_key, parent.clone())).expect("child should issue");
        let context = verification_context(
            vec![&parent_key, &child_key],
            ProofCollection::from_tokens(vec![parent]),
            VERIFICATION_TIME_SECONDS,
        );
        let error = verify_compact_token(&child, &context).expect_err("over-broad child should fail");

        assert!(matches!(error, TokenError::Attenuation { .. }));
    }

    #[test]
    fn widened_child_window_is_rejected_as_temporal_error() {
        let parent_key = signing_key(ISSUER_SECRET_BYTE);
        let child_key = signing_key(CHILD_SECRET_BYTE);
        let child_issuer = child_key.issuer().expect("child issuer should derive");
        let parent =
            issue_token(&issue_request(&parent_key, AudienceDid::from(child_issuer), ProofCollection::empty()))
                .expect("parent should issue");
        let child = issue_token(&widened_child_request(&child_key, parent.clone())).expect("child should issue");
        let context = verification_context(
            vec![&parent_key, &child_key],
            ProofCollection::from_tokens(vec![parent]),
            VERIFICATION_TIME_SECONDS,
        );
        let error = verify_compact_token(&child, &context).expect_err("widened child should fail");

        assert!(matches!(error, TokenError::Temporal { .. }));
    }

    #[test]
    fn expired_parent_is_rejected_as_temporal_error() {
        let parent_key = signing_key(ISSUER_SECRET_BYTE);
        let child_key = signing_key(CHILD_SECRET_BYTE);
        let child_issuer = child_key.issuer().expect("child issuer should derive");
        let parent =
            issue_token(&issue_request(&parent_key, AudienceDid::from(child_issuer), ProofCollection::empty()))
                .expect("parent should issue");
        let child = issue_token(&child_request(&child_key, parent.clone())).expect("child should issue");
        let context = verification_context(
            vec![&parent_key, &child_key],
            ProofCollection::from_tokens(vec![parent]),
            EXPIRED_TIME_SECONDS,
        );
        let error = verify_compact_token(&child, &context).expect_err("expired parent should fail");

        assert!(matches!(error, TokenError::Temporal { .. }));
    }

    #[test]
    fn self_delegation_is_rejected_directly_and_in_chain() {
        let key = signing_key(ISSUER_SECRET_BYTE);
        let self_did = key.issuer().expect("issuer should derive");
        let token = issue_token(&issue_request(&key, AudienceDid::from(self_did), ProofCollection::empty()))
            .expect("self-delegating token can be issued but not verified");
        let context = verification_context(vec![&key], ProofCollection::empty(), VERIFICATION_TIME_SECONDS);
        let error = verify_compact_token(&token, &context).expect_err("self delegation should fail");

        assert!(matches!(error, TokenError::SelfDelegation { .. }));
    }

    #[test]
    fn self_delegating_parent_is_rejected_in_chain() {
        let parent_key = signing_key(ISSUER_SECRET_BYTE);
        let child_key = signing_key(CHILD_SECRET_BYTE);
        let self_did = parent_key.issuer().expect("parent issuer should derive");
        let parent = issue_token(&issue_request(&parent_key, AudienceDid::from(self_did), ProofCollection::empty()))
            .expect("parent can be issued");
        let child = issue_token(&child_request(&child_key, parent.clone())).expect("child should issue");
        let context = verification_context(
            vec![&parent_key, &child_key],
            ProofCollection::from_tokens(vec![parent]),
            VERIFICATION_TIME_SECONDS,
        );
        let error = verify_compact_token(&child, &context).expect_err("self-delegating parent should fail");

        assert!(matches!(error, TokenError::SelfDelegation { .. }));
    }

    #[test]
    fn broken_issuer_audience_link_is_proof_chain_error() {
        let parent_key = signing_key(ISSUER_SECRET_BYTE);
        let child_key = signing_key(CHILD_SECRET_BYTE);
        let wrong_audience = signing_key(OTHER_SECRET_BYTE).issuer().expect("wrong audience should derive");
        let parent =
            issue_token(&issue_request(&parent_key, AudienceDid::from(wrong_audience), ProofCollection::empty()))
                .expect("parent should issue");
        let child = issue_token(&child_request(&child_key, parent.clone())).expect("child should issue");
        let context = verification_context(
            vec![&parent_key, &child_key],
            ProofCollection::from_tokens(vec![parent]),
            VERIFICATION_TIME_SECONDS,
        );
        let error = verify_compact_token(&child, &context).expect_err("broken proof link should fail");

        assert!(matches!(error, TokenError::ProofChain { .. }));
    }

    #[test]
    fn missing_proof_material_is_proof_chain_error() {
        let parent_key = signing_key(ISSUER_SECRET_BYTE);
        let child_key = signing_key(CHILD_SECRET_BYTE);
        let child_issuer = child_key.issuer().expect("child issuer should derive");
        let parent =
            issue_token(&issue_request(&parent_key, AudienceDid::from(child_issuer), ProofCollection::empty()))
                .expect("parent should issue");
        let child = issue_token(&child_request(&child_key, parent)).expect("child should issue");
        let context =
            verification_context(vec![&parent_key, &child_key], ProofCollection::empty(), VERIFICATION_TIME_SECONDS);
        let error = verify_compact_token(&child, &context).expect_err("missing proof should fail");

        assert!(matches!(error, TokenError::ProofChain { .. }));
    }

    fn signing_key(byte: u8) -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes([byte; super::ED25519_SECRET_KEY_BYTES])
    }

    fn issue_request(issuer_key: &Ed25519SigningKey, audience: AudienceDid, proofs: ProofCollection) -> IssueRequest {
        IssueRequest::new(
            issuer_key.clone(),
            audience,
            capabilities("did:key:z6Mkresource", "store/*"),
            proofs,
            TokenTimeBounds::new(TOKEN_NOT_BEFORE_SECONDS, TOKEN_EXPIRES_AT_SECONDS).expect("bounds should validate"),
        )
    }

    fn child_request(issuer_key: &Ed25519SigningKey, parent: CompactToken) -> IssueRequest {
        let audience = signing_key(OTHER_SECRET_BYTE).issuer().expect("audience should derive");
        IssueRequest::new(
            issuer_key.clone(),
            AudienceDid::from(audience),
            capabilities("did:key:z6Mkresource/photos", "store/add"),
            ProofCollection::from_tokens(vec![parent]),
            TokenTimeBounds::new(CHILD_NOT_BEFORE_SECONDS, CHILD_EXPIRES_AT_SECONDS).expect("bounds should validate"),
        )
    }

    fn widened_child_request(issuer_key: &Ed25519SigningKey, parent: CompactToken) -> IssueRequest {
        const WIDENED_CHILD_EXPIRES_AT_SECONDS: u64 = TOKEN_EXPIRES_AT_SECONDS + 1;
        let audience = signing_key(OTHER_SECRET_BYTE).issuer().expect("audience should derive");
        IssueRequest::new(
            issuer_key.clone(),
            AudienceDid::from(audience),
            capabilities("did:key:z6Mkresource/photos", "store/add"),
            ProofCollection::from_tokens(vec![parent]),
            TokenTimeBounds::new(CHILD_NOT_BEFORE_SECONDS, WIDENED_CHILD_EXPIRES_AT_SECONDS)
                .expect("bounds should validate"),
        )
    }

    fn over_broad_child_request(issuer_key: &Ed25519SigningKey, parent: CompactToken) -> IssueRequest {
        let audience = signing_key(OTHER_SECRET_BYTE).issuer().expect("audience should derive");
        IssueRequest::new(
            issuer_key.clone(),
            AudienceDid::from(audience),
            capabilities("did:key:z6Mkresource/photos", "admin/delete"),
            ProofCollection::from_tokens(vec![parent]),
            TokenTimeBounds::new(CHILD_NOT_BEFORE_SECONDS, CHILD_EXPIRES_AT_SECONDS).expect("bounds should validate"),
        )
    }

    fn capabilities(resource: &str, ability: &str) -> CapabilitySet {
        CapabilitySet::new(vec![
            CapabilityDocument::new(resource.to_owned(), ability.to_owned()).expect("capability should validate"),
        ])
        .expect("capability set should validate")
    }

    fn verification_context(
        signing_keys: Vec<&Ed25519SigningKey>,
        proofs: ProofCollection,
        time_seconds: u64,
    ) -> VerificationContext {
        let keys = signing_keys
            .into_iter()
            .map(Ed25519VerificationKey::from_signing_key)
            .collect::<Result<Vec<_>, _>>()
            .expect("verification keys should derive");
        VerificationContext::new(
            VerificationTime::from_unix_seconds(time_seconds),
            KeyResolutionContext::new(keys),
            proofs,
        )
    }

    fn tamper_signature(token: &CompactToken) -> CompactToken {
        const FIRST_SIGNATURE_CHAR_INDEX: usize = 0;
        const REPLACEMENT_A: u8 = b'A';
        const REPLACEMENT_B: u8 = b'B';
        let parts: Vec<&str> = token.as_str().split('.').collect();
        let mut signature = parts[2].as_bytes().to_vec();
        let original = signature[FIRST_SIGNATURE_CHAR_INDEX];
        signature[FIRST_SIGNATURE_CHAR_INDEX] = if original == REPLACEMENT_A {
            REPLACEMENT_B
        } else {
            REPLACEMENT_A
        };
        let signature = String::from_utf8(signature).expect("base64url signature should remain utf-8");
        CompactToken::new(super::join_compact_parts(parts[0], parts[1], signature.as_str()))
            .expect("tampered token should wrap")
    }

    fn token_with_payload(payload_json: &str) -> CompactToken {
        let header = super::EncodedHeader {
            alg: super::TOKEN_ALGORITHM_EDDSA,
            typ: super::TOKEN_TYPE_JWT,
        };
        let header = super::encode_json_part(&header).expect("header should encode");
        let payload = super::URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signature = super::URL_SAFE_NO_PAD.encode([0_u8; verified_logic::ucan_signature::SIGNATURE_LEN]);
        CompactToken::new(super::join_compact_parts(&header, &payload, &signature)).expect("token should wrap")
    }

    fn assert_secret_material_is_absent(output: &str) {
        assert!(!output.contains(REDACTION_TEST_SECRET_DECIMAL));
        assert!(!output.contains(REDACTION_TEST_DIRECT_ARRAY_PREFIX));
        assert!(!output.to_ascii_lowercase().contains(REDACTION_TEST_SECRET_HEX_LOWER));
    }
}
