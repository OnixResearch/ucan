#![allow(clippy::module_name_repetitions)]

use core::fmt;
use core::str::FromStr;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::shell::CapabilityDocument;
use crate::shell::CaveatDocument;
use crate::verified::TokenEnvelopeInput;
use crate::verified::TokenTimeWindow;
use crate::verified::TokenValidationFailure;
use crate::verified::VerifiedCapability;
use crate::verified::VerifiedPrimitiveError;
use crate::verified::compose_time_window_chain;
use crate::verified::derive_ed25519_public_key;
use crate::verified::encode_ed25519_did_key;
use crate::verified::invocation_request_is_authorized;
use crate::verified::proof_link_is_valid;
use crate::verified::revocation_reference_is_listed;
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
const DEFAULT_MAX_PROOF_DEPTH: usize = 16;
const DEFAULT_MAX_PROOF_COUNT: usize = 64;
const DEFAULT_MAX_COMPACT_TOKEN_BYTES: usize = 64 * 1024;
pub const ED25519_SECRET_KEY_BYTES: usize = verified_logic::ucan_signature::SECRET_KEY_LEN;
pub const ED25519_PUBLIC_KEY_BYTES: usize = verified_logic::ucan_signature::PUBLIC_KEY_LEN;
pub const ED25519_SIGNATURE_BYTES: usize = verified_logic::ucan_signature::SIGNATURE_LEN;

pub type SignerResult<T> = std::result::Result<T, SignerError>;
pub type TokenResult<T> = std::result::Result<T, TokenError>;
pub type BuilderResult<T> = std::result::Result<T, BuilderError>;
pub type TimeConversionResult<T> = std::result::Result<T, TimeConversionError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderError {
    MissingField { field: &'static str },
}

impl fmt::Display for BuilderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField { field } => write!(formatter, "missing required builder field {field}"),
        }
    }
}

impl std::error::Error for BuilderError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeConversionError {
    BeforeUnixEpoch,
    DurationOverflow,
    InvalidBounds { message: String },
}

impl fmt::Display for TimeConversionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeforeUnixEpoch => formatter.write_str("system time precedes the Unix epoch"),
            Self::DurationOverflow => formatter.write_str("time bounds overflow u64 Unix seconds"),
            Self::InvalidBounds { message } => write!(formatter, "invalid time bounds: {message}"),
        }
    }
}

impl std::error::Error for TimeConversionError {}

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
pub enum SignerError {
    Refused,
    UnsupportedAlgorithm { algorithm: String },
    InvalidSignatureLength { actual: usize, expected: usize },
    IssuerPublicKeyMismatch { issuer: String, public_key_issuer: String },
}

impl fmt::Display for SignerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused => formatter.write_str("signer refused to sign"),
            Self::UnsupportedAlgorithm { algorithm } => {
                write!(formatter, "unsupported signer algorithm {algorithm:?}")
            }
            Self::InvalidSignatureLength { actual, expected } => {
                write!(formatter, "signer returned {actual} signature bytes, expected {expected}")
            }
            Self::IssuerPublicKeyMismatch {
                issuer,
                public_key_issuer,
            } => {
                write!(formatter, "signer issuer {issuer} does not match public key issuer {public_key_issuer}")
            }
        }
    }
}

impl std::error::Error for SignerError {}

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
    KeyResolver { source: KeyResolverError },
    ProofStore { source: ProofStoreError },
    Revocation { source: RevocationError },
    Revoked { reference: ProofReference },
    LimitExceeded { source: VerificationLimitError },
    Signature { issuer: String },
    Temporal { message: String },
    SelfDelegation { did: String },
    ProofChain { message: String },
    Attenuation { resource: String, ability: String },
    Signer { source: SignerError },
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
            Self::KeyResolver { source } => write!(formatter, "key resolver failed: {source}"),
            Self::ProofStore { source } => write!(formatter, "proof store failed: {source}"),
            Self::Revocation { source } => write!(formatter, "revocation check failed: {source}"),
            Self::Revoked { reference } => write!(formatter, "token reference {reference} is revoked"),
            Self::LimitExceeded { source } => write!(formatter, "verification limit exceeded: {source}"),
            Self::Signature { issuer } => write!(formatter, "signature failed for issuer {issuer}"),
            Self::Temporal { message } => write!(formatter, "temporal verification failed: {message}"),
            Self::SelfDelegation { did } => write!(formatter, "self-delegation rejected for {did}"),
            Self::ProofChain { message } => write!(formatter, "proof-chain verification failed: {message}"),
            Self::Attenuation { resource, ability } => {
                write!(formatter, "capability {resource} {ability} is not delegated by proofs")
            }
            Self::Signer { source } => write!(formatter, "signer failed: {source}"),
            Self::VerifiedPrimitive { source } => write!(formatter, "verified primitive failed: {source}"),
        }
    }
}

impl std::error::Error for TokenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CoreClaims { source } => Some(source),
            Self::Signer { source } => Some(source),
            Self::KeyResolver { source } => Some(source),
            Self::ProofStore { source } => Some(source),
            Self::Revocation { source } => Some(source),
            Self::LimitExceeded { source } => Some(source),
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
            | Self::Revoked { .. }
            | Self::Signature { .. }
            | Self::Temporal { .. }
            | Self::SelfDelegation { .. }
            | Self::ProofChain { .. }
            | Self::Attenuation { .. } => None,
        }
    }
}

impl From<SignerError> for TokenError {
    fn from(source: SignerError) -> Self {
        Self::Signer { source }
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
pub enum KeyResolverError {
    MissingKey { issuer: String },
    Backend { issuer: String, message: String },
}

impl fmt::Display for KeyResolverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingKey { issuer } => write!(formatter, "missing verification key for issuer {issuer}"),
            Self::Backend { issuer, message } => {
                write!(formatter, "backend failed resolving issuer {issuer}: {message}")
            }
        }
    }
}

impl std::error::Error for KeyResolverError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofStoreError {
    MissingProof { reference: ProofReference },
    Backend { reference: ProofReference, message: String },
}

impl fmt::Display for ProofStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProof { reference } => write!(formatter, "missing proof token {reference}"),
            Self::Backend { reference, message } => {
                write!(formatter, "backend failed resolving proof {reference}: {message}")
            }
        }
    }
}

impl std::error::Error for ProofStoreError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationError {
    Backend { reference: ProofReference, message: String },
}

impl fmt::Display for RevocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend { reference, message } => {
                write!(formatter, "backend failed checking revocation for {reference}: {message}")
            }
        }
    }
}

impl std::error::Error for RevocationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationLimitError {
    ProofDepthExceeded { depth: usize, max_depth: usize },
    ProofCountExceeded { count: usize, max_count: usize },
    CompactTokenTooLarge { byte_len: usize, max_byte_len: usize },
}

impl fmt::Display for VerificationLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProofDepthExceeded { depth, max_depth } => {
                write!(formatter, "proof depth {depth} exceeds configured maximum {max_depth}")
            }
            Self::ProofCountExceeded { count, max_count } => {
                write!(formatter, "proof count {count} exceeds configured maximum {max_count}")
            }
            Self::CompactTokenTooLarge { byte_len, max_byte_len } => {
                write!(formatter, "compact token has {byte_len} bytes, maximum is {max_byte_len}")
            }
        }
    }
}

impl std::error::Error for VerificationLimitError {}

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

impl FromStr for CompactToken {
    type Err = TokenError;

    fn from_str(input: &str) -> TokenResult<Self> {
        Self::new(input.to_owned())
    }
}

impl TryFrom<&str> for CompactToken {
    type Error = TokenError;

    fn try_from(value: &str) -> TokenResult<Self> {
        Self::new(value.to_owned())
    }
}

impl TryFrom<String> for CompactToken {
    type Error = TokenError;

    fn try_from(value: String) -> TokenResult<Self> {
        Self::new(value)
    }
}

impl Serialize for CompactToken {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where S: serde::Serializer {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CompactToken {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where D: serde::Deserializer<'de> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
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

impl FromStr for IssuerDid {
    type Err = TokenError;

    fn from_str(input: &str) -> TokenResult<Self> {
        Self::new(input.to_owned())
    }
}

impl TryFrom<&str> for IssuerDid {
    type Error = TokenError;

    fn try_from(value: &str) -> TokenResult<Self> {
        Self::new(value.to_owned())
    }
}

impl TryFrom<String> for IssuerDid {
    type Error = TokenError;

    fn try_from(value: String) -> TokenResult<Self> {
        Self::new(value)
    }
}

impl Serialize for IssuerDid {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where S: serde::Serializer {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for IssuerDid {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where D: serde::Deserializer<'de> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
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

impl FromStr for AudienceDid {
    type Err = TokenError;

    fn from_str(input: &str) -> TokenResult<Self> {
        Self::new(input.to_owned())
    }
}

impl TryFrom<&str> for AudienceDid {
    type Error = TokenError;

    fn try_from(value: &str) -> TokenResult<Self> {
        Self::new(value.to_owned())
    }
}

impl TryFrom<String> for AudienceDid {
    type Error = TokenError;

    fn try_from(value: String) -> TokenResult<Self> {
        Self::new(value)
    }
}

impl Serialize for AudienceDid {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where S: serde::Serializer {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AudienceDid {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where D: serde::Deserializer<'de> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    capability: CapabilityDocument,
}

impl AuthorizationRequest {
    /// Build a concrete authorization request.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] when the requested resource or ability is not a
    /// valid capability input, or when the requested ability contains a wildcard
    /// segment. Wildcards are valid in delegated capabilities, but not in a
    /// concrete operation request.
    pub fn new(resource: impl Into<String>, ability: impl Into<String>) -> TokenResult<Self> {
        let capability =
            CapabilityDocument::new(resource.into(), ability.into()).map_err(|error| TokenError::Capability {
                message: error.to_string(),
            })?;
        let verified_capability =
            VerifiedCapability::from_document(capability.clone()).map_err(|error| TokenError::Capability {
                message: error.to_string(),
            })?;
        if !verified_capability.is_concrete() {
            return Err(TokenError::Capability {
                message: "authorization request ability must not contain wildcard segments".to_owned(),
            });
        }
        Ok(Self { capability })
    }

    #[must_use]
    pub const fn resource(&self) -> &str {
        self.capability.resource.as_str()
    }

    #[must_use]
    pub const fn ability(&self) -> &str {
        self.capability.ability.as_str()
    }

    #[must_use]
    pub const fn capability(&self) -> &CapabilityDocument {
        &self.capability
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationDenialReason {
    MalformedRequest { message: String },
    CaveatRejected { caveat: CaveatIdentifier, message: String },
    CaveatPolicyMissing { caveat: CaveatIdentifier },
    NoMatchingCapability,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaveatIdentifier {
    domain: String,
    caveat_type: String,
    key: String,
}

impl CaveatIdentifier {
    /// Build a caveat identity after core validation of identity fields.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] when any identity field is empty or untrimmed.
    pub fn new(domain: impl Into<String>, caveat_type: impl Into<String>, key: impl Into<String>) -> TokenResult<Self> {
        let domain = domain.into();
        let caveat_type = caveat_type.into();
        let key = key.into();
        ucan_core::token::CaveatView::new(domain.as_str(), caveat_type.as_str(), key.as_str(), &[0]).map_err(
            |source| TokenError::Capability {
                message: source.to_string(),
            },
        )?;
        Ok(Self {
            domain,
            caveat_type,
            key,
        })
    }

    #[must_use]
    pub const fn domain(&self) -> &str {
        self.domain.as_str()
    }
    #[must_use]
    pub const fn caveat_type(&self) -> &str {
        self.caveat_type.as_str()
    }
    #[must_use]
    pub const fn key(&self) -> &str {
        self.key.as_str()
    }
}

impl From<&CaveatDocument> for CaveatIdentifier {
    fn from(caveat: &CaveatDocument) -> Self {
        Self {
            domain: caveat.domain.clone(),
            caveat_type: caveat.caveat_type.clone(),
            key: caveat.key.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaveatDecision {
    Satisfied,
    Rejected { message: String },
}

impl CaveatDecision {
    #[must_use]
    pub const fn is_satisfied(&self) -> bool {
        matches!(self, Self::Satisfied)
    }
}

pub trait CaveatPolicy {
    fn evaluate(&self, caveat: &CaveatDocument, request: &AuthorizationRequest) -> CaveatDecision;
}

pub trait CaveatPolicySet {
    fn policy_for(&self, caveat: &CaveatIdentifier) -> Option<&dyn CaveatPolicy>;
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DenyUnknownCaveats;

impl CaveatPolicySet for DenyUnknownCaveats {
    fn policy_for(&self, _caveat: &CaveatIdentifier) -> Option<&dyn CaveatPolicy> {
        None
    }
}

pub struct InvocationRequest<'a> {
    token: &'a CompactToken,
    context: &'a VerificationContext,
    resource: String,
    ability: String,
    policies: &'a dyn CaveatPolicySet,
}

impl<'a> InvocationRequest<'a> {
    #[must_use]
    pub fn new(
        token: &'a CompactToken,
        context: &'a VerificationContext,
        resource: impl Into<String>,
        ability: impl Into<String>,
        policies: &'a dyn CaveatPolicySet,
    ) -> Self {
        Self {
            token,
            context,
            resource: resource.into(),
            ability: ability.into(),
            policies,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationAllowed {
    issuer: IssuerDid,
    invoker: IssuerDid,
    audience: AudienceDid,
    matched_capability: CapabilityDocument,
    effective_time_bounds: TokenTimeBounds,
}

impl InvocationAllowed {
    #[must_use]
    pub const fn issuer(&self) -> &IssuerDid {
        &self.issuer
    }
    #[must_use]
    pub const fn invoker(&self) -> &IssuerDid {
        &self.invoker
    }
    #[must_use]
    pub const fn audience(&self) -> &AudienceDid {
        &self.audience
    }
    #[must_use]
    pub const fn matched_capability(&self) -> &CapabilityDocument {
        &self.matched_capability
    }
    #[must_use]
    pub const fn effective_time_bounds(&self) -> TokenTimeBounds {
        self.effective_time_bounds
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvocationDenialReason {
    Authorization { reason: AuthorizationDenialReason },
    Verification { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvocationResult {
    Allowed { invocation: InvocationAllowed },
    Denied { reason: InvocationDenialReason },
}

impl InvocationResult {
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }
}

#[must_use]
pub fn verify_invocation(request: &InvocationRequest<'_>) -> InvocationResult {
    let verified = match verify_compact_token(request.token, request.context) {
        Ok(verified) => verified,
        Err(error) => {
            return InvocationResult::Denied {
                reason: InvocationDenialReason::Verification {
                    message: error.to_string(),
                },
            };
        }
    };
    match verified.authorize_with_policies(request.resource.as_str(), request.ability.as_str(), request.policies) {
        AuthorizationDecision::Allowed { matched_capability } => {
            let matched_verified = match VerifiedCapability::from_document(matched_capability.clone()) {
                Ok(matched_verified) => matched_verified,
                Err(error) => {
                    return InvocationResult::Denied {
                        reason: InvocationDenialReason::Verification {
                            message: error.to_string(),
                        },
                    };
                }
            };
            if matched_verified.is_concrete()
                && !invocation_request_is_authorized(
                    verified.audience().as_str(),
                    verified.audience().as_str(),
                    request.resource.as_str(),
                    request.ability.as_str(),
                    matched_capability.resource.as_str(),
                    matched_capability.ability.as_str(),
                )
            {
                return InvocationResult::Denied {
                    reason: InvocationDenialReason::Verification {
                        message: "concrete invocation admission failed verified invocation bridge".to_owned(),
                    },
                };
            }
            let invoker = match IssuerDid::new(verified.audience().as_str().to_owned()) {
                Ok(invoker) => invoker,
                Err(error) => {
                    return InvocationResult::Denied {
                        reason: InvocationDenialReason::Verification {
                            message: error.to_string(),
                        },
                    };
                }
            };
            InvocationResult::Allowed {
                invocation: InvocationAllowed {
                    issuer: verified.issuer().clone(),
                    invoker,
                    audience: verified.audience().clone(),
                    matched_capability,
                    effective_time_bounds: verified.effective_delegation().time_bounds(),
                },
            }
        }
        AuthorizationDecision::Denied { reason } => InvocationResult::Denied {
            reason: InvocationDenialReason::Authorization { reason },
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationDecision {
    Allowed { matched_capability: CapabilityDocument },
    Denied { reason: AuthorizationDenialReason },
}

impl AuthorizationDecision {
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    #[must_use]
    pub const fn matched_capability(&self) -> Option<&CapabilityDocument> {
        match self {
            Self::Allowed { matched_capability } => Some(matched_capability),
            Self::Denied { .. } => None,
        }
    }

    #[must_use]
    pub const fn denial_reason(&self) -> Option<&AuthorizationDenialReason> {
        match self {
            Self::Allowed { .. } => None,
            Self::Denied { reason } => Some(reason),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofReference(Vec<u8>);

impl ProofReference {
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    #[must_use]
    pub fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.as_bytes())
    }
}

impl fmt::Display for ProofReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.to_base64url().as_str())
    }
}

/// Synchronous shell-owned key resolver used by verification.
pub trait KeyResolver {
    /// Resolve a verification key for the supplied issuer DID.
    ///
    /// # Errors
    ///
    /// Returns [`KeyResolverError`] when the issuer key is missing or the
    /// resolver backend fails.
    fn resolve_key(&self, issuer: &IssuerDid) -> std::result::Result<Ed25519PublicKey, KeyResolverError>;
}

/// Synchronous shell-owned proof store used by verification.
pub trait ProofStore {
    /// Resolve a compact proof token by its proof reference.
    ///
    /// # Errors
    ///
    /// Returns [`ProofStoreError`] when the proof is missing or the store
    /// backend fails. Implementations should return serialized compact tokens
    /// so verification can enforce size limits before parsing.
    fn resolve_proof(&self, reference: &ProofReference) -> std::result::Result<CompactToken, ProofStoreError>;
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

impl ProofStore for ProofCollection {
    fn resolve_proof(&self, reference: &ProofReference) -> std::result::Result<CompactToken, ProofStoreError> {
        self.as_slice()
            .iter()
            .find(|candidate| proof_reference_for_token(candidate).as_bytes() == reference.as_bytes())
            .cloned()
            .ok_or_else(|| ProofStoreError::MissingProof {
                reference: reference.clone(),
            })
    }
}

/// Synchronous shell-owned revocation checker used by verification.
pub trait RevocationChecker {
    /// Return true when the compact-token proof reference has been revoked.
    ///
    /// # Errors
    ///
    /// Returns [`RevocationError`] when the revocation backend cannot answer.
    fn is_revoked(&self, reference: &ProofReference) -> std::result::Result<bool, RevocationError>;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoRevocations;

impl RevocationChecker for NoRevocations {
    fn is_revoked(&self, _reference: &ProofReference) -> std::result::Result<bool, RevocationError> {
        Ok(false)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevocationList(Vec<ProofReference>);

impl RevocationList {
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    #[must_use]
    pub const fn from_references(references: Vec<ProofReference>) -> Self {
        Self(references)
    }

    #[must_use]
    pub const fn as_slice(&self) -> &[ProofReference] {
        self.0.as_slice()
    }

    pub fn revoke(&mut self, reference: ProofReference) {
        let revoked_references =
            self.as_slice().iter().map(|existing| existing.as_bytes().to_vec()).collect::<Vec<_>>();
        if !revocation_reference_is_listed(&revoked_references, reference.as_bytes()) {
            self.0.push(reference);
        }
    }
}

impl RevocationChecker for RevocationList {
    fn is_revoked(&self, reference: &ProofReference) -> std::result::Result<bool, RevocationError> {
        let revoked_references =
            self.as_slice().iter().map(|candidate| candidate.as_bytes().to_vec()).collect::<Vec<_>>();
        Ok(revocation_reference_is_listed(&revoked_references, reference.as_bytes()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_field_names)]
pub struct VerificationLimits {
    proof_depth_limit: usize,
    proof_count_limit: usize,
    compact_token_byte_limit: usize,
}

impl VerificationLimits {
    #[must_use]
    pub const fn new(max_proof_depth: usize, max_proof_count: usize, max_compact_token_bytes: usize) -> Self {
        Self {
            proof_depth_limit: max_proof_depth,
            proof_count_limit: max_proof_count,
            compact_token_byte_limit: max_compact_token_bytes,
        }
    }

    #[must_use]
    pub const fn max_proof_depth(self) -> usize {
        self.proof_depth_limit
    }

    #[must_use]
    pub const fn max_proof_count(self) -> usize {
        self.proof_count_limit
    }

    #[must_use]
    pub const fn max_compact_token_bytes(self) -> usize {
        self.compact_token_byte_limit
    }
}

impl Default for VerificationLimits {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_PROOF_DEPTH, DEFAULT_MAX_PROOF_COUNT, DEFAULT_MAX_COMPACT_TOKEN_BYTES)
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

    /// Build token bounds from a deterministic start time and positive duration.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError`] when the duration overflows or yields invalid bounds.
    pub fn from_unix_seconds_and_duration(not_before_seconds: u64, duration: Duration) -> TimeConversionResult<Self> {
        let expires_at_seconds =
            not_before_seconds.checked_add(duration.as_secs()).ok_or(TimeConversionError::DurationOverflow)?;
        Self::new(not_before_seconds, expires_at_seconds).map_err(|error| TimeConversionError::InvalidBounds {
            message: error.to_string(),
        })
    }

    /// Build token bounds from a [`SystemTime`] start and positive duration.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError`] when the start time is before the Unix epoch,
    /// the duration overflows, or the resulting bounds are invalid.
    pub fn from_system_time_and_duration(start: SystemTime, duration: Duration) -> TimeConversionResult<Self> {
        let not_before_seconds = unix_seconds_from_system_time(start)?;
        Self::from_unix_seconds_and_duration(not_before_seconds, duration)
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

    /// Convert a [`SystemTime`] into deterministic Unix-second verification time.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::BeforeUnixEpoch`] when the supplied time is
    /// earlier than the Unix epoch.
    pub fn try_from_system_time(time: SystemTime) -> TimeConversionResult<Self> {
        unix_seconds_from_system_time(time).map(Self::from_unix_seconds)
    }
}

fn unix_seconds_from_system_time(time: SystemTime) -> TimeConversionResult<u64> {
    let duration = time.duration_since(UNIX_EPOCH).map_err(|_| TimeConversionError::BeforeUnixEpoch)?;
    Ok(duration.as_secs())
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

#[derive(Clone, PartialEq, Eq)]
pub struct SignerSignature {
    bytes: Vec<u8>,
}

impl fmt::Debug for SignerSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("SignerSignature");
        debug.field("byte_len", &self.bytes.len());
        debug.finish()
    }
}

impl SignerSignature {
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

/// Signing boundary for compact-token issuance.
///
/// Implementations keep private key custody outside the issuance pipeline while
/// exposing only algorithm identity, issuer identity, verification material, and
/// signatures over caller-provided bytes.
pub trait TokenSigner {
    #[must_use]
    fn algorithm(&self) -> &str;

    /// Return the signer issuer DID.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] when the signer cannot provide a valid issuer DID.
    fn issuer(&self) -> TokenResult<IssuerDid>;

    /// Return the public verification key for the signer.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] when the signer cannot provide valid verification material.
    fn public_key(&self) -> TokenResult<Ed25519PublicKey>;

    /// Sign the supplied compact-token signing input bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SignerError`] when the signer refuses or cannot produce a signature.
    fn sign(&self, signing_input: &[u8]) -> SignerResult<SignerSignature>;
}

#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519InMemorySigner {
    signing_key: Ed25519SigningKey,
}

impl fmt::Debug for Ed25519InMemorySigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("Ed25519InMemorySigner");
        debug.field("secret_key", &RedactedSecretMaterial);
        debug.finish()
    }
}

impl Ed25519InMemorySigner {
    #[must_use]
    pub const fn from_signing_key(signing_key: Ed25519SigningKey) -> Self {
        Self { signing_key }
    }

    #[must_use]
    pub const fn from_seed_bytes(bytes: [u8; ED25519_SECRET_KEY_BYTES]) -> Self {
        Self::from_signing_key(Ed25519SigningKey::from_bytes(bytes))
    }

    /// Build an in-memory signer from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::InvalidSecretKeyLength`] when the slice length is
    /// not the Ed25519 seed length.
    pub fn try_from_slice(bytes: &[u8]) -> TokenResult<Self> {
        let signing_key = Ed25519SigningKey::try_from_slice(bytes)?;
        Ok(Self::from_signing_key(signing_key))
    }

    /// Build the matching verification key for this in-memory signer.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] if public-key derivation or DID encoding fails.
    pub fn verification_key(&self) -> TokenResult<Ed25519VerificationKey> {
        Ed25519VerificationKey::from_signing_key(&self.signing_key)
    }
}

impl From<Ed25519SigningKey> for Ed25519InMemorySigner {
    fn from(signing_key: Ed25519SigningKey) -> Self {
        Self::from_signing_key(signing_key)
    }
}

impl TokenSigner for Ed25519InMemorySigner {
    fn algorithm(&self) -> &str {
        TOKEN_ALGORITHM_EDDSA
    }

    fn issuer(&self) -> TokenResult<IssuerDid> {
        self.signing_key.issuer()
    }

    fn public_key(&self) -> TokenResult<Ed25519PublicKey> {
        self.signing_key.public_key()
    }

    fn sign(&self, signing_input: &[u8]) -> SignerResult<SignerSignature> {
        let signature = sign_ed25519(self.signing_key.as_bytes(), signing_input).map_err(|_| SignerError::Refused)?;
        Ok(SignerSignature::new(signature))
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

impl KeyResolver for KeyResolutionContext {
    fn resolve_key(&self, issuer: &IssuerDid) -> std::result::Result<Ed25519PublicKey, KeyResolverError> {
        self.resolve(issuer).cloned().ok_or_else(|| KeyResolverError::MissingKey {
            issuer: issuer.as_str().to_owned(),
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

    #[must_use]
    pub const fn builder() -> IssueRequestBuilder {
        IssueRequestBuilder::new()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IssueRequestBuilder {
    signing_key: Option<Ed25519SigningKey>,
    audience: Option<AudienceDid>,
    capabilities: Option<CapabilitySet>,
    proofs: Option<ProofCollection>,
    time_bounds: Option<TokenTimeBounds>,
}

impl IssueRequestBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            signing_key: None,
            audience: None,
            capabilities: None,
            proofs: None,
            time_bounds: None,
        }
    }

    #[must_use]
    pub const fn signing_key(mut self, signing_key: Ed25519SigningKey) -> Self {
        self.signing_key = Some(signing_key);
        self
    }

    #[must_use]
    pub fn audience(mut self, audience: AudienceDid) -> Self {
        self.audience = Some(audience);
        self
    }

    #[must_use]
    pub fn capabilities(mut self, capabilities: CapabilitySet) -> Self {
        self.capabilities = Some(capabilities);
        self
    }

    #[must_use]
    pub fn proofs(mut self, proofs: ProofCollection) -> Self {
        self.proofs = Some(proofs);
        self
    }

    #[must_use]
    pub const fn time_bounds(mut self, time_bounds: TokenTimeBounds) -> Self {
        self.time_bounds = Some(time_bounds);
        self
    }

    /// Finalize the request.
    ///
    /// # Errors
    ///
    /// Returns [`BuilderError`] naming the first required field that is absent.
    pub fn build(self) -> BuilderResult<IssueRequest> {
        Ok(IssueRequest::new(
            self.signing_key.ok_or(BuilderError::MissingField { field: "signing_key" })?,
            self.audience.ok_or(BuilderError::MissingField { field: "audience" })?,
            self.capabilities.ok_or(BuilderError::MissingField { field: "capabilities" })?,
            self.proofs.ok_or(BuilderError::MissingField { field: "proofs" })?,
            self.time_bounds.ok_or(BuilderError::MissingField { field: "time_bounds" })?,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationContext {
    time: VerificationTime,
    keys: KeyResolutionContext,
    proofs: ProofCollection,
    limits: VerificationLimits,
}

impl VerificationContext {
    #[must_use]
    pub fn new(time: VerificationTime, keys: KeyResolutionContext, proofs: ProofCollection) -> Self {
        Self::with_limits(time, keys, proofs, VerificationLimits::default())
    }

    #[must_use]
    pub const fn with_limits(
        time: VerificationTime,
        keys: KeyResolutionContext,
        proofs: ProofCollection,
        limits: VerificationLimits,
    ) -> Self {
        Self {
            time,
            keys,
            proofs,
            limits,
        }
    }

    #[must_use]
    pub const fn time(&self) -> VerificationTime {
        self.time
    }

    #[must_use]
    pub const fn keys(&self) -> &KeyResolutionContext {
        &self.keys
    }

    #[must_use]
    pub const fn proofs(&self) -> &ProofCollection {
        &self.proofs
    }

    #[must_use]
    pub const fn limits(&self) -> VerificationLimits {
        self.limits
    }

    #[must_use]
    pub const fn builder() -> VerificationContextBuilder {
        VerificationContextBuilder::new()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerificationContextBuilder {
    time: Option<VerificationTime>,
    keys: Option<KeyResolutionContext>,
    proofs: Option<ProofCollection>,
    limits: Option<VerificationLimits>,
}

impl VerificationContextBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            time: None,
            keys: None,
            proofs: None,
            limits: None,
        }
    }

    #[must_use]
    pub const fn time(mut self, time: VerificationTime) -> Self {
        self.time = Some(time);
        self
    }

    #[must_use]
    pub fn keys(mut self, keys: KeyResolutionContext) -> Self {
        self.keys = Some(keys);
        self
    }

    #[must_use]
    pub fn proofs(mut self, proofs: ProofCollection) -> Self {
        self.proofs = Some(proofs);
        self
    }

    #[must_use]
    pub const fn limits(mut self, limits: VerificationLimits) -> Self {
        self.limits = Some(limits);
        self
    }

    /// Finalize the verification context.
    ///
    /// # Errors
    ///
    /// Returns [`BuilderError`] naming the first required field that is absent.
    pub fn build(self) -> BuilderResult<VerificationContext> {
        Ok(VerificationContext::with_limits(
            self.time.ok_or(BuilderError::MissingField { field: "time" })?,
            self.keys.ok_or(BuilderError::MissingField { field: "keys" })?,
            self.proofs.ok_or(BuilderError::MissingField { field: "proofs" })?,
            self.limits.unwrap_or_default(),
        ))
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

    /// Authorize a concrete resource/ability pair against this token's effective delegation.
    #[must_use]
    pub fn authorize(&self, resource: &str, ability: &str) -> AuthorizationDecision {
        match AuthorizationRequest::new(resource.to_owned(), ability.to_owned()) {
            Ok(request) => self.authorize_request(&request),
            Err(error) => AuthorizationDecision::Denied {
                reason: AuthorizationDenialReason::MalformedRequest {
                    message: error.to_string(),
                },
            },
        }
    }

    /// Authorize a concrete resource/ability pair through explicit caveat policies.
    #[must_use]
    pub fn authorize_with_policies(
        &self,
        resource: &str,
        ability: &str,
        policies: &dyn CaveatPolicySet,
    ) -> AuthorizationDecision {
        match AuthorizationRequest::new(resource.to_owned(), ability.to_owned()) {
            Ok(request) => self.authorize_request_with_policies(&request, policies),
            Err(error) => AuthorizationDecision::Denied {
                reason: AuthorizationDenialReason::MalformedRequest {
                    message: error.to_string(),
                },
            },
        }
    }

    /// Authorize a prevalidated concrete request against this token's effective delegation.
    #[must_use]
    pub fn authorize_request(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        self.authorize_request_with_policies(request, &DenyUnknownCaveats)
    }

    /// Authorize a prevalidated concrete request through explicit caveat policies.
    #[must_use]
    pub fn authorize_request_with_policies(
        &self,
        request: &AuthorizationRequest,
        policies: &dyn CaveatPolicySet,
    ) -> AuthorizationDecision {
        for capability in self.effective_delegation().capabilities().as_slice() {
            let parent = match VerifiedCapability::from_document(capability.clone()) {
                Ok(parent) => parent,
                Err(error) => {
                    return AuthorizationDecision::Denied {
                        reason: AuthorizationDenialReason::MalformedRequest {
                            message: error.to_string(),
                        },
                    };
                }
            };
            let requested = match VerifiedCapability::from_document(request.capability().clone()) {
                Ok(requested) => requested,
                Err(error) => {
                    return AuthorizationDecision::Denied {
                        reason: AuthorizationDenialReason::MalformedRequest {
                            message: error.to_string(),
                        },
                    };
                }
            };
            if parent.contains(&requested) {
                if let Some(reason) = evaluate_capability_caveats(capability, request, policies) {
                    return AuthorizationDecision::Denied { reason };
                }
                return AuthorizationDecision::Allowed {
                    matched_capability: capability.clone(),
                };
            }
        }
        AuthorizationDecision::Denied {
            reason: AuthorizationDenialReason::NoMatchingCapability,
        }
    }
}

fn evaluate_capability_caveats(
    capability: &CapabilityDocument,
    request: &AuthorizationRequest,
    policies: &dyn CaveatPolicySet,
) -> Option<AuthorizationDenialReason> {
    for caveat in capability.caveats.as_slice() {
        let identifier = CaveatIdentifier::from(caveat);
        let Some(policy) = policies.policy_for(&identifier) else {
            return Some(AuthorizationDenialReason::CaveatPolicyMissing { caveat: identifier });
        };
        match policy.evaluate(caveat, request) {
            CaveatDecision::Satisfied => {}
            CaveatDecision::Rejected { message } => {
                return Some(AuthorizationDenialReason::CaveatRejected {
                    caveat: identifier,
                    message,
                });
            }
        }
    }
    None
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
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "cav")]
    caveats: Vec<EncodedCaveat<'a>>,
}

#[derive(Debug, Clone, Serialize)]
struct EncodedCaveat<'a> {
    domain: &'a str,
    #[serde(rename = "type")]
    caveat_type: &'a str,
    key: &'a str,
    payload: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct DecodedCapability {
    #[serde(default, rename = "with")]
    resource: Option<String>,
    #[serde(default, rename = "can")]
    ability: Option<String>,
    #[serde(default, rename = "cav")]
    caveats: Vec<DecodedCaveat>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct DecodedCaveat {
    #[serde(default)]
    domain: Option<String>,
    #[serde(default, rename = "type")]
    caveat_type: Option<String>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    payload: Option<String>,
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

/// Issue and sign a compact UCAN token with the compatibility signing-key request.
///
/// # Errors
///
/// Returns [`TokenError`] when signing, DID derivation, JSON encoding, or
/// structural validation fails.
pub fn issue_token(request: &IssueRequest) -> TokenResult<CompactToken> {
    let signer = Ed25519InMemorySigner::from_signing_key(request.signing_key.clone());
    issue_token_with_signer(&signer, &request.audience, &request.capabilities, &request.proofs, request.time_bounds)
}

/// Issue and sign a compact UCAN token through a signer abstraction.
///
/// # Errors
///
/// Returns [`TokenError`] when the signer reports unsupported identity,
/// refuses to sign, returns malformed signature output, or when token encoding
/// or structural validation fails.
pub fn issue_token_with_signer<S>(
    signer: &S,
    audience: &AudienceDid,
    capabilities: &CapabilitySet,
    proofs: &ProofCollection,
    time_bounds: TokenTimeBounds,
) -> TokenResult<CompactToken>
where
    S: TokenSigner + ?Sized,
{
    let issuer = validate_signer_identity(signer)?;
    let input = IssueClaimsInput {
        issuer: &issuer,
        audience,
        capabilities,
        proofs,
        time_bounds,
    };
    issue_compact_token_with_signer(signer, &input)
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
    verify_token_signature_with_resolver(token, keys)
}

/// Verify the signature on a structurally valid token through an explicit key resolver.
///
/// # Errors
///
/// Returns [`TokenError`] when key resolution fails or the signature is invalid.
pub fn verify_token_signature_with_resolver<R>(
    token: StructurallyValidToken,
    resolver: &R,
) -> TokenResult<SignatureVerifiedToken>
where
    R: KeyResolver + ?Sized,
{
    let issuer = IssuerDid::new(token.claims.issuer_did().to_owned())?;
    let public_key = resolver.resolve_key(&issuer).map_err(|source| match source {
        KeyResolverError::MissingKey { issuer } => TokenError::MissingVerificationKey { issuer },
        source @ KeyResolverError::Backend { .. } => TokenError::KeyResolver { source },
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
    verify_compact_token_with_resolvers(token, context.time, &context.keys, &context.proofs, context.limits)
}

/// Verify a serialized compact token string with size limits applied before parsing.
///
/// # Errors
///
/// Returns [`TokenError`] when size limits, parsing, structural validation,
/// signature validation, temporal validation, or proof-chain validation fails.
pub fn verify_compact_token_str(token: &str, context: &VerificationContext) -> TokenResult<VerifiedToken> {
    enforce_compact_token_size(token, context.limits)?;
    let token = CompactToken::new(token.to_owned())?;
    verify_compact_token(&token, context)
}

/// Verify a compact token through explicit shell-owned resolver and proof-store abstractions.
///
/// # Errors
///
/// Returns [`TokenError`] when size limits, parsing, structural validation,
/// signature validation, temporal validation, proof-store lookup, or proof-chain
/// validation fails.
pub fn verify_compact_token_with_resolvers<R, S>(
    token: &CompactToken,
    time: VerificationTime,
    key_resolver: &R,
    proof_store: &S,
    limits: VerificationLimits,
) -> TokenResult<VerifiedToken>
where
    R: KeyResolver + ?Sized,
    S: ProofStore + ?Sized,
{
    verify_compact_token_with_resolvers_and_revocations(token, time, key_resolver, proof_store, &NoRevocations, limits)
}

/// Verify a compact token with explicit resolver, proof-store, and revocation checker abstractions.
///
/// # Errors
///
/// Returns [`TokenError`] when revocation, size limits, parsing, structural validation,
/// signature validation, proof-store lookup, or proof-chain validation fails.
pub fn verify_compact_token_with_resolvers_and_revocations<R, S, V>(
    token: &CompactToken,
    time: VerificationTime,
    key_resolver: &R,
    proof_store: &S,
    revocations: &V,
    limits: VerificationLimits,
) -> TokenResult<VerifiedToken>
where
    R: KeyResolver + ?Sized,
    S: ProofStore + ?Sized,
    V: RevocationChecker + ?Sized,
{
    let mut traversal = VerificationTraversal::default();
    verify_compact_token_with_traversal(token, time, key_resolver, proof_store, revocations, limits, &mut traversal, 0)
}

fn verify_compact_token_with_traversal<R, S, V>(
    token: &CompactToken,
    time: VerificationTime,
    key_resolver: &R,
    proof_store: &S,
    revocations: &V,
    limits: VerificationLimits,
    traversal: &mut VerificationTraversal,
    depth: usize,
) -> TokenResult<VerifiedToken>
where
    R: KeyResolver + ?Sized,
    S: ProofStore + ?Sized,
    V: RevocationChecker + ?Sized,
{
    enforce_proof_depth(depth, limits)?;
    enforce_compact_token_size(token.as_str(), limits)?;
    reject_revoked_token(token, revocations)?;
    reject_cycle(token, traversal.trail.as_slice())?;
    traversal.trail.push(proof_reference_for_token(token));
    let decoded = parse_compact_token(token)?;
    let valid = validate_decoded_token(decoded)?;
    let signed = verify_token_signature_with_resolver(valid, key_resolver)?;
    let verified =
        authorize_signed_token(signed, time, key_resolver, proof_store, revocations, limits, traversal, depth)?;
    let _removed = traversal.trail.pop();
    Ok(verified)
}

fn authorize_signed_token<R, S, V>(
    signed: SignatureVerifiedToken,
    time: VerificationTime,
    key_resolver: &R,
    proof_store: &S,
    revocations: &V,
    limits: VerificationLimits,
    traversal: &mut VerificationTraversal,
    depth: usize,
) -> TokenResult<VerifiedToken>
where
    R: KeyResolver + ?Sized,
    S: ProofStore + ?Sized,
    V: RevocationChecker + ?Sized,
{
    let token = signed.token;
    validate_envelope_for_token(&token, time)?;
    let issuer = IssuerDid::new(token.claims.issuer_did().to_owned())?;
    let audience = AudienceDid::new(token.claims.audience_did().to_owned())?;
    let capabilities = claims_capability_set(&token.claims)?;
    let time_bounds = claims_time_bounds(&token.claims)?;
    let proofs = direct_proofs(&token, proof_store, limits, traversal)?;
    let effective = effective_delegation(
        &issuer,
        &capabilities,
        time_bounds,
        &proofs,
        time,
        key_resolver,
        proof_store,
        revocations,
        limits,
        traversal,
        depth,
    )?;
    Ok(VerifiedToken {
        issuer,
        audience,
        capabilities,
        proofs,
        effective,
    })
}

#[allow(clippy::too_many_arguments)]
fn effective_delegation<R, S, V>(
    child_issuer: &IssuerDid,
    capabilities: &CapabilitySet,
    time_bounds: TokenTimeBounds,
    proofs: &ProofCollection,
    time: VerificationTime,
    key_resolver: &R,
    proof_store: &S,
    revocations: &V,
    limits: VerificationLimits,
    traversal: &mut VerificationTraversal,
    depth: usize,
) -> TokenResult<EffectiveDelegation>
where
    R: KeyResolver + ?Sized,
    S: ProofStore + ?Sized,
    V: RevocationChecker + ?Sized,
{
    if proofs.as_slice().is_empty() {
        return Ok(EffectiveDelegation {
            capabilities: capabilities.clone(),
            time_bounds,
        });
    }
    let parent_tokens =
        verify_parent_tokens(proofs, time, key_resolver, proof_store, revocations, limits, traversal, depth + 1)?;
    verify_child_is_linked_to_parent_audience(child_issuer, &parent_tokens)?;
    let effective_time = verify_temporal_attenuation(time_bounds, parent_tokens.as_slice())?;
    let effective_capabilities = verify_capability_attenuation(capabilities, parent_tokens.as_slice())?;
    Ok(EffectiveDelegation {
        capabilities: effective_capabilities,
        time_bounds: effective_time,
    })
}

fn verify_parent_tokens<R, S, V>(
    proofs: &ProofCollection,
    time: VerificationTime,
    key_resolver: &R,
    proof_store: &S,
    revocations: &V,
    limits: VerificationLimits,
    traversal: &mut VerificationTraversal,
    depth: usize,
) -> TokenResult<Vec<VerifiedToken>>
where
    R: KeyResolver + ?Sized,
    S: ProofStore + ?Sized,
    V: RevocationChecker + ?Sized,
{
    let mut parents = Vec::with_capacity(proofs.as_slice().len());
    for proof in proofs.as_slice() {
        let parent = verify_compact_token_with_traversal(
            proof,
            time,
            key_resolver,
            proof_store,
            revocations,
            limits,
            traversal,
            depth,
        )?;
        parents.push(parent);
    }
    Ok(parents)
}

fn verify_child_is_linked_to_parent_audience(child_issuer: &IssuerDid, parents: &[VerifiedToken]) -> TokenResult<()> {
    for parent in parents {
        if !proof_link_is_valid(parent.audience().as_str(), child_issuer.as_str()) {
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
    let child_verified = VerifiedCapability::from_document(child.clone())?;
    for parent in parents {
        let parent_verified = VerifiedCapability::from_document(parent.clone())?;
        if parent_verified.contains(&child_verified) && parent_caveats_are_preserved(parent, child) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn parent_caveats_are_preserved(parent: &CapabilityDocument, child: &CapabilityDocument) -> bool {
    parent.caveats.iter().all(|parent_caveat| {
        child.caveats.iter().any(|child_caveat| {
            child_caveat.domain == parent_caveat.domain
                && child_caveat.caveat_type == parent_caveat.caveat_type
                && child_caveat.key == parent_caveat.key
                && child_caveat.payload() == parent_caveat.payload()
        })
    })
}

fn parent_effective_capabilities(parents: &[VerifiedToken]) -> Vec<CapabilityDocument> {
    parents
        .iter()
        .flat_map(|parent| parent.effective_delegation().capabilities().as_slice().iter().cloned())
        .collect()
}

fn direct_proofs<S>(
    token: &StructurallyValidToken,
    proof_store: &S,
    limits: VerificationLimits,
    traversal: &mut VerificationTraversal,
) -> TokenResult<ProofCollection>
where
    S: ProofStore + ?Sized,
{
    let mut proofs = Vec::with_capacity(token.claims.proofs().len());
    for reference in token.claims.proofs() {
        traversal.resolve_one_proof(limits)?;
        let reference = ProofReference::new(reference.as_bytes().to_vec());
        let proof = proof_store.resolve_proof(&reference).map_err(|source| TokenError::ProofStore { source })?;
        enforce_compact_token_size(proof.as_str(), limits)?;
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
        .map(|capability| {
            let caveats = capability
                .caveats()
                .iter()
                .map(|caveat| {
                    CaveatDocument::new(
                        caveat.domain().to_owned(),
                        caveat.caveat_type().to_owned(),
                        caveat.key().to_owned(),
                        caveat.payload().to_vec(),
                    )
                })
                .collect::<crate::Result<Vec<_>>>()?;
            CapabilityDocument::with_caveats(capability.resource().to_owned(), capability.ability().to_owned(), caveats)
        })
        .collect::<crate::Result<Vec<_>>>()
        .map_err(|error| TokenError::Capability {
            message: error.to_string(),
        })
}

const fn claims_time_bounds(claims: &ucan_core::token::Claims) -> TokenResult<TokenTimeBounds> {
    TokenTimeBounds::new(claims.time_bounds().not_before_seconds(), claims.time_bounds().expires_at_seconds())
}

#[derive(Debug, Default)]
struct VerificationTraversal {
    trail: Vec<ProofReference>,
    resolved_proofs: usize,
}

impl VerificationTraversal {
    const fn resolve_one_proof(&mut self, limits: VerificationLimits) -> TokenResult<()> {
        let next_count = self.resolved_proofs.saturating_add(1);
        if next_count > limits.max_proof_count() {
            return Err(TokenError::LimitExceeded {
                source: VerificationLimitError::ProofCountExceeded {
                    count: next_count,
                    max_count: limits.max_proof_count(),
                },
            });
        }
        self.resolved_proofs = next_count;
        Ok(())
    }
}

const fn enforce_proof_depth(depth: usize, limits: VerificationLimits) -> TokenResult<()> {
    if depth > limits.max_proof_depth() {
        return Err(TokenError::LimitExceeded {
            source: VerificationLimitError::ProofDepthExceeded {
                depth,
                max_depth: limits.max_proof_depth(),
            },
        });
    }
    Ok(())
}

const fn enforce_compact_token_size(token: &str, limits: VerificationLimits) -> TokenResult<()> {
    let byte_len = token.len();
    if byte_len > limits.max_compact_token_bytes() {
        return Err(TokenError::LimitExceeded {
            source: VerificationLimitError::CompactTokenTooLarge {
                byte_len,
                max_byte_len: limits.max_compact_token_bytes(),
            },
        });
    }
    Ok(())
}

fn reject_revoked_token<V>(token: &CompactToken, revocations: &V) -> TokenResult<()>
where V: RevocationChecker + ?Sized {
    let reference = proof_reference_for_token(token);
    if revocations.is_revoked(&reference).map_err(|source| TokenError::Revocation { source })? {
        return Err(TokenError::Revoked { reference });
    }
    Ok(())
}

fn reject_cycle(token: &CompactToken, trail: &[ProofReference]) -> TokenResult<()> {
    let current = proof_reference_for_token(token);
    if trail.iter().any(|reference| reference == &current) {
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

struct IssueClaimsInput<'a> {
    issuer: &'a IssuerDid,
    audience: &'a AudienceDid,
    capabilities: &'a CapabilitySet,
    proofs: &'a ProofCollection,
    time_bounds: TokenTimeBounds,
}

fn issue_compact_token_with_signer<S>(signer: &S, input: &IssueClaimsInput<'_>) -> TokenResult<CompactToken>
where S: TokenSigner + ?Sized {
    let proof_references = encode_proof_references(input.proofs.as_slice());
    let header = EncodedHeader {
        alg: TOKEN_ALGORITHM_EDDSA,
        typ: TOKEN_TYPE_JWT,
    };
    let claims = encoded_claims(input);
    let encoded_header = encode_json_part(&header)?;
    let encoded_payload = encode_json_part(&claims)?;
    let signing_input = signing_input(&encoded_header, &encoded_payload);
    let signature = signer.sign(signing_input.as_bytes())?;
    validate_signer_signature(&signature)?;
    let encoded_signature = URL_SAFE_NO_PAD.encode(signature.as_bytes());
    let token = join_compact_parts(&encoded_header, &encoded_payload, &encoded_signature);
    let token = CompactToken::new(token)?;
    assert_issued_token_is_structurally_valid(&token, proof_references.as_slice())?;
    Ok(token)
}

fn validate_signer_identity<S>(signer: &S) -> TokenResult<IssuerDid>
where S: TokenSigner + ?Sized {
    validate_signer_algorithm(signer.algorithm())?;
    let issuer = signer.issuer()?;
    let public_key_issuer = signer.public_key()?.issuer()?;
    if issuer != public_key_issuer {
        return Err(SignerError::IssuerPublicKeyMismatch {
            issuer: issuer.as_str().to_owned(),
            public_key_issuer: public_key_issuer.as_str().to_owned(),
        }
        .into());
    }
    Ok(issuer)
}

fn validate_signer_algorithm(algorithm: &str) -> SignerResult<()> {
    if algorithm == TOKEN_ALGORITHM_EDDSA {
        return Ok(());
    }
    Err(SignerError::UnsupportedAlgorithm {
        algorithm: algorithm.to_owned(),
    })
}

const fn validate_signer_signature(signature: &SignerSignature) -> SignerResult<()> {
    let actual = signature.as_bytes().len();
    if actual == ED25519_SIGNATURE_BYTES {
        return Ok(());
    }
    Err(SignerError::InvalidSignatureLength {
        actual,
        expected: ED25519_SIGNATURE_BYTES,
    })
}

fn encoded_claims<'a>(input: &'a IssueClaimsInput<'a>) -> EncodedClaims<'a> {
    EncodedClaims {
        iss: input.issuer.as_str(),
        aud: input.audience.as_str(),
        att: input
            .capabilities
            .as_slice()
            .iter()
            .map(|capability| EncodedCapability {
                resource: capability.resource.as_str(),
                ability: capability.ability.as_str(),
                caveats: capability
                    .caveats
                    .iter()
                    .map(|caveat| EncodedCaveat {
                        domain: caveat.domain.as_str(),
                        caveat_type: caveat.caveat_type.as_str(),
                        key: caveat.key.as_str(),
                        payload: URL_SAFE_NO_PAD.encode(caveat.payload.as_slice()),
                    })
                    .collect(),
            })
            .collect(),
        prf: encode_proof_references(input.proofs.as_slice())
            .into_iter()
            .map(|reference| URL_SAFE_NO_PAD.encode(reference))
            .collect(),
        exp: input.time_bounds.expires_at_seconds(),
        nbf: input.time_bounds.not_before_seconds(),
    }
}

fn encode_proof_references(proofs: &[CompactToken]) -> Vec<Vec<u8>> {
    proofs.iter().map(|proof| proof_reference_for_token(proof).as_bytes().to_vec()).collect()
}

#[must_use]
pub fn proof_reference(token: &CompactToken) -> ProofReference {
    proof_reference_for_token(token)
}

fn proof_reference_for_token(token: &CompactToken) -> ProofReference {
    let digest = blake3::hash(token.as_str().as_bytes());
    let bytes = digest.as_bytes();
    debug_assert_eq!(bytes.len(), PROOF_REFERENCE_DIGEST_LEN);
    ProofReference::new(bytes.to_vec())
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
        let caveats = decoded_caveat_inputs(capability)?;
        inputs.push(ucan_core::token::CapabilityInput::with_caveats(resource, ability, Box::leak(caveats)));
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

fn decoded_caveat_inputs(capability: &DecodedCapability) -> TokenResult<Box<[ucan_core::token::CaveatInput<'_>]>> {
    let mut inputs = Vec::with_capacity(capability.caveats.len());
    for caveat in &capability.caveats {
        let domain = caveat.domain.as_deref().ok_or_else(|| TokenError::Capability {
            message: "caveat is missing domain".to_owned(),
        })?;
        let caveat_type = caveat.caveat_type.as_deref().ok_or_else(|| TokenError::Capability {
            message: "caveat is missing type".to_owned(),
        })?;
        let key = caveat.key.as_deref().ok_or_else(|| TokenError::Capability {
            message: "caveat is missing key".to_owned(),
        })?;
        let payload = caveat.payload.as_deref().ok_or_else(|| TokenError::Capability {
            message: "caveat is missing payload".to_owned(),
        })?;
        let payload = decode_part(payload, CompactPart::Payload)?;
        inputs.push(ucan_core::token::CaveatInput::new(domain, caveat_type, key, payload.leak()));
    }
    Ok(inputs.into_boxed_slice())
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
            let caveats: Vec<ucan_core::token::CaveatInput<'_>> = capability
                .caveats
                .iter()
                .map(|caveat| {
                    ucan_core::token::CaveatInput::new(
                        caveat.domain.as_str(),
                        caveat.caveat_type.as_str(),
                        caveat.key.as_str(),
                        caveat.payload.as_slice(),
                    )
                })
                .collect();
            ucan_core::token::CapabilityInput::with_caveats(
                capability.resource.as_str(),
                capability.ability.as_str(),
                caveats.leak(),
            )
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
    use super::AuthorizationDecision;
    use super::AuthorizationDenialReason;
    use super::AuthorizationRequest;
    use super::BuilderError;
    use super::CapabilitySet;
    use super::CaveatDecision;
    use super::CaveatIdentifier;
    use super::CaveatPolicy;
    use super::CaveatPolicySet;
    use super::CompactToken;
    use super::Ed25519InMemorySigner;
    use super::Ed25519PublicKey;
    use super::Ed25519SigningKey;
    use super::Ed25519VerificationKey;
    use super::EffectiveDelegation;
    use super::InvocationDenialReason;
    use super::InvocationRequest;
    use super::InvocationResult;
    use super::IssueRequest;
    use super::IssuerDid;
    use super::KeyResolutionContext;
    use super::KeyResolver;
    use super::KeyResolverError;
    use super::NoRevocations;
    use super::ProofCollection;
    use super::ProofReference;
    use super::ProofStore;
    use super::ProofStoreError;
    use super::RevocationChecker;
    use super::RevocationError;
    use super::RevocationList;
    use super::SignerError;
    use super::SignerResult;
    use super::SignerSignature;
    use super::TimeConversionError;
    use super::TokenError;
    use super::TokenResult;
    use super::TokenSigner;
    use super::TokenTimeBounds;
    use super::VerificationContext;
    use super::VerificationLimitError;
    use super::VerificationLimits;
    use super::VerificationTime;
    use super::VerifiedToken;
    use super::issue_token;
    use super::issue_token_with_signer;
    use super::parse_compact_token;
    use super::proof_reference;
    use super::validate_decoded_token;
    use super::verify_compact_token;
    use crate::shell::CapabilityDocument;
    use crate::shell::CaveatDocument;

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
    const SHORT_SIGNATURE_LEN: usize = 1;
    const REDACTION_TEST_SECRET_BYTE: u8 = 0xAA;
    const REDACTION_TEST_SECRET_DECIMAL: &str = "170";
    const REDACTION_TEST_SECRET_HEX_LOWER: &str = "aa";
    const REDACTION_TEST_DIRECT_ARRAY_PREFIX: &str = "[170, 170";
    const UNSUPPORTED_TEST_ALGORITHM: &str = "ES256";

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
    fn public_string_wrappers_parse_display_and_serde_round_trip() {
        let issuer = signing_key(ISSUER_SECRET_BYTE).issuer().expect("issuer should derive");
        let audience = AudienceDid::from(issuer.clone());
        let token = CompactToken::new("header.payload.signature").expect("compact wrapper accepts trimmed strings");

        assert_eq!(issuer.to_string().parse::<IssuerDid>().expect("issuer FromStr"), issuer);
        assert_eq!(IssuerDid::try_from(issuer.as_str()).expect("issuer TryFrom<&str>"), issuer);
        assert_eq!(IssuerDid::try_from(issuer.as_str().to_owned()).expect("issuer TryFrom<String>"), issuer);
        assert_eq!(audience.to_string().parse::<AudienceDid>().expect("audience FromStr"), audience);
        assert_eq!(AudienceDid::try_from(audience.as_str()).expect("audience TryFrom<&str>"), audience);
        assert_eq!(AudienceDid::try_from(audience.as_str().to_owned()).expect("audience TryFrom<String>"), audience);
        assert_eq!(token.to_string().parse::<CompactToken>().expect("compact FromStr"), token);
        assert_eq!(CompactToken::try_from(token.as_str()).expect("compact TryFrom<&str>"), token);
        assert_eq!(CompactToken::try_from(token.as_str().to_owned()).expect("compact TryFrom<String>"), token);

        let serialized_issuer = serde_json::to_string(&issuer).expect("issuer serializes");
        let serialized_audience = serde_json::to_string(&audience).expect("audience serializes");
        let serialized_token = serde_json::to_string(&token).expect("token serializes");
        assert_eq!(serialized_issuer, format!("\"{}\"", issuer.as_str()));
        assert_eq!(serialized_audience, format!("\"{}\"", audience.as_str()));
        assert_eq!(serialized_token, "\"header.payload.signature\"");
        assert_eq!(serde_json::from_str::<IssuerDid>(&serialized_issuer).expect("issuer deserializes"), issuer);
        assert_eq!(serde_json::from_str::<AudienceDid>(&serialized_audience).expect("audience deserializes"), audience);
        assert_eq!(serde_json::from_str::<CompactToken>(&serialized_token).expect("token deserializes"), token);
    }

    #[test]
    fn public_string_wrappers_reject_malformed_parse_and_serde_inputs() {
        assert!(matches!("".parse::<CompactToken>(), Err(TokenError::EmptyCompactToken)));
        assert!(matches!(" token ".parse::<CompactToken>(), Err(TokenError::CompactTokenMustBeTrimmed)));
        assert!(matches!(IssuerDid::try_from(""), Err(TokenError::CoreClaims { .. })));
        assert!(matches!(AudienceDid::try_from(" did:key:z6Mkaudience "), Err(TokenError::CoreClaims { .. })));
        assert!(serde_json::from_str::<IssuerDid>("123").is_err());
        assert!(serde_json::from_str::<AudienceDid>("\"\"").is_err());
        assert!(serde_json::from_str::<CompactToken>("\" token \"").is_err());
    }

    #[test]
    fn builders_match_positional_constructors_and_report_missing_fields() {
        let issuer_key = signing_key(ISSUER_SECRET_BYTE);
        let audience =
            AudienceDid::from(signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive"));
        let capabilities = capabilities("did:key:z6Mkresource", "store/*");
        let proofs = ProofCollection::empty();
        let bounds = token_time_bounds();
        let positional_issue =
            IssueRequest::new(issuer_key.clone(), audience.clone(), capabilities.clone(), proofs.clone(), bounds);
        let built_issue = IssueRequest::builder()
            .signing_key(issuer_key.clone())
            .audience(audience)
            .capabilities(capabilities)
            .proofs(proofs.clone())
            .time_bounds(bounds)
            .build()
            .expect("issue builder should complete");
        assert_eq!(built_issue, positional_issue);
        assert_eq!(IssueRequest::builder().build(), Err(BuilderError::MissingField { field: "signing_key" }));

        let keys = KeyResolutionContext::new(vec![
            Ed25519VerificationKey::from_signing_key(&issuer_key).expect("key should derive"),
        ]);
        let time = VerificationTime::from_unix_seconds(VERIFICATION_TIME_SECONDS);
        let limits = VerificationLimits::new(2, 3, 4_096);
        let positional_context = VerificationContext::with_limits(time, keys.clone(), proofs.clone(), limits);
        let built_context = VerificationContext::builder()
            .time(time)
            .keys(keys)
            .proofs(proofs)
            .limits(limits)
            .build()
            .expect("verification builder should complete");
        assert_eq!(built_context, positional_context);
        assert_eq!(VerificationContext::builder().build(), Err(BuilderError::MissingField { field: "time" }));
    }

    #[test]
    fn system_time_and_duration_helpers_are_deterministic_and_structured() {
        let start = std::time::UNIX_EPOCH + std::time::Duration::from_secs(TOKEN_NOT_BEFORE_SECONDS);
        let verification_time = VerificationTime::try_from_system_time(start).expect("system time should convert");
        let bounds = TokenTimeBounds::from_system_time_and_duration(start, std::time::Duration::from_secs(1_000))
            .expect("duration bounds should convert");
        let direct_bounds = TokenTimeBounds::from_unix_seconds_and_duration(
            TOKEN_NOT_BEFORE_SECONDS,
            std::time::Duration::from_secs(1_000),
        )
        .expect("unix duration bounds should convert");

        assert_eq!(verification_time.as_unix_seconds(), TOKEN_NOT_BEFORE_SECONDS);
        assert_eq!(bounds.not_before_seconds(), TOKEN_NOT_BEFORE_SECONDS);
        assert_eq!(bounds.expires_at_seconds(), TOKEN_NOT_BEFORE_SECONDS + 1_000);
        assert_eq!(direct_bounds, bounds);

        let before_epoch = std::time::UNIX_EPOCH - std::time::Duration::from_secs(1);
        assert_eq!(VerificationTime::try_from_system_time(before_epoch), Err(TimeConversionError::BeforeUnixEpoch));
        assert_eq!(
            TokenTimeBounds::from_unix_seconds_and_duration(u64::MAX, std::time::Duration::from_secs(1)),
            Err(TimeConversionError::DurationOverflow)
        );
        assert!(matches!(
            TokenTimeBounds::from_unix_seconds_and_duration(TOKEN_NOT_BEFORE_SECONDS, std::time::Duration::ZERO),
            Err(TimeConversionError::InvalidBounds { .. })
        ));
    }

    #[test]
    fn ergonomics_work_does_not_add_cleartext_secret_exports() {
        let source = include_str!("token.rs");
        let forbidden = [
            format!("{}{}", "impl fmt::Display for ", "Ed25519SigningKey"),
            format!("{}{}", "impl Serialize for ", "Ed25519SigningKey"),
            format!("{}{}", "impl<'de> Deserialize<'de> for ", "Ed25519SigningKey"),
            format!("{}{}", "impl fmt::Display for ", "Ed25519InMemorySigner"),
            format!("{}{}", "impl Serialize for ", "Ed25519InMemorySigner"),
            format!("{}{}", "impl<'de> Deserialize<'de> for ", "Ed25519InMemorySigner"),
        ];
        for forbidden_impl in forbidden {
            assert!(
                !source.contains(forbidden_impl.as_str()),
                "forbidden cleartext trait implementation appeared: {forbidden_impl}"
            );
        }
        let key = signing_key(REDACTION_TEST_SECRET_BYTE);
        assert_secret_material_is_absent(format!("{key:?}").as_str());
        assert_secret_material_is_absent(format!("{:?}", Ed25519InMemorySigner::from_signing_key(key)).as_str());
    }

    #[test]
    fn verified_token_authorizes_exact_concrete_request() {
        let issuer_key = signing_key(ISSUER_SECRET_BYTE);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let token = issue_token(&issue_request_with_capability(
            &issuer_key,
            AudienceDid::from(audience),
            ProofCollection::empty(),
            "did:key:z6Mkresource/photos",
            "store/add",
        ))
        .expect("token should issue");
        let context = verification_context(vec![&issuer_key], ProofCollection::empty(), VERIFICATION_TIME_SECONDS);
        let verified = verify_compact_token(&token, &context).expect("issued token should verify");
        let request = AuthorizationRequest::new("did:key:z6Mkresource/photos", "store/add")
            .expect("concrete request should validate");

        let decision = verified.authorize_request(&request);

        assert_allowed_capability(&decision, "did:key:z6Mkresource/photos", "store/add");
    }

    #[test]
    fn verified_token_authorizes_delegated_wildcard_and_narrower_resource() {
        let issuer_key = signing_key(ISSUER_SECRET_BYTE);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let token = issue_token(&issue_request(&issuer_key, AudienceDid::from(audience), ProofCollection::empty()))
            .expect("token should issue");
        let context = verification_context(vec![&issuer_key], ProofCollection::empty(), VERIFICATION_TIME_SECONDS);
        let verified = verify_compact_token(&token, &context).expect("issued token should verify");
        let request = AuthorizationRequest::new("did:key:z6Mkresource/photos", "store/add")
            .expect("concrete request should validate");

        let decision = verified.authorize_request(&request);

        assert_allowed_capability(&decision, "did:key:z6Mkresource", "store/*");
    }

    #[test]
    fn verified_token_authorizes_satisfied_caveat_policy() {
        let issuer_key = signing_key(ISSUER_SECRET_BYTE);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let token = issue_token(&issue_request_with_caveat(
            &issuer_key,
            AudienceDid::from(audience),
            ProofCollection::empty(),
            caveat("time", "before", "unix", b"2000"),
        ))
        .expect("token should issue");
        let context = verification_context(vec![&issuer_key], ProofCollection::empty(), VERIFICATION_TIME_SECONDS);
        let verified = verify_compact_token(&token, &context).expect("issued token should verify");
        let policies = SinglePolicySet::new("time", "before", "unix", AllowPolicy);

        let decision = verified.authorize_with_policies("did:key:z6Mkresource/photos", "store/add", &policies);

        assert!(decision.is_allowed());
        assert_eq!(decision.matched_capability().expect("matched").resource, "did:key:z6Mkresource");
        assert_eq!(decision.matched_capability().expect("matched").ability, "store/*");
        assert_eq!(decision.matched_capability().expect("matched").caveats.len(), 1);
    }

    #[test]
    fn verified_token_denies_unknown_or_rejected_caveats() {
        let issuer_key = signing_key(ISSUER_SECRET_BYTE);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let token = issue_token(&issue_request_with_caveat(
            &issuer_key,
            AudienceDid::from(audience),
            ProofCollection::empty(),
            caveat("time", "before", "unix", b"2000"),
        ))
        .expect("token should issue");
        let context = verification_context(vec![&issuer_key], ProofCollection::empty(), VERIFICATION_TIME_SECONDS);
        let verified = verify_compact_token(&token, &context).expect("issued token should verify");

        let unknown = verified.authorize("did:key:z6Mkresource/photos", "store/add");
        let reject = verified.authorize_with_policies(
            "did:key:z6Mkresource/photos",
            "store/add",
            &SinglePolicySet::new("time", "before", "unix", RejectPolicy),
        );

        assert!(matches!(unknown.denial_reason(), Some(AuthorizationDenialReason::CaveatPolicyMissing { .. })));
        assert!(matches!(reject.denial_reason(), Some(AuthorizationDenialReason::CaveatRejected { .. })));
    }

    #[test]
    fn invocation_allows_satisfied_caveat_and_exposes_effective_context() {
        let issuer_key = signing_key(ISSUER_SECRET_BYTE);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let token = issue_token(&issue_request_with_caveat(
            &issuer_key,
            AudienceDid::from(audience.clone()),
            ProofCollection::empty(),
            caveat("time", "before", "unix", b"2000"),
        ))
        .expect("token should issue");
        let context = verification_context(vec![&issuer_key], ProofCollection::empty(), VERIFICATION_TIME_SECONDS);
        let policies = SinglePolicySet::new("time", "before", "unix", AllowPolicy);
        let request = InvocationRequest::new(&token, &context, "did:key:z6Mkresource/photos", "store/add", &policies);

        let result = super::verify_invocation(&request);

        let InvocationResult::Allowed { invocation } = result else {
            panic!("invocation should be allowed");
        };
        assert_eq!(invocation.issuer().as_str(), issuer_key.issuer().expect("issuer").as_str());
        assert_eq!(invocation.invoker().as_str(), audience.as_str());
        assert_eq!(invocation.audience().as_str(), audience.as_str());
        assert_eq!(invocation.matched_capability().resource, "did:key:z6Mkresource");
        assert_eq!(invocation.effective_time_bounds(), token_time_bounds());
    }

    #[test]
    fn invocation_with_concrete_matched_capability_uses_verified_invocation_admission() {
        let issuer_key = signing_key(ISSUER_SECRET_BYTE);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let token = issue_token(&issue_request_with_capability(
            &issuer_key,
            AudienceDid::from(audience.clone()),
            ProofCollection::empty(),
            "did:key:z6Mkresource",
            "store/add",
        ))
        .expect("token should issue");
        let context = verification_context(vec![&issuer_key], ProofCollection::empty(), VERIFICATION_TIME_SECONDS);
        let request = InvocationRequest::new(
            &token,
            &context,
            "did:key:z6Mkresource/photos",
            "store/add",
            &super::DenyUnknownCaveats,
        );

        let result = super::verify_invocation(&request);

        let InvocationResult::Allowed { invocation } = result else {
            panic!("concrete invocation should be allowed");
        };
        assert_eq!(invocation.invoker().as_str(), audience.as_str());
        assert_eq!(invocation.matched_capability().ability, "store/add");
    }

    #[test]
    fn invocation_denies_caveat_rejection_and_verification_failure() {
        let issuer_key = signing_key(ISSUER_SECRET_BYTE);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let token = issue_token(&issue_request_with_caveat(
            &issuer_key,
            AudienceDid::from(audience),
            ProofCollection::empty(),
            caveat("time", "before", "unix", b"2000"),
        ))
        .expect("token should issue");
        let context = verification_context(vec![&issuer_key], ProofCollection::empty(), VERIFICATION_TIME_SECONDS);
        let reject_policies = SinglePolicySet::new("time", "before", "unix", RejectPolicy);
        let rejected = super::verify_invocation(&InvocationRequest::new(
            &token,
            &context,
            "did:key:z6Mkresource/photos",
            "store/add",
            &reject_policies,
        ));
        let tampered = CompactToken::new("not.enough").expect("non-empty wrapper");
        let verified_bad = super::verify_invocation(&InvocationRequest::new(
            &tampered,
            &context,
            "did:key:z6Mkresource/photos",
            "store/add",
            &reject_policies,
        ));

        assert!(matches!(rejected, InvocationResult::Denied {
            reason: InvocationDenialReason::Authorization {
                reason: AuthorizationDenialReason::CaveatRejected { .. }
            }
        }));
        assert!(matches!(verified_bad, InvocationResult::Denied {
            reason: InvocationDenialReason::Verification { .. }
        }));
    }

    #[test]
    fn verified_token_denies_unmatched_concrete_request() {
        let issuer_key = signing_key(ISSUER_SECRET_BYTE);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let token = issue_token(&issue_request(&issuer_key, AudienceDid::from(audience), ProofCollection::empty()))
            .expect("token should issue");
        let context = verification_context(vec![&issuer_key], ProofCollection::empty(), VERIFICATION_TIME_SECONDS);
        let verified = verify_compact_token(&token, &context).expect("issued token should verify");

        let decision = verified.authorize("did:key:z6Mkresource/photos", "admin/delete");

        assert_eq!(decision.denial_reason(), Some(&AuthorizationDenialReason::NoMatchingCapability));
    }

    #[test]
    fn authorization_request_rejects_malformed_ability_wildcards() {
        let embedded_error = AuthorizationRequest::new("did:key:z6Mkresource/photos", "store/a*d")
            .expect_err("embedded wildcard segment should fail core ability validation");
        let full_segment_error = AuthorizationRequest::new("did:key:z6Mkresource/photos", "store/*")
            .expect_err("operation request must be concrete");

        assert!(matches!(embedded_error, TokenError::Capability { .. }));
        assert!(matches!(full_segment_error, TokenError::Capability { .. }));

        let issuer_key = signing_key(ISSUER_SECRET_BYTE);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let token = issue_token(&issue_request(&issuer_key, AudienceDid::from(audience), ProofCollection::empty()))
            .expect("token should issue");
        let context = verification_context(vec![&issuer_key], ProofCollection::empty(), VERIFICATION_TIME_SECONDS);
        let verified = verify_compact_token(&token, &context).expect("issued token should verify");

        let embedded_decision = verified.authorize("did:key:z6Mkresource/photos", "store/a*d");
        let full_segment_decision = verified.authorize("did:key:z6Mkresource/photos", "store/*");

        assert_malformed_denial(&embedded_decision);
        assert_malformed_denial(&full_segment_decision);
    }

    #[test]
    fn verified_token_denies_broader_resource_than_child_delegation() {
        let verified = verified_child_token();

        let decision = verified.authorize("did:key:z6Mkresource", "store/add");

        assert_eq!(decision.denial_reason(), Some(&AuthorizationDenialReason::NoMatchingCapability));
    }

    #[test]
    fn authorization_uses_effective_child_delegation_not_broader_proof_capability() {
        let verified = verified_child_token();
        assert_allowed_capability(
            &verified.authorize("did:key:z6Mkresource/photos", "store/add"),
            "did:key:z6Mkresource/photos",
            "store/add",
        );

        let decision = verified.authorize("did:key:z6Mkresource", "store/add");

        assert_eq!(decision.denial_reason(), Some(&AuthorizationDenialReason::NoMatchingCapability));
    }

    #[test]
    fn authorization_uses_effective_delegation_not_direct_capability_claims() {
        let verified = VerifiedToken {
            issuer: IssuerDid::new("did:key:z6Mkissuer").expect("issuer should validate"),
            audience: AudienceDid::new("did:key:z6Mkaudience").expect("audience should validate"),
            capabilities: capabilities("did:key:z6Mkresource", "store/*"),
            proofs: ProofCollection::empty(),
            effective: EffectiveDelegation {
                capabilities: capabilities("did:key:z6Mkresource/photos", "store/add"),
                time_bounds: token_time_bounds(),
            },
        };
        assert_eq!(verified.capabilities().as_slice(), capabilities("did:key:z6Mkresource", "store/*").as_slice());

        let decision = verified.authorize("did:key:z6Mkresource", "store/add");

        assert_eq!(decision.denial_reason(), Some(&AuthorizationDenialReason::NoMatchingCapability));
        assert_allowed_capability(
            &verified.authorize("did:key:z6Mkresource/photos", "store/add"),
            "did:key:z6Mkresource/photos",
            "store/add",
        );
    }

    #[test]
    fn issued_token_uses_required_compact_shape_and_claim_names() {
        let issuer_key = signing_key(ISSUER_SECRET_BYTE);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let token = issue_token(&issue_request(&issuer_key, AudienceDid::from(audience), ProofCollection::empty()))
            .expect("token should issue");
        assert_token_shape_and_claim_names(&token);
    }

    #[test]
    fn signer_based_issue_round_trips_with_in_memory_ed25519() {
        let signer = in_memory_signer(ISSUER_SECRET_BYTE);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let capabilities = capabilities("did:key:z6Mkresource", "store/*");
        let proofs = ProofCollection::empty();
        let bounds = token_time_bounds();
        let token = issue_token_with_signer(&signer, &AudienceDid::from(audience), &capabilities, &proofs, bounds)
            .expect("signer should issue");
        let context = VerificationContext::new(
            VerificationTime::from_unix_seconds(VERIFICATION_TIME_SECONDS),
            KeyResolutionContext::new(vec![signer.verification_key().expect("verification key should derive")]),
            ProofCollection::empty(),
        );

        let verified = verify_compact_token(&token, &context).expect("signer-issued token should verify");

        assert_eq!(verified.issuer().as_str(), signer.issuer().expect("issuer should derive").as_str());
        assert_eq!(verified.capabilities().as_slice(), capabilities.as_slice());
        assert_eq!(verified.effective_delegation().time_bounds(), bounds);
    }

    #[test]
    fn signer_based_issue_preserves_compact_shape() {
        let signer = in_memory_signer(ISSUER_SECRET_BYTE);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let token = issue_token_with_signer(
            &signer,
            &AudienceDid::from(audience),
            &capabilities("did:key:z6Mkresource", "store/*"),
            &ProofCollection::empty(),
            token_time_bounds(),
        )
        .expect("signer should issue");

        assert_token_shape_and_claim_names(&token);
    }

    #[test]
    fn refusing_signer_returns_structured_error() {
        let key = signing_key(ISSUER_SECRET_BYTE);
        let signer = RefusingSigner::new(&key);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let error = issue_token_with_signer(
            &signer,
            &AudienceDid::from(audience),
            &capabilities("did:key:z6Mkresource", "store/*"),
            &ProofCollection::empty(),
            token_time_bounds(),
        )
        .expect_err("refusing signer should fail");

        assert!(matches!(error, TokenError::Signer {
            source: SignerError::Refused
        }));
    }

    #[test]
    fn signer_with_unsupported_algorithm_is_rejected() {
        let key = signing_key(ISSUER_SECRET_BYTE);
        let signer = UnsupportedAlgorithmSigner::new(&key);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let error = issue_token_with_signer(
            &signer,
            &AudienceDid::from(audience),
            &capabilities("did:key:z6Mkresource", "store/*"),
            &ProofCollection::empty(),
            token_time_bounds(),
        )
        .expect_err("unsupported algorithm should fail");

        assert!(matches!(error, TokenError::Signer {
            source: SignerError::UnsupportedAlgorithm { .. }
        }));
    }

    #[test]
    fn signer_with_wrong_signature_length_is_rejected() {
        let key = signing_key(ISSUER_SECRET_BYTE);
        let signer = FixedSignatureSigner::new(&key, SignerSignature::new(vec![0_u8; SHORT_SIGNATURE_LEN]));
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let error = issue_token_with_signer(
            &signer,
            &AudienceDid::from(audience),
            &capabilities("did:key:z6Mkresource", "store/*"),
            &ProofCollection::empty(),
            token_time_bounds(),
        )
        .expect_err("short signature should fail");

        assert_eq!(error, TokenError::Signer {
            source: SignerError::InvalidSignatureLength {
                actual: SHORT_SIGNATURE_LEN,
                expected: super::ED25519_SIGNATURE_BYTES,
            }
        });
    }

    #[test]
    fn signer_with_invalid_signature_bytes_is_rejected_by_verification() {
        let key = signing_key(ISSUER_SECRET_BYTE);
        let signer = FixedSignatureSigner::new(&key, SignerSignature::new(vec![0_u8; super::ED25519_SIGNATURE_BYTES]));
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let token = issue_token_with_signer(
            &signer,
            &AudienceDid::from(audience),
            &capabilities("did:key:z6Mkresource", "store/*"),
            &ProofCollection::empty(),
            token_time_bounds(),
        )
        .expect("fixed-length malformed signature can produce a structurally valid token");
        let context = verification_context(vec![&key], ProofCollection::empty(), VERIFICATION_TIME_SECONDS);
        let error = verify_compact_token(&token, &context).expect_err("malformed signature should fail");

        assert!(matches!(error, TokenError::Signature { .. }));
    }

    #[test]
    fn signer_with_mismatched_issuer_and_public_key_is_rejected() {
        let key = signing_key(ISSUER_SECRET_BYTE);
        let other_issuer = signing_key(OTHER_SECRET_BYTE).issuer().expect("other issuer should derive");
        let signer = MismatchedIssuerSigner::new(&key, other_issuer);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let error = issue_token_with_signer(
            &signer,
            &AudienceDid::from(audience),
            &capabilities("did:key:z6Mkresource", "store/*"),
            &ProofCollection::empty(),
            token_time_bounds(),
        )
        .expect_err("issuer mismatch should fail");

        assert!(matches!(error, TokenError::Signer {
            source: SignerError::IssuerPublicKeyMismatch { .. }
        }));
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
    fn in_memory_signer_debug_redacts_secret_bytes() {
        let signer = in_memory_signer(REDACTION_TEST_SECRET_BYTE);
        let debug_output = format!("{signer:?}");

        assert!(debug_output.contains("Ed25519InMemorySigner"));
        assert!(debug_output.contains(super::REDACTED_SECRET_MATERIAL_DEBUG));
        assert_secret_material_is_absent(debug_output.as_str());
    }

    #[test]
    fn assertion_failure_formatting_redacts_secret_bytes() {
        let redacted_key = signing_key(REDACTION_TEST_SECRET_BYTE);
        let other_signing_key = signing_key(OTHER_SECRET_BYTE);
        let key_failure = capture_assertion_failure_message(|| assert_eq!(redacted_key, other_signing_key));

        assert!(key_failure.contains("Ed25519SigningKey"));
        assert!(key_failure.contains(super::REDACTED_SECRET_MATERIAL_DEBUG));
        assert_secret_material_is_absent(key_failure.as_str());

        let redacted_signer = in_memory_signer(REDACTION_TEST_SECRET_BYTE);
        let other_signer = in_memory_signer(OTHER_SECRET_BYTE);
        let signer_failure = capture_assertion_failure_message(|| assert_eq!(redacted_signer, other_signer));

        assert!(signer_failure.contains("Ed25519InMemorySigner"));
        assert!(signer_failure.contains(super::REDACTED_SECRET_MATERIAL_DEBUG));
        assert_secret_material_is_absent(signer_failure.as_str());

        let issuer_key = signing_key(REDACTION_TEST_SECRET_BYTE);
        let other_issuer_key = signing_key(OTHER_SECRET_BYTE);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let request = issue_request(&issuer_key, AudienceDid::from(audience.clone()), ProofCollection::empty());
        let other_request = issue_request(&other_issuer_key, AudienceDid::from(audience), ProofCollection::empty());
        let request_failure = capture_assertion_failure_message(|| assert_eq!(request, other_request));

        assert!(request_failure.contains("IssueRequest"));
        assert!(request_failure.contains(super::REDACTED_SECRET_MATERIAL_DEBUG));
        assert_secret_material_is_absent(request_failure.as_str());
    }

    #[test]
    fn invalid_secret_key_errors_do_not_echo_input_bytes() {
        let malformed_key = [REDACTION_TEST_SECRET_BYTE; INVALID_KEY_LEN];
        let key_error = Ed25519SigningKey::try_from_slice(&malformed_key).expect_err("short key should fail");
        let signer_error = Ed25519InMemorySigner::try_from_slice(&malformed_key).expect_err("short signer should fail");

        assert!(matches!(key_error, TokenError::InvalidSecretKeyLength { .. }));
        assert_secret_material_is_absent(format!("{key_error}").as_str());
        assert_secret_material_is_absent(format!("{key_error:?}").as_str());

        assert!(matches!(signer_error, TokenError::InvalidSecretKeyLength { .. }));
        assert_secret_material_is_absent(format!("{signer_error}").as_str());
        assert_secret_material_is_absent(format!("{signer_error:?}").as_str());
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
    fn child_must_preserve_parent_caveat_payload_for_attenuation() {
        let parent_key = signing_key(ISSUER_SECRET_BYTE);
        let child_key = signing_key(CHILD_SECRET_BYTE);
        let child_issuer = child_key.issuer().expect("child issuer should derive");
        let parent_caveat = caveat("time", "before", "unix", b"2000");
        let parent = issue_token(&issue_request_with_caveat(
            &parent_key,
            AudienceDid::from(child_issuer),
            ProofCollection::empty(),
            parent_caveat.clone(),
        ))
        .expect("parent should issue");
        let missing_caveat_child = issue_token(&child_request(&child_key, parent.clone())).expect("child should issue");
        let narrowed_child = issue_token(&child_request_with_caveat(&child_key, parent.clone(), parent_caveat))
            .expect("child should issue");
        let context = verification_context(
            vec![&parent_key, &child_key],
            ProofCollection::from_tokens(vec![parent]),
            VERIFICATION_TIME_SECONDS,
        );

        let missing_error = verify_compact_token(&missing_caveat_child, &context)
            .expect_err("child that drops parent caveat should fail attenuation");
        let verified = verify_compact_token(&narrowed_child, &context).expect("preserved caveat should verify");

        assert!(matches!(missing_error, TokenError::Attenuation { .. }));
        assert_eq!(verified.effective_delegation().capabilities().as_slice()[0].caveats.len(), 1);
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

        assert!(matches!(error, TokenError::ProofStore {
            source: ProofStoreError::MissingProof { .. }
        }));
    }

    #[test]
    fn resolver_backend_errors_preserve_issuer_context() {
        let issuer_key = signing_key(ISSUER_SECRET_BYTE);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let token = issue_token(&issue_request(&issuer_key, AudienceDid::from(audience), ProofCollection::empty()))
            .expect("token should issue");
        let context = verification_context(vec![], ProofCollection::empty(), VERIFICATION_TIME_SECONDS);
        let resolver = BackendFailingResolver;
        let error = super::verify_compact_token_with_resolvers(
            &token,
            VerificationTime::from_unix_seconds(VERIFICATION_TIME_SECONDS),
            &resolver,
            &context.proofs,
            context.limits(),
        )
        .expect_err("resolver backend should fail");

        assert!(matches!(error, TokenError::KeyResolver {
            source: KeyResolverError::Backend { issuer, message }
        } if issuer == issuer_key.issuer().expect("issuer should derive").as_str() && message == BACKEND_FAILURE_MESSAGE));
    }

    #[test]
    fn proof_store_backend_errors_preserve_reference_context() {
        let parent_key = signing_key(ISSUER_SECRET_BYTE);
        let child_key = signing_key(CHILD_SECRET_BYTE);
        let child_issuer = child_key.issuer().expect("child issuer should derive");
        let parent =
            issue_token(&issue_request(&parent_key, AudienceDid::from(child_issuer), ProofCollection::empty()))
                .expect("parent should issue");
        let child = issue_token(&child_request(&child_key, parent)).expect("child should issue");
        let keys = KeyResolutionContext::new(
            [&parent_key, &child_key]
                .into_iter()
                .map(Ed25519VerificationKey::from_signing_key)
                .collect::<Result<Vec<_>, _>>()
                .expect("keys should derive"),
        );
        let store = BackendFailingProofStore;
        let error = super::verify_compact_token_with_resolvers(
            &child,
            VerificationTime::from_unix_seconds(VERIFICATION_TIME_SECONDS),
            &keys,
            &store,
            VerificationLimits::default(),
        )
        .expect_err("proof store backend should fail");

        assert!(matches!(error, TokenError::ProofStore {
            source: ProofStoreError::Backend { reference, message }
        } if !reference.as_bytes().is_empty() && message == BACKEND_FAILURE_MESSAGE));
    }

    #[test]
    fn no_revocations_preserves_delegation_verification() {
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
            VERIFICATION_TIME_SECONDS,
        );

        let baseline = verify_compact_token(&child, &context).expect("baseline should verify");
        let checked = super::verify_compact_token_with_resolvers_and_revocations(
            &child,
            context.time(),
            context.keys(),
            context.proofs(),
            &NoRevocations,
            context.limits(),
        )
        .expect("no-op revocation checker should preserve verification");

        assert_eq!(baseline.issuer(), checked.issuer());
        assert_eq!(baseline.audience(), checked.audience());
        assert_eq!(baseline.proofs(), checked.proofs());
        assert_eq!(baseline.effective_delegation(), checked.effective_delegation());
    }

    #[test]
    fn revocation_list_revoke_is_idempotent_through_verified_set_membership() {
        let reference = ProofReference::new(b"proof-a".to_vec());
        let mut revocations = RevocationList::empty();

        revocations.revoke(reference.clone());
        revocations.revoke(reference.clone());

        assert_eq!(revocations.as_slice(), &[reference]);
    }

    #[test]
    fn revoked_leaf_token_is_rejected() {
        let issuer_key = signing_key(ISSUER_SECRET_BYTE);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let token = issue_token(&issue_request(&issuer_key, AudienceDid::from(audience), ProofCollection::empty()))
            .expect("token should issue");
        let context = verification_context(vec![&issuer_key], ProofCollection::empty(), VERIFICATION_TIME_SECONDS);
        let revoked = RevocationList::from_references(vec![proof_reference(&token)]);

        let error = super::verify_compact_token_with_resolvers_and_revocations(
            &token,
            context.time(),
            context.keys(),
            context.proofs(),
            &revoked,
            context.limits(),
        )
        .expect_err("revoked leaf should fail");

        assert!(matches!(error, TokenError::Revoked { reference } if reference == proof_reference(&token)));
    }

    #[test]
    fn revoked_parent_token_rejects_delegated_child() {
        let parent_key = signing_key(ISSUER_SECRET_BYTE);
        let child_key = signing_key(CHILD_SECRET_BYTE);
        let child_issuer = child_key.issuer().expect("child issuer should derive");
        let parent =
            issue_token(&issue_request(&parent_key, AudienceDid::from(child_issuer), ProofCollection::empty()))
                .expect("parent should issue");
        let child = issue_token(&child_request(&child_key, parent.clone())).expect("child should issue");
        let context = verification_context(
            vec![&parent_key, &child_key],
            ProofCollection::from_tokens(vec![parent.clone()]),
            VERIFICATION_TIME_SECONDS,
        );
        let revoked = RevocationList::from_references(vec![proof_reference(&parent)]);

        let error = super::verify_compact_token_with_resolvers_and_revocations(
            &child,
            context.time(),
            context.keys(),
            context.proofs(),
            &revoked,
            context.limits(),
        )
        .expect_err("revoked parent should fail child verification");

        assert!(matches!(error, TokenError::Revoked { reference } if reference == proof_reference(&parent)));
    }

    #[test]
    fn revocation_backend_errors_fail_closed() {
        let issuer_key = signing_key(ISSUER_SECRET_BYTE);
        let audience = signing_key(AUDIENCE_SECRET_BYTE).issuer().expect("audience did should derive");
        let token = issue_token(&issue_request(&issuer_key, AudienceDid::from(audience), ProofCollection::empty()))
            .expect("token should issue");
        let context = verification_context(vec![&issuer_key], ProofCollection::empty(), VERIFICATION_TIME_SECONDS);
        let error = super::verify_compact_token_with_resolvers_and_revocations(
            &token,
            context.time(),
            context.keys(),
            context.proofs(),
            &BackendFailingRevocationChecker,
            context.limits(),
        )
        .expect_err("revocation backend failure should fail closed");

        assert!(matches!(error, TokenError::Revocation {
            source: RevocationError::Backend { reference, message }
        } if reference == proof_reference(&token) && message == BACKEND_FAILURE_MESSAGE));
    }

    #[test]
    fn verification_limits_reject_oversized_input_before_parse() {
        let context = VerificationContext::with_limits(
            VerificationTime::from_unix_seconds(VERIFICATION_TIME_SECONDS),
            KeyResolutionContext::new(Vec::new()),
            ProofCollection::empty(),
            VerificationLimits::new(1, 1, 3),
        );
        let error = super::verify_compact_token_str("not.enough.parts", &context)
            .expect_err("oversized input should fail before parse");

        assert!(matches!(error, TokenError::LimitExceeded {
            source: VerificationLimitError::CompactTokenTooLarge {
                byte_len: 16,
                max_byte_len: 3
            }
        }));
    }

    #[test]
    fn proof_depth_limit_rejects_parent_traversal() {
        let parent_key = signing_key(ISSUER_SECRET_BYTE);
        let child_key = signing_key(CHILD_SECRET_BYTE);
        let child_issuer = child_key.issuer().expect("child issuer should derive");
        let parent =
            issue_token(&issue_request(&parent_key, AudienceDid::from(child_issuer), ProofCollection::empty()))
                .expect("parent should issue");
        let child = issue_token(&child_request(&child_key, parent.clone())).expect("child should issue");
        let context = VerificationContext::with_limits(
            VerificationTime::from_unix_seconds(VERIFICATION_TIME_SECONDS),
            KeyResolutionContext::new(
                [&parent_key, &child_key]
                    .into_iter()
                    .map(Ed25519VerificationKey::from_signing_key)
                    .collect::<Result<Vec<_>, _>>()
                    .expect("keys should derive"),
            ),
            ProofCollection::from_tokens(vec![parent]),
            VerificationLimits::new(0, 1, usize::MAX),
        );
        let error = verify_compact_token(&child, &context).expect_err("depth limit should fail");

        assert!(matches!(error, TokenError::LimitExceeded {
            source: VerificationLimitError::ProofDepthExceeded { depth: 1, max_depth: 0 }
        }));
    }

    #[test]
    fn proof_count_limit_stops_before_proof_lookup() {
        let parent_key = signing_key(ISSUER_SECRET_BYTE);
        let child_key = signing_key(CHILD_SECRET_BYTE);
        let child_issuer = child_key.issuer().expect("child issuer should derive");
        let parent =
            issue_token(&issue_request(&parent_key, AudienceDid::from(child_issuer), ProofCollection::empty()))
                .expect("parent should issue");
        let child = issue_token(&child_request(&child_key, parent)).expect("child should issue");
        let keys = KeyResolutionContext::new(
            [&parent_key, &child_key]
                .into_iter()
                .map(Ed25519VerificationKey::from_signing_key)
                .collect::<Result<Vec<_>, _>>()
                .expect("keys should derive"),
        );
        let limits = VerificationLimits::new(1, 0, usize::MAX);
        let error = super::verify_compact_token_with_resolvers(
            &child,
            VerificationTime::from_unix_seconds(VERIFICATION_TIME_SECONDS),
            &keys,
            &CountingProofStore,
            limits,
        )
        .expect_err("proof count limit should fail");

        assert!(matches!(error, TokenError::LimitExceeded {
            source: VerificationLimitError::ProofCountExceeded { count: 1, max_count: 0 }
        }));
    }

    #[test]
    fn resolved_proof_size_limit_precedes_parsing() {
        let parent_key = signing_key(ISSUER_SECRET_BYTE);
        let child_key = signing_key(CHILD_SECRET_BYTE);
        let child_issuer = child_key.issuer().expect("child issuer should derive");
        let parent =
            issue_token(&issue_request(&parent_key, AudienceDid::from(child_issuer), ProofCollection::empty()))
                .expect("parent should issue");
        let child = issue_token(&child_request(&child_key, parent)).expect("child should issue");
        let keys = KeyResolutionContext::new(
            [&parent_key, &child_key]
                .into_iter()
                .map(Ed25519VerificationKey::from_signing_key)
                .collect::<Result<Vec<_>, _>>()
                .expect("keys should derive"),
        );
        let limits = VerificationLimits::new(1, 1, child.as_str().len() + 10);
        let error = super::verify_compact_token_with_resolvers(
            &child,
            VerificationTime::from_unix_seconds(VERIFICATION_TIME_SECONDS),
            &keys,
            &OversizedProofStore,
            limits,
        )
        .expect_err("oversized resolved proof should fail before parse");

        assert!(matches!(error, TokenError::LimitExceeded {
            source: VerificationLimitError::CompactTokenTooLarge { .. }
        }));
    }

    #[test]
    fn proof_store_cycle_is_rejected_by_trail_detection() {
        let parent_key = signing_key(ISSUER_SECRET_BYTE);
        let child_key = signing_key(CHILD_SECRET_BYTE);
        let child_issuer = child_key.issuer().expect("child issuer should derive");
        let parent =
            issue_token(&issue_request(&parent_key, AudienceDid::from(child_issuer), ProofCollection::empty()))
                .expect("parent should issue");
        let child = issue_token(&child_request(&child_key, parent)).expect("child should issue");
        let keys = KeyResolutionContext::new(
            [&parent_key, &child_key]
                .into_iter()
                .map(Ed25519VerificationKey::from_signing_key)
                .collect::<Result<Vec<_>, _>>()
                .expect("keys should derive"),
        );
        let store = CyclicProofStore { token: child.clone() };
        let error = super::verify_compact_token_with_resolvers(
            &child,
            VerificationTime::from_unix_seconds(VERIFICATION_TIME_SECONDS),
            &keys,
            &store,
            VerificationLimits::default(),
        )
        .expect_err("proof cycle should fail");

        assert!(matches!(error, TokenError::ProofChain { .. }));
    }

    const BACKEND_FAILURE_MESSAGE: &str = "backend unavailable";

    struct BackendFailingResolver;

    impl KeyResolver for BackendFailingResolver {
        fn resolve_key(&self, issuer: &IssuerDid) -> std::result::Result<Ed25519PublicKey, KeyResolverError> {
            Err(KeyResolverError::Backend {
                issuer: issuer.as_str().to_owned(),
                message: BACKEND_FAILURE_MESSAGE.to_owned(),
            })
        }
    }

    struct BackendFailingProofStore;

    impl ProofStore for BackendFailingProofStore {
        fn resolve_proof(&self, reference: &ProofReference) -> std::result::Result<CompactToken, ProofStoreError> {
            Err(ProofStoreError::Backend {
                reference: reference.clone(),
                message: BACKEND_FAILURE_MESSAGE.to_owned(),
            })
        }
    }

    #[derive(Default)]

    struct BackendFailingRevocationChecker;

    impl RevocationChecker for BackendFailingRevocationChecker {
        fn is_revoked(&self, reference: &ProofReference) -> std::result::Result<bool, RevocationError> {
            Err(RevocationError::Backend {
                reference: reference.clone(),
                message: BACKEND_FAILURE_MESSAGE.to_owned(),
            })
        }
    }

    struct CountingProofStore;

    impl ProofStore for CountingProofStore {
        fn resolve_proof(&self, reference: &ProofReference) -> std::result::Result<CompactToken, ProofStoreError> {
            panic!("proof store should not be called after proof-count limit for {reference}");
        }
    }

    struct OversizedProofStore;

    impl ProofStore for OversizedProofStore {
        fn resolve_proof(&self, _reference: &ProofReference) -> std::result::Result<CompactToken, ProofStoreError> {
            CompactToken::new("x".repeat(8192)).map_err(|error| ProofStoreError::Backend {
                reference: ProofReference::new(Vec::new()),
                message: error.to_string(),
            })
        }
    }

    struct AllowPolicy;

    impl CaveatPolicy for AllowPolicy {
        fn evaluate(&self, _caveat: &CaveatDocument, _request: &AuthorizationRequest) -> CaveatDecision {
            CaveatDecision::Satisfied
        }
    }

    struct RejectPolicy;

    impl CaveatPolicy for RejectPolicy {
        fn evaluate(&self, _caveat: &CaveatDocument, _request: &AuthorizationRequest) -> CaveatDecision {
            CaveatDecision::Rejected {
                message: "rejected by test policy".to_owned(),
            }
        }
    }

    struct SinglePolicySet<P> {
        identifier: CaveatIdentifier,
        policy: P,
    }

    impl<P> SinglePolicySet<P> {
        fn new(domain: &str, caveat_type: &str, key: &str, policy: P) -> Self {
            Self {
                identifier: CaveatIdentifier::new(domain, caveat_type, key).expect("identifier should validate"),
                policy,
            }
        }
    }

    impl<P: CaveatPolicy> CaveatPolicySet for SinglePolicySet<P> {
        fn policy_for(&self, caveat: &CaveatIdentifier) -> Option<&dyn CaveatPolicy> {
            if caveat == &self.identifier {
                Some(&self.policy)
            } else {
                None
            }
        }
    }

    struct CyclicProofStore {
        token: CompactToken,
    }

    impl ProofStore for CyclicProofStore {
        fn resolve_proof(&self, _reference: &ProofReference) -> std::result::Result<CompactToken, ProofStoreError> {
            Ok(self.token.clone())
        }
    }

    #[derive(Clone)]
    struct RefusingSigner {
        issuer: IssuerDid,
        public_key: Ed25519PublicKey,
    }

    impl RefusingSigner {
        fn new(signing_key: &Ed25519SigningKey) -> Self {
            Self {
                issuer: signing_key.issuer().expect("issuer should derive"),
                public_key: signing_key.public_key().expect("public key should derive"),
            }
        }
    }

    impl TokenSigner for RefusingSigner {
        fn algorithm(&self) -> &str {
            super::TOKEN_ALGORITHM_EDDSA
        }

        fn issuer(&self) -> TokenResult<IssuerDid> {
            Ok(self.issuer.clone())
        }

        fn public_key(&self) -> TokenResult<Ed25519PublicKey> {
            Ok(self.public_key.clone())
        }

        fn sign(&self, _signing_input: &[u8]) -> SignerResult<SignerSignature> {
            Err(SignerError::Refused)
        }
    }

    #[derive(Clone)]
    struct UnsupportedAlgorithmSigner {
        issuer: IssuerDid,
        public_key: Ed25519PublicKey,
    }

    impl UnsupportedAlgorithmSigner {
        fn new(signing_key: &Ed25519SigningKey) -> Self {
            Self {
                issuer: signing_key.issuer().expect("issuer should derive"),
                public_key: signing_key.public_key().expect("public key should derive"),
            }
        }
    }

    impl TokenSigner for UnsupportedAlgorithmSigner {
        fn algorithm(&self) -> &str {
            UNSUPPORTED_TEST_ALGORITHM
        }

        fn issuer(&self) -> TokenResult<IssuerDid> {
            Ok(self.issuer.clone())
        }

        fn public_key(&self) -> TokenResult<Ed25519PublicKey> {
            Ok(self.public_key.clone())
        }

        fn sign(&self, _signing_input: &[u8]) -> SignerResult<SignerSignature> {
            Ok(SignerSignature::new(vec![0_u8; super::ED25519_SIGNATURE_BYTES]))
        }
    }

    #[derive(Clone)]
    struct FixedSignatureSigner {
        issuer: IssuerDid,
        public_key: Ed25519PublicKey,
        signature: SignerSignature,
    }

    impl FixedSignatureSigner {
        fn new(signing_key: &Ed25519SigningKey, signature: SignerSignature) -> Self {
            Self {
                issuer: signing_key.issuer().expect("issuer should derive"),
                public_key: signing_key.public_key().expect("public key should derive"),
                signature,
            }
        }
    }

    impl TokenSigner for FixedSignatureSigner {
        fn algorithm(&self) -> &str {
            super::TOKEN_ALGORITHM_EDDSA
        }

        fn issuer(&self) -> TokenResult<IssuerDid> {
            Ok(self.issuer.clone())
        }

        fn public_key(&self) -> TokenResult<Ed25519PublicKey> {
            Ok(self.public_key.clone())
        }

        fn sign(&self, _signing_input: &[u8]) -> SignerResult<SignerSignature> {
            Ok(self.signature.clone())
        }
    }

    #[derive(Clone)]
    struct MismatchedIssuerSigner {
        issuer: IssuerDid,
        public_key: Ed25519PublicKey,
    }

    impl MismatchedIssuerSigner {
        fn new(signing_key: &Ed25519SigningKey, issuer: IssuerDid) -> Self {
            Self {
                issuer,
                public_key: signing_key.public_key().expect("public key should derive"),
            }
        }
    }

    impl TokenSigner for MismatchedIssuerSigner {
        fn algorithm(&self) -> &str {
            super::TOKEN_ALGORITHM_EDDSA
        }

        fn issuer(&self) -> TokenResult<IssuerDid> {
            Ok(self.issuer.clone())
        }

        fn public_key(&self) -> TokenResult<Ed25519PublicKey> {
            Ok(self.public_key.clone())
        }

        fn sign(&self, _signing_input: &[u8]) -> SignerResult<SignerSignature> {
            Ok(SignerSignature::new(vec![0_u8; super::ED25519_SIGNATURE_BYTES]))
        }
    }

    fn signing_key(byte: u8) -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes([byte; super::ED25519_SECRET_KEY_BYTES])
    }

    fn in_memory_signer(byte: u8) -> Ed25519InMemorySigner {
        Ed25519InMemorySigner::from_seed_bytes([byte; super::ED25519_SECRET_KEY_BYTES])
    }

    fn token_time_bounds() -> TokenTimeBounds {
        TokenTimeBounds::new(TOKEN_NOT_BEFORE_SECONDS, TOKEN_EXPIRES_AT_SECONDS).expect("bounds should validate")
    }

    fn issue_request(issuer_key: &Ed25519SigningKey, audience: AudienceDid, proofs: ProofCollection) -> IssueRequest {
        issue_request_with_capability(issuer_key, audience, proofs, "did:key:z6Mkresource", "store/*")
    }

    fn issue_request_with_capability(
        issuer_key: &Ed25519SigningKey,
        audience: AudienceDid,
        proofs: ProofCollection,
        resource: &str,
        ability: &str,
    ) -> IssueRequest {
        IssueRequest::new(
            issuer_key.clone(),
            audience,
            capabilities(resource, ability),
            proofs,
            TokenTimeBounds::new(TOKEN_NOT_BEFORE_SECONDS, TOKEN_EXPIRES_AT_SECONDS).expect("bounds should validate"),
        )
    }

    fn issue_request_with_caveat(
        issuer_key: &Ed25519SigningKey,
        audience: AudienceDid,
        proofs: ProofCollection,
        caveat: CaveatDocument,
    ) -> IssueRequest {
        IssueRequest::new(
            issuer_key.clone(),
            audience,
            CapabilitySet::new(vec![
                CapabilityDocument::with_caveats("did:key:z6Mkresource".to_owned(), "store/*".to_owned(), vec![caveat])
                    .expect("capability with caveat should validate"),
            ])
            .expect("capability set should validate"),
            proofs,
            TokenTimeBounds::new(TOKEN_NOT_BEFORE_SECONDS, TOKEN_EXPIRES_AT_SECONDS).expect("bounds should validate"),
        )
    }

    fn caveat(domain: &str, caveat_type: &str, key: &str, payload: &[u8]) -> CaveatDocument {
        CaveatDocument::new(domain.to_owned(), caveat_type.to_owned(), key.to_owned(), payload.to_vec())
            .expect("caveat should validate")
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

    fn child_request_with_caveat(
        issuer_key: &Ed25519SigningKey,
        parent: CompactToken,
        caveat: CaveatDocument,
    ) -> IssueRequest {
        let audience = signing_key(OTHER_SECRET_BYTE).issuer().expect("audience should derive");
        IssueRequest::new(
            issuer_key.clone(),
            AudienceDid::from(audience),
            CapabilitySet::new(vec![
                CapabilityDocument::with_caveats(
                    "did:key:z6Mkresource/photos".to_owned(),
                    "store/add".to_owned(),
                    vec![caveat],
                )
                .expect("capability with caveat should validate"),
            ])
            .expect("capability set should validate"),
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

    fn verified_child_token() -> VerifiedToken {
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
            VERIFICATION_TIME_SECONDS,
        );
        verify_compact_token(&child, &context).expect("delegation chain should verify")
    }

    fn assert_allowed_capability(decision: &AuthorizationDecision, resource: &str, ability: &str) {
        assert!(decision.is_allowed());
        assert_eq!(
            decision.matched_capability().expect("match should be exposed"),
            &CapabilityDocument::new(resource.to_owned(), ability.to_owned()).expect("capability should validate")
        );
    }

    fn assert_malformed_denial(decision: &AuthorizationDecision) {
        assert!(matches!(decision, AuthorizationDecision::Denied {
            reason: AuthorizationDenialReason::MalformedRequest { .. }
        }));
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
        let signature = super::URL_SAFE_NO_PAD.encode([0_u8; super::ED25519_SIGNATURE_BYTES]);
        CompactToken::new(super::join_compact_parts(&header, &payload, &signature)).expect("token should wrap")
    }

    fn assert_token_shape_and_claim_names(token: &CompactToken) {
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

    fn assert_secret_material_is_absent(output: &str) {
        assert!(!output.contains(REDACTION_TEST_SECRET_DECIMAL));
        assert!(!output.contains(REDACTION_TEST_DIRECT_ARRAY_PREFIX));
        assert!(!output.to_ascii_lowercase().contains(REDACTION_TEST_SECRET_HEX_LOWER));
    }

    fn capture_assertion_failure_message<F>(body: F) -> String
    where F: FnOnce() + std::panic::UnwindSafe {
        let panic = std::panic::catch_unwind(body).expect_err("assertion should fail");
        if let Some(message) = panic.downcast_ref::<String>() {
            return message.clone();
        }
        if let Some(message) = panic.downcast_ref::<&'static str>() {
            return (*message).to_owned();
        }
        panic!("assertion failure should use string panic payload");
    }
}
