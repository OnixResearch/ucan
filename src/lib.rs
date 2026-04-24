#![allow(clippy::cargo_common_metadata)]
#![allow(clippy::multiple_crate_versions)]

pub use ucan_core as core;

pub mod error;
pub mod shell;
pub mod verified;

pub use error::Error;
pub use error::Result;
pub use shell::CapabilityDocument;
pub use shell::load_capability_from_path;
pub use shell::load_capability_from_reader;
pub use shell::write_capability_to_writer;
pub use verified::TokenEnvelopeInput;
pub use verified::TokenTimeWindow;
pub use verified::TokenValidationFailure;
pub use verified::VerifiedCapability;
pub use verified::VerifiedPrimitiveError;
pub use verified::VerifiedResult;
pub use verified::attenuation_chain_is_valid;
pub use verified::compose_time_window_chain;
pub use verified::derive_ed25519_public_key;
pub use verified::encode_ed25519_did_key;
pub use verified::sign_ed25519;
pub use verified::token_needs_refresh;
pub use verified::token_time_valid;
pub use verified::token_time_valid_at;
pub use verified::validate_token_envelope;
pub use verified::verify_ed25519_signature;
