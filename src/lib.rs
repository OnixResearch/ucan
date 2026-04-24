#![allow(clippy::cargo_common_metadata)]

pub use ucan_core as core;

pub mod error;
pub mod shell;

pub use error::Error;
pub use error::Result;
pub use shell::CapabilityDocument;
pub use shell::load_capability_from_path;
pub use shell::load_capability_from_reader;
pub use shell::write_capability_to_writer;
