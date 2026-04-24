use core::fmt;
use std::io;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum Error {
    Io { source: io::Error },
    Capability { source: ucan_core::CapabilityError },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { source } => write!(formatter, "I/O error: {source}"),
            Self::Capability { source } => write!(formatter, "capability error: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source } => Some(source),
            Self::Capability { source } => Some(source),
        }
    }
}

impl From<io::Error> for Error {
    fn from(source: io::Error) -> Self {
        Self::Io { source }
    }
}

impl From<ucan_core::CapabilityError> for Error {
    fn from(source: ucan_core::CapabilityError) -> Self {
        Self::Capability { source }
    }
}
