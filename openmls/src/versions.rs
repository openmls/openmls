//! # MLS versions
//!
//! Only MLS 1.0 is currently supported.

use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt};
use thiserror::Error;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

// Public types

/// # Protocol Version
///
/// 7. Key Packages
///
/// ```text
/// enum {
///     reserved(0),
///     mls10(1),
///     (255)
/// } ProtocolVersion;
/// ```
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum ProtocolVersion {
    Mls10 = 1,
}

/// There's only one version right now, which is the default.
impl Default for ProtocolVersion {
    fn default() -> Self {
        ProtocolVersion::Mls10
    }
}

impl TryFrom<u8> for ProtocolVersion {
    type Error = VersionError;

    /// Convert an integer to the corresponding protocol version.
    ///
    /// Returns an error if the protocol version is not supported.
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(ProtocolVersion::Mls10),
            _ => Err(VersionError::UnsupportedMlsVersion),
        }
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            ProtocolVersion::Mls10 => write!(f, "MLS 1.0"),
        }
    }
}

/// Version Error
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum VersionError {
    /// Unsupported MLS version.
    #[error("Unsupported MLS version.")]
    UnsupportedMlsVersion,
}
