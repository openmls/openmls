//! # MLS versions
//!
//! Only MLS 1.0 is currently supported.

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

// Public types

/// # Protocol Version
///
/// ```text
/// enum {
///     reserved(0),
///     mls10(1),
///     (65535)
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
#[repr(u16)]
#[allow(missing_docs)]
pub enum ProtocolVersion {
    Mls10 = 1,
    Mls10Draft11 = 200, // pre RFC version
}

/// There's only one version right now, which is the default.
impl Default for ProtocolVersion {
    fn default() -> Self {
        ProtocolVersion::Mls10
    }
}

impl TryFrom<u16> for ProtocolVersion {
    type Error = VersionError;

    /// Convert an integer to the corresponding protocol version.
    ///
    /// Returns an error if the protocol version is not supported.
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(ProtocolVersion::Mls10),
            200 => Ok(ProtocolVersion::Mls10Draft11),
            _ => Err(VersionError::UnsupportedMlsVersion),
        }
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            ProtocolVersion::Mls10 => write!(f, "MLS 1.0"),
            ProtocolVersion::Mls10Draft11 => write!(f, "MLS 1.0 (Draft 11)"),
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
