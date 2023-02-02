//! # MLS versions
//!
//! Only MLS 1.0 is currently supported.

use discrim::FromDiscriminant;
use serde::{Deserialize, Serialize};
use std::fmt;
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
    FromDiscriminant,
)]
#[repr(u8)]
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
