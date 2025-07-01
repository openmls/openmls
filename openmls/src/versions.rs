//! # MLS versions
//!
//! Only MLS 1.0 is currently supported.

use serde::{Deserialize, Serialize};
use std::{fmt, io::Read};
use thiserror::Error;
use tls_codec::{
    Deserialize as TlsDeserializeTrait, DeserializeBytes, Error, Serialize as TlsSerializeTrait,
    Size,
};

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
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u16)]
#[allow(missing_docs)]
pub enum ProtocolVersion {
    Mls10 = 1,
    Other(u16),
}

/// There's only one version right now, which is the default.
impl Default for ProtocolVersion {
    fn default() -> Self {
        ProtocolVersion::Mls10
    }
}

impl From<u16> for ProtocolVersion {
    /// Convert an integer to the corresponding protocol version.
    fn from(v: u16) -> Self {
        match v {
            1 => ProtocolVersion::Mls10,
            _ => ProtocolVersion::Other(v),
        }
    }
}

impl TlsSerializeTrait for ProtocolVersion {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        match self {
            ProtocolVersion::Mls10 => {
                let v = 1u16;
                v.tls_serialize(writer)
            }
            ProtocolVersion::Other(v) => v.tls_serialize(writer),
        }
    }
}

impl TlsDeserializeTrait for ProtocolVersion {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        u16::tls_deserialize(bytes).map(ProtocolVersion::from)
    }
}

impl DeserializeBytes for ProtocolVersion {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized,
    {
        let (v, bytes) = u16::tls_deserialize_bytes(bytes)?;
        Ok((ProtocolVersion::from(v), bytes))
    }
}

impl Size for ProtocolVersion {
    fn tls_serialized_len(&self) -> usize {
        2
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            ProtocolVersion::Mls10 => write!(f, "MLS 1.0"),
            ProtocolVersion::Other(v) => write!(f, "Other version: {}", v),
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
