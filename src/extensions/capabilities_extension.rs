//! # Capabilities Extension
//!
//! > Key Package Extension
//!
//! The capabilities extension is mandatory in key packages.
//!
//! ```text
//! struct {
//!     ProtocolVersion versions<0..255>;
//!     CipherSuite ciphersuites<0..255>;
//!     ExtensionType extensions<0..255>;
//! } Capabilities;
//! ```
//!

use super::{Extension, ExtensionType};
use crate::ciphersuite::CiphersuiteName;
use crate::codec::{decode_vec, encode_vec, Cursor, VecSize};
use crate::config::ProtocolVersion;
use crate::errors::ConfigError;

#[derive(PartialEq, Clone, Debug)]
pub(crate) struct CapabilitiesExtension {
    versions: Vec<ProtocolVersion>,
    ciphersuites: Vec<CiphersuiteName>,
    extensions: Vec<ExtensionType>,
}

// TODO: All these functions should be in a trait.

impl CapabilitiesExtension {
    /// Create a new `CapabilitiesExtension` with the given values.
    pub(crate) fn new(
        versions: Vec<ProtocolVersion>,
        ciphersuites: Vec<CiphersuiteName>,
        extensions: Vec<ExtensionType>,
    ) -> Self {
        CapabilitiesExtension {
            versions,
            ciphersuites,
            extensions,
        }
    }

    /// Build a new CapabilitiesExtension from a byte slice.
    pub(crate) fn new_from_bytes(bytes: &[u8]) -> Result<Self, ConfigError> {
        let cursor = &mut Cursor::new(bytes);
        let version_numbers: Vec<u8> = decode_vec(VecSize::VecU8, cursor).unwrap();
        let mut versions = Vec::new();
        for &version_number in version_numbers.iter() {
            versions.push(ProtocolVersion::from(version_number)?)
        }
        let ciphersuites = decode_vec(VecSize::VecU8, cursor).unwrap();
        let extensions = decode_vec(VecSize::VecU8, cursor).unwrap();
        Ok(Self {
            versions,
            ciphersuites,
            extensions,
        })
    }

    pub(crate) fn to_extension(&self) -> Extension {
        let mut extension_data: Vec<u8> = vec![];
        encode_vec(VecSize::VecU8, &mut extension_data, &self.versions).unwrap();
        encode_vec(VecSize::VecU8, &mut extension_data, &self.ciphersuites).unwrap();
        encode_vec(VecSize::VecU8, &mut extension_data, &self.extensions).unwrap();
        let extension_type = ExtensionType::Capabilities;
        Extension {
            extension_type,
            extension_data,
        }
    }

    pub(crate) fn contains_ciphersuite(&self, ciphersuite: &CiphersuiteName) -> bool {
        self.ciphersuites.contains(ciphersuite)
    }
}
