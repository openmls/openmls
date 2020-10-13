//! # Capabilities Extension
//!
//! > Key Package Extension
//!
//! This extension MUST be always present in a KeyPackage. Extensions that
//! appear in the extensions field of a KeyPackage MUST be included in the
//! extensions field of the capabilities extension.
//!
//! ```text
//! struct {
//!     ProtocolVersion versions<0..255>;
//!     CipherSuite ciphersuites<0..255>;
//!     ExtensionType extensions<0..255>;
//! } Capabilities;
//! ```
//!

use super::{Extension, ExtensionStruct, ExtensionType};
use crate::ciphersuite::CiphersuiteName;
use crate::codec::{decode_vec, encode_vec, Cursor, VecSize};
use crate::config::{Config, ProtocolVersion};
use crate::errors::ConfigError;

#[derive(PartialEq, Clone, Debug)]
pub(crate) struct CapabilitiesExtension {
    versions: Vec<ProtocolVersion>,
    ciphersuites: Vec<CiphersuiteName>,
    extensions: Vec<ExtensionType>,
}

impl Default for CapabilitiesExtension {
    fn default() -> Self {
        CapabilitiesExtension {
            versions: Config::supported_versions(),
            ciphersuites: Config::supported_ciphersuites(),
            extensions: Config::supported_extensions(),
        }
    }
}

impl Extension for CapabilitiesExtension {
    fn get_type(&self) -> ExtensionType {
        ExtensionType::Capabilities
    }

    /// Build a new CapabilitiesExtension from a byte slice.
    /// Checks that we can work with these capabilities and returns a `ConfigError`
    /// if not.
    fn new_from_bytes(bytes: &[u8]) -> Result<Box<dyn Extension>, ConfigError>
    where
        Self: Sized,
    {
        let cursor = &mut Cursor::new(bytes);

        let version_numbers: Vec<u8> = decode_vec(VecSize::VecU8, cursor).unwrap();
        let mut versions = Vec::new();
        for &version_number in version_numbers.iter() {
            versions.push(ProtocolVersion::from(version_number)?)
        }
        // There must be at least one version we support.
        if versions.is_empty() {
            return Err(ConfigError::UnsupportedMlsVersion);
        }

        let ciphersuites: Vec<CiphersuiteName> = decode_vec(VecSize::VecU8, cursor).unwrap();
        // There must be at least one ciphersuite we support.
        let mut supported_suite = false;
        for suite in ciphersuites.iter() {
            if suite.is_supported() {
                supported_suite = true;
                break;
            }
        }
        if !supported_suite {
            return Err(ConfigError::UnsupportedCiphersuite);
        }

        let extensions = decode_vec(VecSize::VecU8, cursor).unwrap();

        Ok(Box::new(Self {
            versions,
            ciphersuites,
            extensions,
        }))
    }

    fn to_extension_struct(&self) -> ExtensionStruct {
        let mut extension_data: Vec<u8> = vec![];
        encode_vec(VecSize::VecU8, &mut extension_data, &self.versions).unwrap();
        encode_vec(VecSize::VecU8, &mut extension_data, &self.ciphersuites).unwrap();
        encode_vec(VecSize::VecU8, &mut extension_data, &self.extensions).unwrap();
        let extension_type = ExtensionType::Capabilities;
        ExtensionStruct::new(extension_type, extension_data)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
