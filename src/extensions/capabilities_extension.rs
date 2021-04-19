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

use std::convert::TryFrom;

use super::{
    CapabilitiesExtensionError, Deserialize, Extension, ExtensionError, ExtensionStruct,
    ExtensionType, Serialize,
};
use crate::codec::{decode_vec, encode_vec, Cursor, VecSize};
use crate::config::{Config, ProtocolVersion};
use crate::{ciphersuite::CiphersuiteName, codec::TlsSize};

#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct CapabilitiesExtension {
    versions: Vec<ProtocolVersion>,
    ciphersuites: Vec<CiphersuiteName>,
    extensions: Vec<ExtensionType>,
}

impl Default for CapabilitiesExtension {
    fn default() -> Self {
        CapabilitiesExtension {
            versions: Config::supported_versions().to_vec(),
            ciphersuites: Config::supported_ciphersuite_names().to_vec(),
            extensions: Config::supported_extensions().to_vec(),
        }
    }
}

impl CapabilitiesExtension {
    /// Create a new capabilities extension with the given configuration.
    /// Any argument that is `None` is filled with the default values from the
    /// global configuration.
    pub fn new(
        versions: Option<&[ProtocolVersion]>,
        ciphersuites: Option<&[CiphersuiteName]>,
        extensions: Option<&[ExtensionType]>,
    ) -> Self {
        Self {
            versions: match versions {
                Some(v) => v.to_vec(),
                None => Config::supported_versions().to_vec(),
            },
            ciphersuites: match ciphersuites {
                Some(c) => c.to_vec(),
                None => Config::supported_ciphersuite_names().to_vec(),
            },
            extensions: match extensions {
                Some(e) => e.to_vec(),
                None => Config::supported_extensions().to_vec(),
            },
        }
    }
    /// Get a reference to the list of versions in this extension.
    pub fn versions(&self) -> &[ProtocolVersion] {
        &self.versions
    }
    /// Get a reference to the list of cipher suites in this extension.
    pub fn ciphersuites(&self) -> &[CiphersuiteName] {
        &self.ciphersuites
    }
    /// Get a reference to the list of supported extensions.
    pub fn extensions(&self) -> &[ExtensionType] {
        &self.extensions
    }
}

impl TlsSize for CapabilitiesExtension {
    #[inline]
    fn serialized_len(&self) -> usize {
        1 + self.versions.len() + 1 + self.ciphersuites.len() + 1 + self.extensions.len()
    }
}

#[typetag::serde]
impl Extension for CapabilitiesExtension {
    fn extension_type(&self) -> ExtensionType {
        ExtensionType::Capabilities
    }

    /// Build a new CapabilitiesExtension from a byte slice.
    /// Checks that we can work with these capabilities and returns an
    /// `ExtensionError` if not.
    fn new_from_bytes(bytes: &[u8]) -> Result<Self, ExtensionError>
    where
        Self: Sized,
    {
        let cursor = &mut Cursor::new(bytes);

        let version_numbers: Vec<u8> = decode_vec(VecSize::VecU8, cursor)?;
        let mut versions = Vec::new();
        for &version_number in version_numbers.iter() {
            versions.push(ProtocolVersion::try_from(version_number)?)
        }
        // There must be at least one version we support.
        if versions.is_empty() {
            let e = ExtensionError::Capabilities(CapabilitiesExtensionError::EmptyVersionsField);
            log::error!("Error reading capabilities extension form bytes: {:?}", e);
            return Err(e);
        }

        let ciphersuites: Vec<CiphersuiteName> = decode_vec(VecSize::VecU8, cursor)?;
        // There must be at least one ciphersuite we support.
        let mut supported_suite = false;
        for suite in ciphersuites.iter() {
            if suite.is_supported() {
                supported_suite = true;
                break;
            }
        }
        if !supported_suite {
            return Err(ExtensionError::Capabilities(
                super::CapabilitiesExtensionError::UnsupportedCiphersuite,
            ));
        }

        let extensions = decode_vec(VecSize::VecU8, cursor)?;

        Ok(Self {
            versions,
            ciphersuites,
            extensions,
        })
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
