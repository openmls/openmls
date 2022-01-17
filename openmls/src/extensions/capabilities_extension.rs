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

use std::io::Read;

use tls_codec::{TlsSerialize, TlsSize, TlsVecU8};

use super::{CapabilitiesExtensionError, Deserialize, ExtensionType, Serialize};
use crate::ciphersuite::CiphersuiteName;
use crate::config::{Config, ProtocolVersion};
use crate::messages::proposals::ProposalType;

#[derive(PartialEq, Clone, Debug, Serialize, Deserialize, TlsSize, TlsSerialize)]
pub struct CapabilitiesExtension {
    versions: TlsVecU8<ProtocolVersion>,
    ciphersuites: TlsVecU8<CiphersuiteName>,
    extensions: TlsVecU8<ExtensionType>,
    proposals: TlsVecU8<ProposalType>,
}

impl Default for CapabilitiesExtension {
    fn default() -> Self {
        CapabilitiesExtension {
            versions: Config::supported_versions().into(),
            ciphersuites: Config::supported_ciphersuite_names().into(),
            extensions: Config::supported_extensions().into(),
            proposals: Config::supported_proposals().into(),
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
        proposals: Option<&[ProposalType]>,
    ) -> Self {
        Self {
            versions: match versions {
                Some(v) => v.into(),
                None => Config::supported_versions().into(),
            },
            ciphersuites: match ciphersuites {
                Some(c) => c.into(),
                None => Config::supported_ciphersuite_names().into(),
            },
            extensions: match extensions {
                Some(e) => e.into(),
                None => Config::supported_extensions().into(),
            },
            proposals: match proposals {
                Some(p) => p.into(),
                None => Config::supported_proposals().into(),
            },
        }
    }
    /// Get a reference to the list of versions in this extension.
    pub fn versions(&self) -> &[ProtocolVersion] {
        self.versions.as_slice()
    }
    /// Get a reference to the list of cipher suites in this extension.
    pub fn ciphersuites(&self) -> &[CiphersuiteName] {
        self.ciphersuites.as_slice()
    }
    /// Get a reference to the list of supported extensions.
    pub fn extensions(&self) -> &[ExtensionType] {
        self.extensions.as_slice()
    }
    /// Get a reference to the list of supported proposals.
    pub fn proposals(&self) -> &[ProposalType] {
        self.proposals.as_slice()
    }
}

// We deserialize manually in order to perform some checks on the values.
impl tls_codec::Deserialize for CapabilitiesExtension {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let versions = TlsVecU8::<ProtocolVersion>::tls_deserialize(bytes)?;
        // There must be at least one version we support.
        if versions.is_empty() {
            let e = tls_codec::Error::DecodingError(format!(
                "{:?}",
                CapabilitiesExtensionError::EmptyVersionsField
            ));
            log::error!("Error reading capabilities extension form bytes: {:?}", e);
            return Err(e);
        }

        let ciphersuites = TlsVecU8::<CiphersuiteName>::tls_deserialize(bytes)?;
        // There must be at least one ciphersuite we support.
        let mut supported_suite = false;
        for suite in ciphersuites.iter() {
            if suite.is_supported() {
                supported_suite = true;
                break;
            }
        }
        if !supported_suite {
            return Err(tls_codec::Error::DecodingError(format!(
                "{:?}",
                CapabilitiesExtensionError::UnsupportedCiphersuite,
            )));
        }

        let extensions = TlsVecU8::tls_deserialize(bytes)?;
        let proposals = TlsVecU8::tls_deserialize(bytes)?;

        Ok(Self {
            versions,
            ciphersuites,
            extensions,
            proposals,
        })
    }
}
