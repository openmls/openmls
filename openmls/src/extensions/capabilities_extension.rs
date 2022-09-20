use std::io::Read;

use openmls_traits::types::Ciphersuite;
use tls_codec::{TlsSerialize, TlsSize, TlsVecU8};

use super::{
    CapabilitiesExtensionError, Deserialize, ExtensionType, RequiredCapabilitiesExtension,
    Serialize,
};
use crate::{messages::proposals::ProposalType, versions::ProtocolVersion};

/// # Capabilities Extension
///
/// The capabilities extension indicates what protocol versions, ciphersuites,
/// protocol extensions, and non-default proposal types are supported by a client.
///
/// Proposal types defined in the RFC are considered "default" and thus need not
/// be listed.
///
/// This extension is always present in a KeyPackage.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize, TlsSize, TlsSerialize)]
pub struct CapabilitiesExtension {
    versions: TlsVecU8<ProtocolVersion>,
    ciphersuites: TlsVecU8<Ciphersuite>,
    extensions: TlsVecU8<ExtensionType>,
    proposals: TlsVecU8<ProposalType>,
}

fn default_extensions() -> Vec<ExtensionType> {
    vec![
        ExtensionType::Capabilities,
        ExtensionType::Lifetime,
        ExtensionType::ExternalKeyId,
    ]
}

fn default_proposals() -> Vec<ProposalType> {
    vec![
        ProposalType::Add,
        ProposalType::Update,
        ProposalType::Remove,
        ProposalType::Presharedkey,
        ProposalType::Reinit,
        ProposalType::GroupContextExtensions,
    ]
}

fn default_versions() -> Vec<ProtocolVersion> {
    vec![ProtocolVersion::Mls10]
}

fn default_ciphersuites() -> Vec<Ciphersuite> {
    vec![
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    ]
}

impl Default for CapabilitiesExtension {
    fn default() -> Self {
        CapabilitiesExtension {
            versions: default_versions().into(),
            ciphersuites: default_ciphersuites().into(),
            extensions: default_extensions().into(),
            proposals: default_proposals().into(),
        }
    }
}

impl CapabilitiesExtension {
    /// Create a new capabilities extension with the given configuration.
    /// Any argument that is `None` is filled with the default values from the
    /// global configuration.
    pub fn new(
        versions: Option<&[ProtocolVersion]>,
        ciphersuites: Option<&[Ciphersuite]>,
        extensions: Option<&[ExtensionType]>,
        proposals: Option<&[ProposalType]>,
    ) -> Self {
        Self {
            versions: match versions {
                Some(v) => v.into(),
                None => default_versions().into(),
            },
            ciphersuites: match ciphersuites {
                Some(c) => c.into(),
                None => default_ciphersuites().into(),
            },
            extensions: match extensions {
                Some(e) => e.into(),
                None => default_extensions().into(),
            },
            proposals: match proposals {
                Some(p) => p.into(),
                None => default_proposals().into(),
            },
        }
    }
    /// Get a reference to the list of versions in this extension.
    pub fn versions(&self) -> &[ProtocolVersion] {
        self.versions.as_slice()
    }
    /// Get a reference to the list of cipher suites in this extension.
    pub fn ciphersuites(&self) -> &[Ciphersuite] {
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
    /// Check if this [`CapabilitiesExtension`] supports all the capabilities
    /// required by the given [`RequiredCapabilities`] extension. Returns
    /// `true` if that is the case and `false` otherwise.
    pub(crate) fn supports_required_capabilities(
        &self,
        required_capabilities: &RequiredCapabilitiesExtension,
    ) -> bool {
        // Check if all required extensions are supported.
        if required_capabilities
            .extensions()
            .iter()
            .any(|e| !self.extensions().contains(e))
        {
            return false;
        }
        // Check if all required proposals are supported.
        if required_capabilities
            .proposals()
            .iter()
            .any(|p| !self.proposals().contains(p))
        {
            return false;
        }
        true
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

        let ciphersuites = TlsVecU8::<Ciphersuite>::tls_deserialize(bytes)?;
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
