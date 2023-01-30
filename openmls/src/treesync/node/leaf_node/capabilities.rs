use openmls_traits::types::Ciphersuite;
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{
    credentials::CredentialType,
    extensions::{ExtensionType, RequiredCapabilitiesExtension},
    messages::proposals::ProposalType,
    versions::ProtocolVersion,
};

/// Capabilities of [`LeafNode`]s.
///
/// ```text
/// struct {
///     ProtocolVersion versions<V>;
///     CipherSuite ciphersuites<V>;
///     ExtensionType extensions<V>;
///     ProposalType proposals<V>;
///     CredentialType credentials<V>;
/// } Capabilities;
/// ```
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct Capabilities {
    pub(super) versions: Vec<ProtocolVersion>,
    pub(super) ciphersuites: Vec<Ciphersuite>,
    pub(super) extensions: Vec<ExtensionType>,
    pub(super) proposals: Vec<ProposalType>,
    pub(super) credentials: Vec<CredentialType>,
}

impl Capabilities {
    /// Create a new [`Capabilities`] struct with the given configuration.
    /// Any argument that is `None` is filled with the default values from the
    /// global configuration.
    // TODO(#1232)
    pub fn new(
        versions: Option<&[ProtocolVersion]>,
        ciphersuites: Option<&[Ciphersuite]>,
        extensions: Option<&[ExtensionType]>,
        proposals: Option<&[ProposalType]>,
        credentials: Option<&[CredentialType]>,
    ) -> Self {
        Self {
            versions: match versions {
                Some(v) => v.into(),
                None => default_versions(),
            },
            ciphersuites: match ciphersuites {
                Some(c) => c.into(),
                None => default_ciphersuites(),
            },
            extensions: match extensions {
                Some(e) => e.into(),
                None => vec![],
            },
            proposals: match proposals {
                Some(p) => p.into(),
                None => vec![],
            },
            credentials: match credentials {
                Some(c) => c.into(),
                None => default_credentials(),
            },
        }
    }

    /// Create new empty [`Capabilities`].
    pub fn empty() -> Self {
        Self {
            versions: Vec::new(),
            ciphersuites: Vec::new(),
            extensions: Vec::new(),
            proposals: Vec::new(),
            credentials: Vec::new(),
        }
    }

    // ---------------------------------------------------------------------------------------------

    /// Get a reference to the list of versions in this extension.
    pub fn versions(&self) -> &[ProtocolVersion] {
        &self.versions
    }

    /// Get a reference to the list of ciphersuites in this extension.
    pub fn ciphersuites(&self) -> &[Ciphersuite] {
        &self.ciphersuites
    }

    /// Get a reference to the list of supported extensions.
    pub fn extensions(&self) -> &[ExtensionType] {
        &self.extensions
    }

    /// Get a reference to the list of supported proposals.
    pub fn proposals(&self) -> &[ProposalType] {
        &self.proposals
    }

    /// Get a reference to the list of supported credential types.
    pub fn credentials(&self) -> &[CredentialType] {
        &self.credentials
    }

    // ---------------------------------------------------------------------------------------------

    /// Check if these [`Capabilities`] support all the capabilities
    /// required by the given [`RequiredCapabilities`] extension. Returns
    /// `true` if that is the case and `false` otherwise.
    pub(crate) fn supports_required_capabilities(
        &self,
        required_capabilities: &RequiredCapabilitiesExtension,
    ) -> bool {
        // Check if all required extensions are supported.
        if required_capabilities
            .extension_types()
            .iter()
            .any(|e| !self.extensions().contains(e))
        {
            return false;
        }
        // Check if all required proposals are supported.
        if required_capabilities
            .proposal_types()
            .iter()
            .any(|p| !self.proposals().contains(p))
        {
            return false;
        }
        true
    }
}

#[cfg(test)]
impl Capabilities {
    /// Set the versions list.
    pub fn set_versions(&mut self, versions: Vec<ProtocolVersion>) {
        self.versions = versions;
    }

    /// Set the ciphersuites list.
    pub fn set_ciphersuites(&mut self, ciphersuites: Vec<Ciphersuite>) {
        self.ciphersuites = ciphersuites;
    }
}

impl Default for Capabilities {
    fn default() -> Self {
        Capabilities {
            versions: default_versions(),
            ciphersuites: default_ciphersuites(),
            extensions: default_extensions(),
            proposals: default_proposals(),
            credentials: default_credentials(),
        }
    }
}

pub(super) fn default_versions() -> Vec<ProtocolVersion> {
    vec![ProtocolVersion::Mls10]
}

pub(super) fn default_ciphersuites() -> Vec<Ciphersuite> {
    vec![
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    ]
}

/// All extensions defined in the MLS spec are considered "default" by the spec.
pub(super) fn default_extensions() -> Vec<ExtensionType> {
    vec![ExtensionType::ApplicationId]
}

/// All proposals defined in the MLS spec are considered "default" by the spec.
pub(super) fn default_proposals() -> Vec<ProposalType> {
    vec![
        ProposalType::Add,
        ProposalType::Update,
        ProposalType::Remove,
        ProposalType::Presharedkey,
        ProposalType::Reinit,
        ProposalType::GroupContextExtensions,
    ]
}

// TODO(#1231)
pub(super) fn default_credentials() -> Vec<CredentialType> {
    vec![CredentialType::Basic]
}
