use openmls_traits::types::{Ciphersuite, VerifiableCiphersuite};
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

#[cfg(doc)]
use super::LeafNode;
use crate::{
    ciphersuite,
    credentials::CredentialType,
    extensions::{Extension, ExtensionType, Extensions, RequiredCapabilitiesExtension},
    messages::proposals::ProposalType,
    treesync::errors::LeafNodeValidationError,
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
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct Capabilities {
    pub(super) versions: Vec<ProtocolVersion>,
    pub(super) ciphersuites: Vec<VerifiableCiphersuite>,
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
                Some(c) => c.iter().map(|c| VerifiableCiphersuite::from(*c)).collect(),
                None => default_ciphersuites()
                    .into_iter()
                    .map(VerifiableCiphersuite::from)
                    .collect(),
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

    pub fn builder() -> CapabilitiesBuilder {
        CapabilitiesBuilder(Self::default())
    }

    // ---------------------------------------------------------------------------------------------

    /// Get a reference to the list of versions in this extension.
    pub fn versions(&self) -> &[ProtocolVersion] {
        &self.versions
    }

    /// Get a reference to the list of ciphersuites in this extension.
    pub fn ciphersuites(&self) -> &[VerifiableCiphersuite] {
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

    pub(crate) fn supports_extension_type(&self, extension_type: ExtensionType) -> bool {
        default_extensions().contains(&extension_type) || self.extensions.contains(&extension_type)
    }

    pub(crate) fn supports_proposal_type(&self, proposal_type: ProposalType) -> bool {
        default_proposals().contains(&proposal_type) || self.proposals.contains(&proposal_type)
    }

    pub(crate) fn supports_credential_type(&self, credential_type: CredentialType) -> bool {
        default_credentials().contains(&credential_type)
            || self.credentials.contains(&credential_type)
    }
    pub(crate) fn supports_ciphersuite(&self, ciphersuite: Ciphersuite) -> bool {
        default_ciphersuites().contains(&ciphersuite)
            || self.ciphersuites.contains(&ciphersuite.into())
    }

    pub(crate) fn supports_version(&self, version: ProtocolVersion) -> bool {
        default_versions().contains(&version) || self.versions.contains(&version)
    }

    /// Check if these [`Capabilities`] support all the capabilities required by
    /// the given [`RequiredCapabilitiesExtension`].
    ///
    /// # Errors
    ///
    /// Returns a [`LeafNodeValidationError`] error if any of the required
    /// capabilities is not supported.
    pub(crate) fn supports_required_capabilities(
        &self,
        required_capabilities: &RequiredCapabilitiesExtension,
    ) -> Result<(), LeafNodeValidationError> {
        // Check if all required extensions are supported.
        if required_capabilities
            .extension_types()
            .iter()
            .any(|e| !(self.extensions().contains(e) || default_extensions().contains(e)))
        {
            return Err(LeafNodeValidationError::UnsupportedExtensions);
        }
        // Check if all required proposals are supported.
        if required_capabilities
            .proposal_types()
            .iter()
            .any(|p| !(self.proposals().contains(p) || default_proposals().contains(p)))
        {
            return Err(LeafNodeValidationError::UnsupportedProposals);
        }
        // Check if all required credential types are supported.
        if required_capabilities
            .credential_types()
            .iter()
            .any(|c| !(self.credentials().contains(c) || default_credentials().contains(c)))
        {
            return Err(LeafNodeValidationError::UnsupportedCredentials);
        }
        Ok(())
    }

    /// Check if these [`Capabilities`] contain all the extensions.
    pub(crate) fn contain_extensions(&self, extension: &Extensions) -> bool {
        extension.iter().map(Extension::extension_type).all(|e| {
            println!("{e:?}");
            self.extensions().contains(&e)
        })
    }

    /// Check if these [`Capabilities`] contain all the credentials.
    pub(crate) fn contains_credential(&self, credential_type: &CredentialType) -> bool {
        self.credentials().contains(credential_type)
    }
}

pub struct CapabilitiesBuilder(Capabilities);

impl CapabilitiesBuilder {
    pub fn versions(self, versions: Vec<ProtocolVersion>) -> Self {
        Self(Capabilities { versions, ..self.0 })
    }

    pub fn ciphersuites(self, ciphersuites: Vec<Ciphersuite>) -> Self {
        let ciphersuites = ciphersuites.into_iter().map(|cs| cs.into()).collect();

        Self(Capabilities {
            ciphersuites,
            ..self.0
        })
    }

    pub fn extensions(self, extensions: Vec<ExtensionType>) -> Self {
        Self(Capabilities {
            extensions,
            ..self.0
        })
    }

    pub fn proposals(self, proposals: Vec<ProposalType>) -> Self {
        Self(Capabilities {
            proposals,
            ..self.0
        })
    }

    pub fn credentials(self, credentials: Vec<CredentialType>) -> Self {
        Self(Capabilities {
            credentials,
            ..self.0
        })
    }

    pub fn build(self) -> Capabilities {
        self.0
    }
}

#[cfg(test)]
impl Capabilities {
    /// Set the versions list.
    pub fn set_versions(&mut self, versions: Vec<ProtocolVersion>) {
        self.versions = versions;
    }

    /// Set the ciphersuites list.
    pub fn set_ciphersuites(&mut self, ciphersuites: Vec<VerifiableCiphersuite>) {
        self.ciphersuites = ciphersuites;
    }
}

impl Default for Capabilities {
    fn default() -> Self {
        Capabilities {
            versions: default_versions(),
            ciphersuites: default_ciphersuites()
                .into_iter()
                .map(VerifiableCiphersuite::from)
                .collect(),
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
        Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
    ]
}

/// All extensions defined in the MLS spec are considered "default" by the spec.
pub(crate) fn default_extensions() -> Vec<ExtensionType> {
    vec![
        ExtensionType::ApplicationId,
        ExtensionType::RatchetTree,
        ExtensionType::RequiredCapabilities,
        ExtensionType::ExternalPub,
        ExtensionType::ExternalSenders,
    ]
}

/// All proposals defined in the MLS spec are considered "default" by the spec.
pub(super) fn default_proposals() -> Vec<ProposalType> {
    vec![
        ProposalType::Add,
        ProposalType::Update,
        ProposalType::Remove,
        ProposalType::PreSharedKey,
        ProposalType::Reinit,
        ProposalType::GroupContextExtensions,
    ]
}

// TODO(#1231)
pub(super) fn default_credentials() -> Vec<CredentialType> {
    vec![CredentialType::Basic]
}

#[cfg(test)]
mod tests {
    use openmls_traits::types::{Ciphersuite, VerifiableCiphersuite};
    use tls_codec::{Deserialize, Serialize};

    use super::Capabilities;
    use crate::{
        credentials::CredentialType, messages::proposals::ProposalType, prelude::ExtensionType,
        versions::ProtocolVersion,
    };

    #[test]
    fn that_unknown_capabilities_are_de_serialized_correctly() {
        let versions = vec![ProtocolVersion::Mls10, ProtocolVersion::Other(999)];
        let ciphersuites = vec![
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.into(),
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256.into(),
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519.into(),
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448.into(),
            Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521.into(),
            Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448.into(),
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384.into(),
            VerifiableCiphersuite::new(0x0000),
            VerifiableCiphersuite::new(0x0A0A),
            VerifiableCiphersuite::new(0x7A7A),
            VerifiableCiphersuite::new(0xF000),
            VerifiableCiphersuite::new(0xFFFF),
        ];

        let extensions = vec![
            ExtensionType::Unknown(0x0000),
            ExtensionType::Unknown(0xFAFA),
        ];

        let proposals = vec![ProposalType::Custom(0x7A7A)];

        let credentials = vec![
            CredentialType::Basic,
            CredentialType::X509,
            CredentialType::Other(0x0000),
            CredentialType::Other(0x7A7A),
            CredentialType::Other(0xFFFF),
        ];

        let expected = Capabilities {
            versions,
            ciphersuites,
            extensions,
            proposals,
            credentials,
        };

        let test_serialized = expected.tls_serialize_detached().unwrap();

        let got = Capabilities::tls_deserialize_exact(test_serialized).unwrap();

        assert_eq!(expected, got);
    }
}
