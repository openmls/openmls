use std::collections::HashSet;

use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, VerifiableCiphersuite},
};
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use super::LeafNode;
use crate::{
    credentials::CredentialType,
    extensions::{
        Extension, ExtensionType, ExtensionValidator, Extensions, RequiredCapabilitiesExtension,
    },
    messages::proposals::ProposalType,
    treesync::errors::LeafNodeValidationError,
    versions::ProtocolVersion,
};

/// How a leaf's capabilities are treated when they don't already cover what
/// the leaf being built needs.
///
/// There is deliberately no [`Default`]: which policy applies depends on
/// whether the caller set capabilities at all, so every call site resolves it
/// through `resolve_capabilities` rather than falling back on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilitiesPolicy {
    /// Reject construction unless the given capabilities already cover the
    /// leaf's own ciphersuite, credential type and extension types, and the
    /// group's required capabilities.
    Reject,
    /// Add whatever the leaf itself uses — its ciphersuite, credential type
    /// and extension types — and reject only if the group's required
    /// capabilities are still unmet. Never removes anything the caller set.
    ///
    /// Note that this widens only capabilities the library can derive from the
    /// leaf. It never claims support for the group's required extension,
    /// proposal or credential types on its own, and it cannot
    /// cover the cross-member credential checks a group applies on receipt.
    /// Therefore, a widened leaf is not automatically an acceptable one.
    Widen,
}

/// Resolve builder-level capabilities and policy into what leaf construction
/// needs.
///
/// Capabilities the caller never set are widened from the leaf itself: there is
/// exactly one sensible answer for what an unconfigured leaf should advertise,
/// and it is derivable. Capabilities the caller set explicitly are held to
/// exactly what they listed, because a list that doesn't cover the leaf is a
/// mistake worth reporting rather than papering over.
///
/// An explicit policy always wins over both defaults.
pub(crate) fn resolve_capabilities(
    capabilities: Option<Capabilities>,
    policy: Option<CapabilitiesPolicy>,
) -> (Capabilities, CapabilitiesPolicy) {
    match capabilities {
        Some(capabilities) => (capabilities, policy.unwrap_or(CapabilitiesPolicy::Reject)),
        None => (
            Capabilities::default(),
            policy.unwrap_or(CapabilitiesPolicy::Widen),
        ),
    }
}

/// Like [`resolve_capabilities`], but for a leaf that already exists in a tree.
///
/// Unset capabilities are inherited from that leaf rather than derived from
/// scratch: they were already validated when it entered the tree, so there is
/// nothing to widen from, and a rejection means the group's requirements have
/// changed since.
pub(crate) fn resolve_capabilities_for_existing_leaf(
    capabilities: Option<Capabilities>,
    policy: Option<CapabilitiesPolicy>,
    existing: &Capabilities,
) -> (Capabilities, CapabilitiesPolicy) {
    match capabilities {
        Some(_) => resolve_capabilities(capabilities, policy),
        None => (
            existing.clone(),
            policy.unwrap_or(CapabilitiesPolicy::Reject),
        ),
    }
}

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
    ///
    /// Only `versions` has a default (`Mls1.0`); every other `None`
    /// produces an **empty** list. An empty list is an
    /// explicit statement that nothing is supported, so a leaf built from it is
    /// rejected unless the caller also asks for [`CapabilitiesPolicy::Widen`].
    ///
    /// Prefer [`Capabilities::builder`], which makes the empty starting point
    /// obvious.
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
                None => vec![],
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
                None => vec![],
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

    /// Creates a new [`CapabilitiesBuilder`] for constructing [`Capabilities`].
    ///
    /// Starts from empty lists — except `versions`, which is seeded with
    /// `default_versions` since the library only ever builds `Mls10` leaves
    /// and there is no meaningful choice to make there. So a builder only ever
    /// ends up containing what the caller actually asked for, not an unrelated
    /// baseline.
    pub fn builder() -> CapabilitiesBuilder {
        CapabilitiesBuilder(Self::default())
    }

    /// Creates [`Capabilities`] advertising exactly the ciphersuites supported
    /// by the given crypto provider, derived from
    /// [`OpenMlsCrypto::supported_ciphersuites()`].
    ///
    /// All other lists are left empty, as everywhere else; only `versions` is
    /// seeded. Useful for a client that wants to advertise its full crypto
    /// reach rather than just the one ciphersuite a given leaf uses.
    pub fn for_provider(crypto: &impl OpenMlsCrypto) -> Self {
        Capabilities {
            ciphersuites: crypto
                .supported_ciphersuites()
                .into_iter()
                .map(VerifiableCiphersuite::from)
                .collect(),
            ..Default::default()
        }
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
        // The required capabilities come from the wire, so all three checks use
        // a set lookup and stop at the first unsupported entry.

        // Check if all required extensions are supported.
        let supported_extensions: HashSet<ExtensionType> =
            self.extensions().iter().copied().collect();
        if required_capabilities
            .extension_types()
            .iter()
            .any(|e| !e.is_default() && !supported_extensions.contains(e))
        {
            log::error!(
                "Leaf node does not support all required extension types\n
                Supported extensions: {:?}\n
                Required extensions: {:?}",
                self.extensions(),
                required_capabilities.extension_types()
            );
            return Err(LeafNodeValidationError::UnsupportedExtensions);
        }
        // Check if all required proposals are supported.
        let supported_proposals: HashSet<ProposalType> = self.proposals().iter().copied().collect();
        if required_capabilities
            .proposal_types()
            .iter()
            .any(|p| !p.is_default() && !supported_proposals.contains(p))
        {
            return Err(LeafNodeValidationError::UnsupportedProposals);
        }
        // Check if all required credential types are supported.
        let supported_credentials: HashSet<CredentialType> =
            self.credentials().iter().copied().collect();
        if required_capabilities
            .credential_types()
            .iter()
            .any(|c| !supported_credentials.contains(c))
        {
            return Err(LeafNodeValidationError::UnsupportedCredentials);
        }
        Ok(())
    }

    /// Check if these [`Capabilities`] contain all the extensions.
    pub(crate) fn contains_extensions(
        &self,
        extensions: &Extensions<impl ExtensionValidator>,
    ) -> bool {
        let mut required = extensions
            .iter()
            .map(Extension::extension_type)
            .filter(|e| !e.is_default())
            .peekable();

        // Most leaf nodes carry no non-default extensions. Skip building the
        // lookup set for them.
        if required.peek().is_none() {
            return true;
        }

        let supported: HashSet<ExtensionType> = self.extensions().iter().copied().collect();
        required.all(|e| supported.contains(&e))
    }

    /// Check if these [`Capabilities`] contain the extension.
    #[cfg(test)]
    pub(crate) fn contains_extension_type(&self, extension: &ExtensionType) -> bool {
        // Many leaf nodes carry no non-default extensions. Skip building the
        // lookup set for them.
        if extension.is_default() {
            return true;
        }

        let supported: HashSet<ExtensionType> = self.extensions().iter().copied().collect();
        supported.contains(extension)
    }

    /// Check if these [`Capabilities`] contains the credential.
    pub(crate) fn contains_credential(&self, credential_type: CredentialType) -> bool {
        self.credentials().contains(&credential_type)
    }

    /// Check if these [`Capabilities`] contain the version.
    pub(crate) fn contains_version(&self, version: ProtocolVersion) -> bool {
        self.versions().contains(&version)
    }

    /// Check if these [`Capabilities`] contain the ciphersuite.
    pub(crate) fn contains_ciphersuite(&self, ciphersuite: VerifiableCiphersuite) -> bool {
        self.ciphersuites().contains(&ciphersuite)
    }

    /// Ensure `version` is advertised.
    ///
    /// This is deliberately outside [`CapabilitiesPolicy`]: OpenMLS only ever
    /// builds `Mls10` leaves, so there is no choice for a caller to get wrong
    /// and nothing to reject. Real per-version negotiation would need to
    /// revisit this.
    pub(super) fn ensure_version(&mut self, version: ProtocolVersion) {
        if !self.contains_version(version) {
            self.versions.push(version);
        }
    }

    /// Widen `self` to cover what the leaf itself uses: its ciphersuite, its
    /// credential type, and its non-default extension types.
    ///
    /// Only ever adds; never removes anything the caller set. Every added
    /// entry is a fact about the leaf being built, so advertising it is
    /// always truthful.
    ///
    /// Note what this deliberately does *not* do: it never adds the group's
    /// [`RequiredCapabilitiesExtension`] entries. Those would be claims about
    /// what the *application* implements, which the library is in no position
    /// to make on its behalf, so a leaf that doesn't meet the group's
    /// requirements is rejected instead — see
    /// [`Capabilities::supports_required_capabilities`].
    ///
    /// Default extension types are skipped: RFC 9420 makes support for
    /// them implicit, so they never need listing. GREASE extension types are
    /// never default, so a GREASE extension actually present on the leaf is
    /// covered here.
    pub(super) fn widen_for(
        &mut self,
        ciphersuite: Ciphersuite,
        credential_type: CredentialType,
        leaf_extensions: &Extensions<LeafNode>,
    ) {
        let verifiable_ciphersuite = VerifiableCiphersuite::from(ciphersuite);
        if !self.contains_ciphersuite(verifiable_ciphersuite) {
            self.ciphersuites.push(verifiable_ciphersuite);
        }

        if !self.contains_credential(credential_type) {
            self.credentials.push(credential_type);
        }

        for extension_type in leaf_extensions.iter().map(Extension::extension_type) {
            if !extension_type.is_default() && !self.extensions.contains(&extension_type) {
                self.extensions.push(extension_type);
            }
        }
    }

    /// Add random GREASE values to the capabilities to ensure extensibility.
    ///
    /// This adds one random GREASE value to each capability list if no GREASE
    /// value is already present:
    /// - Ciphersuites
    /// - Extensions
    /// - Proposals
    /// - Credentials
    ///
    /// GREASE values are used per [RFC 9420 Section 13.5](https://www.rfc-editor.org/rfc/rfc9420.html#section-13.5)
    /// to help prevent extensibility failures by ensuring implementations properly
    /// handle unknown values.
    ///
    /// # Example
    ///
    /// ```
    /// use openmls::prelude::*;
    /// use openmls_rust_crypto::OpenMlsRustCrypto;
    ///
    /// let provider = OpenMlsRustCrypto::default();
    ///
    /// // Create capabilities with GREASE values injected
    /// let capabilities = Capabilities::builder()
    ///     .build()
    ///     .with_grease(provider.rand());
    ///
    /// // Verify GREASE values were added
    /// assert!(capabilities.ciphersuites().iter().any(|cs| cs.is_grease()));
    /// assert!(capabilities.extensions().iter().any(|ext| ext.is_grease()));
    /// assert!(capabilities.proposals().iter().any(|prop| prop.is_grease()));
    /// assert!(capabilities.credentials().iter().any(|cred| cred.is_grease()));
    /// ```
    pub fn with_grease(mut self, rand: &impl openmls_traits::random::OpenMlsRand) -> Self {
        use crate::credentials::CredentialType;
        use crate::extensions::ExtensionType;
        use crate::messages::proposals::ProposalType;
        use openmls_traits::types::VerifiableCiphersuite;

        // Add GREASE ciphersuite if none present
        if !self.ciphersuites.iter().any(|cs| cs.is_grease()) {
            let grease_cs = VerifiableCiphersuite::new(crate::grease::random_grease_value(rand));
            self.ciphersuites.push(grease_cs);
        }

        // Add GREASE extension if none present
        if !self.extensions.iter().any(|ext| ext.is_grease()) {
            let grease_ext = ExtensionType::Grease(crate::grease::random_grease_value(rand));
            self.extensions.push(grease_ext);
        }

        // Add GREASE proposal if none present
        if !self.proposals.iter().any(|prop| prop.is_grease()) {
            let grease_prop = ProposalType::Grease(crate::grease::random_grease_value(rand));
            self.proposals.push(grease_prop);
        }

        // Add GREASE credential if none present
        if !self.credentials.iter().any(|cred| cred.is_grease()) {
            let grease_cred = CredentialType::Grease(crate::grease::random_grease_value(rand));
            self.credentials.push(grease_cred);
        }

        self
    }
}

/// A helper for building [`Capabilities`]
#[derive(Debug, Clone)]
pub struct CapabilitiesBuilder(Capabilities);

impl CapabilitiesBuilder {
    /// Sets the `versions` field on the [`Capabilities`].
    pub fn versions(self, versions: Vec<ProtocolVersion>) -> Self {
        Self(Capabilities { versions, ..self.0 })
    }

    /// Sets the `ciphersuites` field on the [`Capabilities`].
    pub fn ciphersuites(self, ciphersuites: Vec<Ciphersuite>) -> Self {
        let ciphersuites = ciphersuites.into_iter().map(|cs| cs.into()).collect();

        Self(Capabilities {
            ciphersuites,
            ..self.0
        })
    }

    /// Sets the `extensions` field on the [`Capabilities`].
    pub fn extensions(self, extensions: Vec<ExtensionType>) -> Self {
        Self(Capabilities {
            extensions,
            ..self.0
        })
    }

    /// Sets the `proposals` field on the [`Capabilities`].
    pub fn proposals(self, proposals: Vec<ProposalType>) -> Self {
        Self(Capabilities {
            proposals,
            ..self.0
        })
    }

    /// Sets the `credentials` field on the [`Capabilities`].
    pub fn credentials(self, credentials: Vec<CredentialType>) -> Self {
        Self(Capabilities {
            credentials,
            ..self.0
        })
    }

    /// Adds random GREASE values to the capabilities being built.
    ///
    /// This is a convenience method that calls [`Capabilities::with_grease`] on the
    /// built capabilities. See that method for more details.
    ///
    /// # Example
    ///
    /// ```
    /// use openmls::prelude::*;
    /// use openmls_rust_crypto::OpenMlsRustCrypto;
    ///
    /// let provider = OpenMlsRustCrypto::default();
    ///
    /// let capabilities = Capabilities::builder()
    ///     .with_grease(provider.rand())
    ///     .build();
    ///
    /// // GREASE values were added
    /// assert!(capabilities.ciphersuites().iter().any(|cs| cs.is_grease()));
    /// ```
    pub fn with_grease(self, rand: &impl openmls_traits::random::OpenMlsRand) -> Self {
        Self(self.0.with_grease(rand))
    }

    /// Builds the [`Capabilities`].
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
    /// Like empty, but setting the default version to MLS1.0
    fn default() -> Self {
        Capabilities {
            versions: default_versions(),
            ciphersuites: vec![],
            extensions: vec![],
            proposals: vec![],
            credentials: vec![],
        }
    }
}

/// We have a default version because this is the only version supported by
/// OpenMLS right now.
///
/// All other capabilities do not have default values.
pub(super) fn default_versions() -> Vec<ProtocolVersion> {
    vec![ProtocolVersion::Mls10]
}

#[cfg(test)]
mod tests {
    use openmls_traits::{
        crypto::OpenMlsCrypto,
        types::{Ciphersuite, VerifiableCiphersuite},
    };
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
            // Use non-GREASE values (GREASE pattern is 0x_A_A)
            VerifiableCiphersuite::new(0x0B0B),
            VerifiableCiphersuite::new(0x7C7C),
            VerifiableCiphersuite::new(0xF000),
            VerifiableCiphersuite::new(0xFFFF),
        ];

        let extensions = vec![
            ExtensionType::Unknown(0x0000),
            ExtensionType::Unknown(0xFAFA),
        ];

        // Use non-GREASE values
        let proposals = vec![ProposalType::Custom(0x7C7C)];

        let credentials = vec![
            CredentialType::Basic,
            CredentialType::X509,
            CredentialType::Other(0x0000),
            // Use non-GREASE values
            CredentialType::Other(0x7C7C),
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

    #[test]
    fn for_provider_advertises_exactly_the_supported_ciphersuites() {
        let crypto = openmls_rust_crypto::RustCrypto::default();
        let capabilities = Capabilities::for_provider(&crypto);

        let expected: Vec<VerifiableCiphersuite> = crypto
            .supported_ciphersuites()
            .into_iter()
            .map(VerifiableCiphersuite::from)
            .collect();
        assert_eq!(capabilities.ciphersuites(), expected.as_slice());
    }
}
