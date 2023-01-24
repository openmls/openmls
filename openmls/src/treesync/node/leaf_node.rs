//! This module contains the [`LeafNode`] struct and its implementation.
use openmls_traits::{
    key_store::OpenMlsKeyStore, signatures::ByteSigner, types::Ciphersuite, OpenMlsCryptoProvider,
};
use serde::{Deserialize, Serialize};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait, TlsDeserialize,
    TlsSerialize, TlsSize, VLBytes,
};

use thiserror::Error;

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    ciphersuite::{
        signable::{Signable, SignedStruct, Verifiable},
        HpkePublicKey, Signature, SignaturePublicKey,
    },
    credentials::{Credential, CredentialType, CredentialWithKey},
    error::LibraryError,
    extensions::Extensions,
    extensions::{ExtensionType, RequiredCapabilitiesExtension},
    group::{config::CryptoConfig, GroupId},
    key_packages::KeyPackage,
    messages::proposals::ProposalType,
    prelude::PublicTreeError,
    treesync::errors::TreeSyncError,
    versions::ProtocolVersion,
};

mod lifetime;
pub use self::lifetime::Lifetime;

use super::encryption_keys::{EncryptionKey, EncryptionKeyPair};

#[derive(Error, Debug, PartialEq, Clone)]
pub enum LeafNodeGenerationError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Error storing leaf private key in key store.
    #[error("Error storing leaf private key in key store.")]
    KeyStoreError(KeyStoreError),
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
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct Capabilities {
    versions: Vec<ProtocolVersion>,
    ciphersuites: Vec<Ciphersuite>,
    extensions: Vec<ExtensionType>,
    proposals: Vec<ProposalType>,
    credentials: Vec<CredentialType>,
}

// FIXME: deduplicate with CapabilitiesExtension.

/// All extensions defined in the MLS spec are considered "default" by the spec.
fn default_extensions() -> Vec<ExtensionType> {
    vec![ExtensionType::ApplicationId]
}

/// All proposals defined in the MLS spec are considered "default" by the spec.
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

fn default_credentials() -> Vec<CredentialType> {
    vec![CredentialType::Basic]
}

impl Capabilities {
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

    /// Create a new [`Capabilities`] struct with the given configuration.
    /// Any argument that is `None` is filled with the default values from the
    /// global configuration.
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

    /// Get a reference to the list of versions in this extension.
    pub fn versions(&self) -> &[ProtocolVersion] {
        &self.versions
    }

    /// Set the versions list.
    #[cfg(test)]
    pub fn set_versions(&mut self, versions: Vec<ProtocolVersion>) {
        self.versions = versions;
    }

    /// Get a reference to the list of ciphersuites in this extension.
    pub fn ciphersuites(&self) -> &[Ciphersuite] {
        &self.ciphersuites
    }

    /// Set the ciphersuites list.
    #[cfg(test)]
    pub fn set_ciphersuites(&mut self, ciphersuites: Vec<Ciphersuite>) {
        self.ciphersuites = ciphersuites;
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

pub type ParentHash = VLBytes;

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
#[repr(u8)]
pub enum LeafNodeSource {
    #[tls_codec(discriminant = 1)]
    KeyPackage(Lifetime),
    Update,
    Commit(ParentHash),
}

#[derive(Debug, TlsSerialize, TlsDeserialize, TlsSize)]
pub(crate) struct TreePosition {
    group_id: GroupId,
    leaf_index: LeafNodeIndex,
}

/// Helper struct that holds additional information required to sign a leaf node.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     // ... continued from [`LeafNodeTbs`] ...
///
///     select (LeafNodeTBS.leaf_node_source) {
///         case key_package:
///             struct{};
///
///         case update:
///             opaque group_id<V>;
///             uint32 leaf_index;
///
///         case commit:
///             opaque group_id<V>;
///             uint32 leaf_index;
///     };
/// } LeafNodeTBS;
/// ```
#[derive(Debug)]
pub(crate) enum TreeInfoTbs {
    KeyPackage,
    Update(TreePosition),
    Commit(TreePosition),
}

impl TreeInfoTbs {
    pub(crate) fn commit(group_id: GroupId, leaf_index: LeafNodeIndex) -> Self {
        Self::Commit(TreePosition {
            group_id,
            leaf_index,
        })
    }
}

/// The payload of a [`LeafNode`]
///
/// ```text
/// struct {
///     HPKEPublicKey encryption_key;
///     SignaturePublicKey signature_key;
///     Credential credential;
///     Capabilities capabilities;
///
///     LeafNodeSource leaf_node_source;
///     select (LeafNode.leaf_node_source) {
///         case key_package:
///             Lifetime lifetime;
///
///         case update:
///             struct{};
///
///         case commit:
///             opaque parent_hash<V>;
///     };
///
///     Extension extensions<V>;
///     ...
/// } LeafNode;
/// ```
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
struct LeafNodePayload {
    encryption_key: EncryptionKey,
    signature_key: SignaturePublicKey,
    credential: Credential,
    capabilities: Capabilities,
    leaf_node_source: LeafNodeSource,
    extensions: Extensions,
}

/// To-be-signed leaf node.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     HPKEPublicKey encryption_key;
///     SignaturePublicKey signature_key;
///     Credential credential;
///     Capabilities capabilities;
///
///     LeafNodeSource leaf_node_source;
///     select (LeafNodeTBS.leaf_node_source) {
///         case key_package:
///             Lifetime lifetime;
///
///         case update:
///             struct{};
///
///         case commit:
///             opaque parent_hash<V>;
///     };
///
///     Extension extensions<V>;
///
///     // ... continued in [`TreeInfoTbs`] ...
/// } LeafNodeTBS;
/// ```
#[derive(Debug)]
pub struct LeafNodeTbs {
    payload: LeafNodePayload,
    tree_info: TreeInfoTbs,
}

impl TlsSerializeTrait for LeafNodeTbs {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let written = self.payload.tls_serialize(writer)?;
        match &self.tree_info {
            TreeInfoTbs::KeyPackage => Ok(written),
            TreeInfoTbs::Update(p) | TreeInfoTbs::Commit(p) => {
                p.tls_serialize(writer).map(|b| written + b)
            }
        }
    }
}

impl tls_codec::Size for LeafNodeTbs {
    fn tls_serialized_len(&self) -> usize {
        let len = self.payload.tls_serialized_len();
        match &self.tree_info {
            TreeInfoTbs::KeyPackage => len,
            TreeInfoTbs::Update(p) | TreeInfoTbs::Commit(p) => p.tls_serialized_len() + len,
        }
    }
}

impl TlsDeserializeTrait for LeafNodeTbs {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let payload = LeafNodePayload::tls_deserialize(bytes)?;
        let tree_info = match payload.leaf_node_source {
            LeafNodeSource::KeyPackage(_) => TreeInfoTbs::KeyPackage,
            LeafNodeSource::Update => TreeInfoTbs::Update(TreePosition::tls_deserialize(bytes)?),
            LeafNodeSource::Commit(_) => TreeInfoTbs::Commit(TreePosition::tls_deserialize(bytes)?),
        };
        Ok(Self { payload, tree_info })
    }
}

/// This struct implements the MLS leaf node.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     HPKEPublicKey encryption_key;
///     SignaturePublicKey signature_key;
///     Credential credential;
///     Capabilities capabilities;
///
///     LeafNodeSource leaf_node_source;
///     select (LeafNode.leaf_node_source) {
///         case key_package:
///             Lifetime lifetime;
///
///         case update:
///             struct{};
///
///         case commit:
///             opaque parent_hash<V>;
///     };
///
///     Extension extensions<V>;
///     /* SignWithLabel(., "LeafNodeTBS", LeafNodeTBS) */
///     opaque signature<V>;
/// } LeafNode;
/// ```
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct LeafNode {
    payload: LeafNodePayload,
    signature: Signature,
}

impl From<OpenMlsLeafNode> for LeafNode {
    fn from(leaf: OpenMlsLeafNode) -> Self {
        leaf.leaf_node
    }
}

impl LeafNode {
    /// Create a new [`LeafNode`].
    /// This first creates a `LeadNodeTbs` and returns the result of signing
    /// it.
    ///
    /// This function generates a fresh HPKE key pair for the leaf node and
    /// returns the HPKE key pair along with the new leaf node.
    /// The caller is responsible for storing the private key.
    pub(crate) fn new(
        config: CryptoConfig,
        credential_with_key: CredentialWithKey,
        leaf_node_source: LeafNodeSource,
        capabilities: Capabilities,
        extensions: Extensions,
        backend: &impl OpenMlsCryptoProvider,
        signer: &(impl ByteSigner + ?Sized),
    ) -> Result<(Self, EncryptionKeyPair), LibraryError> {
        // Create a new encryption key pair.
        let encryption_key_pair = EncryptionKeyPair::random(backend, config)?;

        let leaf_node = Self::new_with_key(
            encryption_key_pair.public_key().clone(),
            credential_with_key,
            leaf_node_source,
            capabilities,
            extensions,
            signer,
        )?;

        Ok((leaf_node, encryption_key_pair))
    }

    /// Create a new leaf node with a given HPKE encryption key pair.
    /// The key pair must be stored in the key store by the caller.
    fn new_with_key(
        encryption_key: EncryptionKey,
        credential_with_key: CredentialWithKey,
        leaf_node_source: LeafNodeSource,
        capabilities: Capabilities,
        extensions: Extensions,
        signer: &(impl ByteSigner + ?Sized),
    ) -> Result<Self, LibraryError> {
        let leaf_node_tbs = LeafNodeTbs::new(
            encryption_key,
            credential_with_key,
            capabilities,
            leaf_node_source,
            extensions,
        )?;

        leaf_node_tbs
            .sign(signer)
            .map_err(|_| LibraryError::custom("Signing failed"))
    }

    /// Generate a fresh leaf node with a fresh encryption key but otherwise
    /// the same properties as the current leaf node.
    ///
    /// The newly generated encryption key pair is stored in the key store.
    ///
    /// This function can be used when generating an update. In most other cases
    /// a leaf node should be generated as part of a new [`KeyPackage`].
    pub fn updated<KeyStore: OpenMlsKeyStore>(
        &self,
        config: CryptoConfig,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &(impl ByteSigner + ?Sized),
    ) -> Result<Self, LeafNodeGenerationError<KeyStore::Error>> {
        Self::generate(
            config,
            CredentialWithKey {
                credential: self.payload.credential.clone(),
                signature_key: self.payload.signature_key.clone(),
            },
            self.payload.capabilities.clone(),
            self.payload.extensions.clone(),
            backend,
            signer,
        )
    }

    /// Generate a fresh leaf node.
    ///
    /// This includes generating a new encryption key pair that is stored in the
    /// key store.
    ///
    /// This function can be used when generating an update. In most other cases
    /// a leaf node should be generated as part of a new [`KeyPackage`].
    pub fn generate<KeyStore: OpenMlsKeyStore>(
        config: CryptoConfig,
        credential_with_key: CredentialWithKey,
        capabilities: Capabilities,
        extensions: Extensions,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &(impl ByteSigner + ?Sized),
    ) -> Result<Self, LeafNodeGenerationError<KeyStore::Error>> {
        // Note that this function is supposed to be used in the public API only
        // because it is interacting with the key store.

        let (leaf_node, encryption_key_pair) = Self::new(
            config,
            credential_with_key,
            LeafNodeSource::Update,
            capabilities,
            extensions,
            backend,
            signer,
        )?;

        // Store the encryption key pair in the key store.
        encryption_key_pair
            .write_to_key_store(backend)
            .map_err(LeafNodeGenerationError::KeyStoreError)?;

        Ok(leaf_node)
    }

    /// Returns the `encryption_key`.
    pub(crate) fn encryption_key(&self) -> &EncryptionKey {
        &self.payload.encryption_key
    }

    /// Returns the `signature_key` as byte slice.
    pub fn signature_key(&self) -> &SignaturePublicKey {
        &self.payload.signature_key
    }

    /// Returns the `signature_key` as byte slice.
    pub fn credential(&self) -> &Credential {
        &self.payload.credential
    }

    /// Returns the `parent_hash` as byte slice or `None`.
    pub fn parent_hash(&self) -> Option<&[u8]> {
        match &self.payload.leaf_node_source {
            LeafNodeSource::Commit(ph) => Some(ph.as_slice()),
            _ => None,
        }
    }

    /// Returns the [`Lifetime`] if present.
    /// `None` otherwise.
    pub(crate) fn life_time(&self) -> Option<&Lifetime> {
        if let LeafNodeSource::KeyPackage(life_time) = &self.payload.leaf_node_source {
            Some(life_time)
        } else {
            None
        }
    }

    /// Returns a reference to the [`Signature`] of this leaf.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Return a reference to [`Capabilities`].
    pub(crate) fn capabilities(&self) -> &Capabilities {
        &self.payload.capabilities
    }

    /// Return a reference to the leaf node extensions.
    pub fn extensions(&self) -> &Extensions {
        &self.payload.extensions
    }

    // ----- Validation ----------------------------------------------------------------------------

    /// Check that all extensions that are required, are supported by this leaf
    /// node.
    pub(crate) fn validate_required_capabilities<'a>(
        &self,
        required_capabilities: impl Into<Option<&'a RequiredCapabilitiesExtension>>,
    ) -> Result<(), TreeSyncError> {
        if let Some(required_capabilities) = required_capabilities.into() {
            for required_extension in required_capabilities.extension_types() {
                if !self.supports_extension(required_extension) {
                    return Err(TreeSyncError::UnsupportedExtension);
                }
            }
            for required_proposal in required_capabilities.proposal_types() {
                if !self.supports_proposal(required_proposal) {
                    return Err(TreeSyncError::UnsupportedProposal);
                }
            }
        }
        Ok(())
    }

    /// Returns `true` if the [`ExtensionType`] is supported by this leaf node.
    pub(crate) fn supports_extension(&self, extension_type: &ExtensionType) -> bool {
        self.payload
            .capabilities
            .extensions
            .iter()
            .any(|et| et == extension_type)
            || default_extensions().iter().any(|et| et == extension_type)
    }

    /// Returns `true` if the [`ProposalType`] is supported by this leaf node.
    pub(crate) fn supports_proposal(&self, proposal_type: &ProposalType) -> bool {
        self.payload
            .capabilities
            .proposals
            .iter()
            .any(|pt| pt == proposal_type)
            || default_proposals().iter().any(|pt| pt == proposal_type)
    }
}

impl LeafNode {
    /// Expose [`new_with_key`] for tests.
    #[cfg(test)]
    pub(crate) fn create_new_with_key(
        encryption_key: EncryptionKey,
        credential_with_key: CredentialWithKey,
        leaf_node_source: LeafNodeSource,
        capabilities: Capabilities,
        extensions: Extensions,
        signer: &(impl ByteSigner + ?Sized),
    ) -> Result<Self, LibraryError> {
        Self::new_with_key(
            encryption_key,
            credential_with_key,
            leaf_node_source,
            capabilities,
            extensions,
            signer,
        )
    }

    /// Replace the credential in the KeyPackage.
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn set_credential(&mut self, credential: Credential) {
        self.payload.credential = credential;
    }

    /// Return a mutable reference to [`Capabilities`].
    #[cfg(test)]
    pub fn capabilities_mut(&mut self) -> &mut Capabilities {
        &mut self.payload.capabilities
    }

    /// Check whether the this leaf node supports all the required extensions
    /// in the provided list.
    #[cfg(test)]
    pub(crate) fn check_extension_support(
        &self,
        extensions: &[ExtensionType],
    ) -> Result<(), TreeSyncError> {
        for required in extensions.iter() {
            if !self.supports_extension(required) {
                return Err(TreeSyncError::UnsupportedExtension);
            }
        }
        Ok(())
    }
}

const LEAF_NODE_SIGNATURE_LABEL: &str = "LeafNodeTBS";

impl Signable for LeafNodeTbs {
    type SignedOutput = LeafNode;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }

    fn label(&self) -> &str {
        LEAF_NODE_SIGNATURE_LABEL
    }
}

impl SignedStruct<LeafNodeTbs> for LeafNode {
    fn from_payload(tbs: LeafNodeTbs, signature: Signature) -> Self {
        Self {
            payload: tbs.payload,
            signature,
        }
    }
}

/// Helper struct to verify incoming leaf nodes.
/// The [`LeafNode`] doesn't have all the information needed to verify.
/// In particular is the [`TreeInfoTbs`] missing.
pub(crate) struct VerifiableLeafNodeTbs<'a> {
    pub(crate) tbs: &'a LeafNodeTbs,
    pub(crate) signature: &'a Signature,
}

impl<'a> Verifiable for VerifiableLeafNodeTbs<'a> {
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tbs.tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        self.signature
    }

    fn label(&self) -> &str {
        LEAF_NODE_SIGNATURE_LABEL
    }
}

impl LeafNodeTbs {
    /// Build a [`LeafNodeTbs`] from a [`LeafNode`] and a [`TreeInfoTbs`]
    /// to update a leaf node.
    pub(crate) fn from(leaf_node: LeafNode, tree_info: TreeInfoTbs) -> Self {
        Self {
            payload: leaf_node.payload,
            tree_info,
        }
    }

    /// Build a new [`LeafNodeTbs`] from a [`KeyPackage`] and [`Credential`].
    /// To get the [`LeafNode`] call [`LeafNode::sign`].
    pub(crate) fn new(
        encryption_key: EncryptionKey,
        credential_with_key: CredentialWithKey,
        capabilities: Capabilities,
        leaf_node_source: LeafNodeSource,
        extensions: Extensions,
    ) -> Result<Self, LibraryError> {
        let payload = LeafNodePayload {
            encryption_key,
            signature_key: credential_with_key.signature_key,
            credential: credential_with_key.credential,
            capabilities,
            leaf_node_source,
            extensions,
        };
        let tree_info = TreeInfoTbs::KeyPackage;
        let tbs = LeafNodeTbs { payload, tree_info };
        Ok(tbs)
    }
}

/// The OpenMLS wrapper for the [`LeafNode`] that holds additional information
/// that we need:
/// * the HPKE private key for to the public key that's in the [`LeafNode`].
/// * the leaf index of the [`LeafNode`].
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct OpenMlsLeafNode {
    pub(in crate::treesync) leaf_node: LeafNode,
    leaf_index: Option<LeafNodeIndex>,
}

impl From<LeafNode> for OpenMlsLeafNode {
    fn from(leaf_node: LeafNode) -> Self {
        Self {
            leaf_node,
            leaf_index: None,
        }
    }
}

impl From<KeyPackage> for OpenMlsLeafNode {
    fn from(key_package: KeyPackage) -> Self {
        Self {
            leaf_node: key_package.leaf_node().clone(),
            leaf_index: None,
        }
    }
}

impl OpenMlsLeafNode {
    /// Generate a new [`OpenMlsLeafNode`] for a new tree.
    pub(crate) fn new(
        config: CryptoConfig,
        leaf_node_source: LeafNodeSource,
        backend: &impl OpenMlsCryptoProvider,
        signer: &(impl ByteSigner + ?Sized),
        credential_with_key: CredentialWithKey,
        capabilities: Capabilities,
        extensions: Extensions,
    ) -> Result<(Self, EncryptionKeyPair), LibraryError> {
        let (leaf_node, encryption_key_pair) = LeafNode::new(
            config,
            credential_with_key,
            leaf_node_source,
            capabilities,
            extensions,
            backend,
            signer,
        )?;

        Ok((
            Self {
                leaf_node,
                leaf_index: Some(LeafNodeIndex::new(0)),
            },
            encryption_key_pair,
        ))
    }

    /// Return a reference to the `encryption_key` of this [`LeafNode`].
    pub(crate) fn public_key(&self) -> &HpkePublicKey {
        self.leaf_node.payload.encryption_key.key()
    }

    /// Update the `encryption_key` in this leaf node and re-signs it.
    ///
    /// Optionally, a new leaf node can be provided to update more values such as
    /// the credential.
    pub(crate) fn update_and_re_sign(
        &mut self,
        new_encryption_key: impl Into<Option<EncryptionKey>>,
        leaf_node: impl Into<Option<LeafNode>>,
        group_id: GroupId,
        signer: &(impl ByteSigner + ?Sized),
    ) -> Result<(), PublicTreeError> {
        let tree_info = self.update_tree_info(group_id)?;
        // TODO: If we could take out the leaf_node without cloning, this would all be nicer.
        let mut leaf_node_tbs = LeafNodeTbs::from(self.leaf_node.clone(), tree_info);

        // Update credential
        // ValSem109 check that the identity is the same.
        if let Some(leaf_node) = leaf_node.into() {
            if leaf_node.credential().identity() != leaf_node_tbs.payload.credential.identity() {
                return Err(PublicTreeError::IdentityMismatch);
            }
            leaf_node_tbs.payload.credential = leaf_node.credential().clone();
            leaf_node_tbs.payload.encryption_key = leaf_node.encryption_key().clone();
        }

        if let Some(new_encryption_key) = new_encryption_key.into() {
            // If there's no new leaf, the encryption key must be provided
            // explicitly.
            leaf_node_tbs.payload.encryption_key = new_encryption_key;
        } else {
            return Err(LibraryError::custom(
                    "update_and_re_sign needs to be called with a new leaf node or a new encryption key. Neither was the case.").into());
        }

        // Set the new signed leaf node with the new encryption key
        self.leaf_node = leaf_node_tbs.sign(signer)?;
        Ok(())
    }

    /// Replace the encryption key in this leaf with a random one.
    ///
    /// This signs the new leaf node as well.
    pub(crate) fn rekey(
        &mut self,
        group_id: &GroupId,
        ciphersuite: Ciphersuite,
        protocol_version: ProtocolVersion,
        backend: &impl OpenMlsCryptoProvider,
        signer: &(impl ByteSigner + ?Sized),
    ) -> Result<EncryptionKeyPair, PublicTreeError> {
        if !self
            .leaf_node
            .payload
            .capabilities
            .ciphersuites
            .contains(&ciphersuite)
            || !self
                .leaf_node
                .payload
                .capabilities
                .versions
                .contains(&protocol_version)
        {
            debug_assert!(
                false,
                "Ciphersuite or protocol version is not supported by this leaf node.\
                 \ncapabilities: {:?}\nprotocol version: {:?}\nciphersuite: {:?}",
                self.leaf_node.payload.capabilities, protocol_version, ciphersuite
            );
            return Err(LibraryError::custom(
                "Ciphersuite or protocol version is not supported by this leaf node.",
            )
            .into());
        }
        let key_pair = EncryptionKeyPair::random(
            backend,
            CryptoConfig {
                ciphersuite,
                version: protocol_version,
            },
        )?;

        self.update_and_re_sign(
            key_pair.public_key().clone(),
            None,
            group_id.clone(),
            signer,
        )?;

        Ok(key_pair)
    }

    /// Create the [`TreeInfoTbs`] for an update for this leaf.
    fn update_tree_info(&self, group_id: GroupId) -> Result<TreeInfoTbs, LibraryError> {
        debug_assert!(
            self.leaf_index.is_some(),
            "TreeInfoTbs for Update can't be created without a leaf index. \
             Leaf identity: {:?} ({})",
            self.leaf_node().credential().identity(),
            String::from_utf8(self.leaf_node().credential().identity().to_vec())
                .unwrap_or_default()
        );
        self.leaf_index
            .map(|leaf_index| {
                TreeInfoTbs::Update(TreePosition {
                    group_id,
                    leaf_index,
                })
            })
            .ok_or_else(|| {
                LibraryError::custom(
                    "TreeInfoTbs for Update can't be created without a leaf index.",
                )
            })
    }

    /// Get a reference to the leaf's [`Credential`].
    pub(crate) fn credential(&self) -> &Credential {
        self.leaf_node.credential()
    }

    /// Get a reference to the leaf's signature key.
    pub(crate) fn signature_key(&self) -> &SignaturePublicKey {
        self.leaf_node.signature_key()
    }

    /// Get a clone of this [`OpenMlsLeafNode`] without the private information.
    pub(in crate::treesync) fn clone_public(&self) -> Self {
        Self {
            leaf_node: self.leaf_node.clone(),
            leaf_index: None,
        }
    }

    /// Get the [`LeafNode`] as reference.
    pub(crate) fn leaf_node(&self) -> &LeafNode {
        &self.leaf_node
    }

    /// Update the parent hash of this [`LeafNode`].
    ///
    /// This re-signs the leaf node.
    pub(in crate::treesync) fn update_parent_hash(
        &mut self,
        parent_hash: &[u8],
        group_id: GroupId,
        signer: &(impl ByteSigner + ?Sized),
    ) -> Result<(), LibraryError> {
        self.leaf_node.payload.leaf_node_source = LeafNodeSource::Commit(parent_hash.into());
        let tbs = LeafNodeTbs::from(
            self.leaf_node.clone(), // TODO: With a better setup we wouldn't have to clone here.
            TreeInfoTbs::Commit(TreePosition {
                group_id,
                leaf_index: self
                    .leaf_index
                    .ok_or_else(|| LibraryError::custom("Missing leaf index in own leaf"))?,
            }),
        );
        self.leaf_node = tbs
            .sign(signer)
            .map_err(|_| LibraryError::custom("Signing failed"))?;

        Ok(())
    }

    /// Check that all extensions that are required, are supported by this leaf
    /// node.
    #[cfg(test)]
    pub(crate) fn validate_required_capabilities<'a>(
        &self,
        required_capabilities: impl Into<Option<&'a RequiredCapabilitiesExtension>>,
    ) -> Result<(), TreeSyncError> {
        self.leaf_node
            .validate_required_capabilities(required_capabilities)
    }

    /// Returns a reference to the encryption key of the leaf node.
    pub(crate) fn encryption_key(&self) -> &EncryptionKey {
        self.leaf_node.encryption_key()
    }

    /// Replace the public key in the leaf node and re-sign.
    #[cfg(any(feature = "test-utils", test))]
    pub fn set_public_key(&mut self, public_key: HpkePublicKey, signer: &(impl ByteSigner + ?Sized)) {
        let mut tbs = LeafNodeTbs::from(self.leaf_node.clone(), TreeInfoTbs::KeyPackage);
        tbs.payload.encryption_key = public_key.into();
        self.leaf_node = tbs.sign(signer).unwrap();
    }

    /// Set the leaf index for this leaf.
    pub fn set_leaf_index(&mut self, leaf_index: LeafNodeIndex) {
        self.leaf_index = Some(leaf_index);
    }

    /// Generate a leaf from a [`LeafNode`] and the leaf index.
    #[cfg(test)]
    pub(crate) fn from_leaf_node(
        backend: &impl OpenMlsCryptoProvider,
        leaf_index: LeafNodeIndex,
        leaf_node: LeafNode,
    ) -> (Self, EncryptionKeyPair) {
        // Get the encryption key pair from the leaf.
        let encryption_key_pair =
            EncryptionKeyPair::read_from_key_store(backend, leaf_node.encryption_key()).unwrap();

        (
            Self {
                leaf_node,
                leaf_index: Some(leaf_index),
            },
            encryption_key_pair,
        )
    }

    /// Get a list of supported cipher suites.
    pub fn ciphersuites(&self) -> &[Ciphersuite] {
        &self.leaf_node.payload.capabilities.ciphersuites
    }
}
