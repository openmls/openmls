//! This module contains the [`LeafNode`] struct and its implementation.
use openmls_traits::{
    crypto::OpenMlsCrypto, random::OpenMlsRand, signatures::Signer, types::Ciphersuite,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tls_codec::{
    Serialize as TlsSerializeTrait, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
    VLBytes,
};

use super::encryption_keys::{EncryptionKey, EncryptionKeyPair};
use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    ciphersuite::{
        signable::{Signable, SignedStruct, Verifiable, VerifiedStruct},
        Signature, SignaturePublicKey,
    },
    credentials::{Credential, CredentialType, CredentialWithKey},
    error::LibraryError,
    extensions::{ExtensionType, Extensions},
    group::GroupId,
    key_packages::{KeyPackage, Lifetime},
    prelude::KeyPackageBundle,
    storage::OpenMlsProvider,
};

use crate::treesync::errors::LeafNodeValidationError;

mod capabilities;
mod codec;

pub use capabilities::*;

pub(crate) struct NewLeafNodeParams {
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) credential_with_key: CredentialWithKey,
    pub(crate) leaf_node_source: LeafNodeSource,
    pub(crate) capabilities: Capabilities,
    pub(crate) extensions: Extensions,
    pub(crate) tree_info_tbs: TreeInfoTbs,
}

/// Set of LeafNode parameters that are used when regenerating a LeafNodes
/// during an update operation.
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct UpdateLeafNodeParams {
    pub(crate) credential_with_key: CredentialWithKey,
    pub(crate) capabilities: Capabilities,
    pub(crate) extensions: Extensions,
}

impl UpdateLeafNodeParams {
    #[cfg(test)]
    pub(crate) fn derive(leaf_node: &LeafNode) -> Self {
        Self {
            credential_with_key: CredentialWithKey {
                credential: leaf_node.payload.credential.clone(),
                signature_key: leaf_node.payload.signature_key.clone(),
            },
            capabilities: leaf_node.payload.capabilities.clone(),
            extensions: leaf_node.payload.extensions.clone(),
        }
    }
}

/// Parameters for a leaf node that can be chosen by the application.
#[derive(Debug, PartialEq, Clone, Default)]
pub struct LeafNodeParameters {
    credential_with_key: Option<CredentialWithKey>,
    capabilities: Option<Capabilities>,
    extensions: Option<Extensions>,
}

impl LeafNodeParameters {
    /// Create a new [`LeafNodeParametersBuilder`].
    pub fn builder() -> LeafNodeParametersBuilder {
        LeafNodeParametersBuilder::default()
    }

    /// Returns the credential with key.
    pub fn credential_with_key(&self) -> Option<&CredentialWithKey> {
        self.credential_with_key.as_ref()
    }

    /// Returns the capabilities.
    pub fn capabilities(&self) -> Option<&Capabilities> {
        self.capabilities.as_ref()
    }

    /// Returns the extensions.
    pub fn extensions(&self) -> Option<&Extensions> {
        self.extensions.as_ref()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.credential_with_key.is_none()
            && self.capabilities.is_none()
            && self.extensions.is_none()
    }
}

/// Builder for [`LeafNodeParameters`].
#[derive(Debug, Default)]
pub struct LeafNodeParametersBuilder {
    credential_with_key: Option<CredentialWithKey>,
    capabilities: Option<Capabilities>,
    extensions: Option<Extensions>,
}

impl LeafNodeParametersBuilder {
    /// Set the credential with key.
    pub fn with_credential_with_key(mut self, credential_with_key: CredentialWithKey) -> Self {
        self.credential_with_key = Some(credential_with_key);
        self
    }

    /// Set the capabilities.
    pub fn with_capabilities(mut self, capabilities: Capabilities) -> Self {
        self.capabilities = Some(capabilities);
        self
    }

    /// Set the extensions.
    pub fn with_extensions(mut self, extensions: Extensions) -> Self {
        self.extensions = Some(extensions);
        self
    }

    /// Build the [`LeafNodeParameters`].
    pub fn build(self) -> LeafNodeParameters {
        LeafNodeParameters {
            credential_with_key: self.credential_with_key,
            capabilities: self.capabilities,
            extensions: self.extensions,
        }
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
// TODO(#1242): Do not derive `TlsDeserialize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub struct LeafNode {
    payload: LeafNodePayload,
    signature: Signature,
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
        provider: &impl OpenMlsProvider,
        signer: &impl Signer,
        new_leaf_node_params: NewLeafNodeParams,
    ) -> Result<(Self, EncryptionKeyPair), LibraryError> {
        let NewLeafNodeParams {
            ciphersuite,
            credential_with_key,
            leaf_node_source,
            capabilities,
            extensions,
            tree_info_tbs,
        } = new_leaf_node_params;

        // Create a new encryption key pair.
        let encryption_key_pair =
            EncryptionKeyPair::random(provider.rand(), provider.crypto(), ciphersuite)?;

        let leaf_node = Self::new_with_key(
            encryption_key_pair.public_key().clone(),
            credential_with_key,
            leaf_node_source,
            capabilities,
            extensions,
            tree_info_tbs,
            signer,
        )?;

        Ok((leaf_node, encryption_key_pair))
    }

    /// Creates a new placeholder [`LeafNode`] that is used to build external
    /// commits.
    ///
    /// Note: This is not a valid leaf node and it must be rekeyed and signed
    /// before it can be used.
    pub(crate) fn new_placeholder() -> Self {
        let payload = LeafNodePayload {
            encryption_key: EncryptionKey::from(Vec::new()),
            signature_key: Vec::new().into(),
            credential: Credential::new(CredentialType::Basic, Vec::new()),
            capabilities: Capabilities::default(),
            leaf_node_source: LeafNodeSource::Update,
            extensions: Extensions::default(),
        };

        Self {
            payload,
            signature: Vec::new().into(),
        }
    }

    /// Create a new leaf node with a given HPKE encryption key pair.
    /// The key pair must be stored in the key store by the caller.
    fn new_with_key(
        encryption_key: EncryptionKey,
        credential_with_key: CredentialWithKey,
        leaf_node_source: LeafNodeSource,
        capabilities: Capabilities,
        extensions: Extensions,
        tree_info_tbs: TreeInfoTbs,
        signer: &impl Signer,
    ) -> Result<Self, LibraryError> {
        let leaf_node_tbs = LeafNodeTbs::new(
            encryption_key,
            credential_with_key,
            capabilities,
            leaf_node_source,
            extensions,
            tree_info_tbs,
        );

        leaf_node_tbs
            .sign(signer)
            .map_err(|_| LibraryError::custom("Signing failed"))
    }

    /// New [`LeafNode`] with a parent hash.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::treesync) fn new_with_parent_hash(
        rand: &impl OpenMlsRand,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        parent_hash: &[u8],
        leaf_node_params: UpdateLeafNodeParams,
        group_id: GroupId,
        leaf_index: LeafNodeIndex,
        signer: &impl Signer,
    ) -> Result<(Self, EncryptionKeyPair), LibraryError> {
        let encryption_key_pair = EncryptionKeyPair::random(rand, crypto, ciphersuite)?;

        let leaf_node_tbs = LeafNodeTbs::new(
            encryption_key_pair.public_key().clone(),
            leaf_node_params.credential_with_key,
            leaf_node_params.capabilities,
            LeafNodeSource::Commit(parent_hash.into()),
            leaf_node_params.extensions,
            TreeInfoTbs::Commit(TreePosition {
                group_id,
                leaf_index,
            }),
        );

        // Sign the leaf node
        let leaf_node = leaf_node_tbs
            .sign(signer)
            .map_err(|_| LibraryError::custom("Signing failed"))?;

        Ok((leaf_node, encryption_key_pair))
    }

    /// Generate a fresh leaf node.
    ///
    /// This includes generating a new encryption key pair that is stored in the
    /// key store.
    ///
    /// This function can be used when generating an update. In most other cases
    /// a leaf node should be generated as part of a new [`KeyPackage`].
    #[cfg(test)]
    pub(crate) fn generate_update<Provider: OpenMlsProvider>(
        ciphersuite: Ciphersuite,
        credential_with_key: CredentialWithKey,
        capabilities: Capabilities,
        extensions: Extensions,
        tree_info_tbs: TreeInfoTbs,
        provider: &Provider,
        signer: &impl Signer,
    ) -> Result<Self, LeafNodeGenerationError<Provider::StorageError>> {
        // Note that this function is supposed to be used in the public API only
        // because it is interacting with the key store.

        let new_leaf_node_params = NewLeafNodeParams {
            ciphersuite,
            credential_with_key,
            leaf_node_source: LeafNodeSource::Update,
            capabilities,
            extensions,
            tree_info_tbs,
        };

        let (leaf_node, encryption_key_pair) = Self::new(provider, signer, new_leaf_node_params)?;

        // Store the encryption key pair in the key store.
        encryption_key_pair
            .write(provider.storage())
            .map_err(LeafNodeGenerationError::StorageError)?;

        Ok(leaf_node)
    }

    /// Update a leaf node.
    ///
    /// This function generates a new encryption key pair that is stored in the
    /// key store and also returned.
    ///
    /// This function can be used when generating an update. In most other cases
    /// a leaf node should be generated as part of a new [`KeyPackage`].
    pub(crate) fn update<Provider: OpenMlsProvider>(
        &mut self,
        ciphersuite: Ciphersuite,
        provider: &Provider,
        signer: &impl Signer,
        group_id: GroupId,
        leaf_index: LeafNodeIndex,
        leaf_node_parmeters: LeafNodeParameters,
    ) -> Result<EncryptionKeyPair, LeafNodeUpdateError<Provider::StorageError>> {
        let tree_info = TreeInfoTbs::Update(TreePosition::new(group_id, leaf_index));
        let mut leaf_node_tbs = LeafNodeTbs::from(self.clone(), tree_info);

        // Update credential
        if let Some(credential_with_key) = leaf_node_parmeters.credential_with_key {
            leaf_node_tbs.payload.credential = credential_with_key.credential;
            leaf_node_tbs.payload.signature_key = credential_with_key.signature_key;
        }

        // Update extensions
        if let Some(extensions) = leaf_node_parmeters.extensions {
            leaf_node_tbs.payload.extensions = extensions;
        }

        // Update capabilities
        if let Some(capabilities) = leaf_node_parmeters.capabilities {
            leaf_node_tbs.payload.capabilities = capabilities;
        }

        // Create a new encryption key pair
        let encryption_key_pair =
            EncryptionKeyPair::random(provider.rand(), provider.crypto(), ciphersuite)?;
        leaf_node_tbs.payload.encryption_key = encryption_key_pair.public_key().clone();

        // Store the encryption key pair in the key store.
        encryption_key_pair
            .write(provider.storage())
            .map_err(LeafNodeUpdateError::Storage)?;

        // Set the leaf node source to update
        leaf_node_tbs.payload.leaf_node_source = LeafNodeSource::Update;

        // Sign the leaf node
        let leaf_node = leaf_node_tbs.sign(signer)?;
        self.payload = leaf_node.payload;
        self.signature = leaf_node.signature;

        Ok(encryption_key_pair)
    }

    /// Returns the `encryption_key`.
    pub fn encryption_key(&self) -> &EncryptionKey {
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
    pub fn capabilities(&self) -> &Capabilities {
        &self.payload.capabilities
    }

    /// Return a reference to the leaf node source.
    pub fn leaf_node_source(&self) -> &LeafNodeSource {
        &self.payload.leaf_node_source
    }

    /// Return a reference to the leaf node extensions.
    pub fn extensions(&self) -> &Extensions {
        &self.payload.extensions
    }

    /// Returns `true` if the [`ExtensionType`] is supported by this leaf node.
    pub(crate) fn supports_extension(&self, extension_type: &ExtensionType) -> bool {
        extension_type.is_default()
            || self
                .payload
                .capabilities
                .extensions
                .contains(extension_type)
    }

    /// Check whether the this leaf node supports all the required extensions
    /// in the provided list.
    pub(crate) fn check_extension_support(
        &self,
        extensions: &[ExtensionType],
    ) -> Result<(), LeafNodeValidationError> {
        for required in extensions.iter() {
            if !self.supports_extension(required) {
                log::error!(
                    "Leaf node does not support required extension {:?}\n
                    Supported extensions: {:?}",
                    required,
                    self.payload.capabilities.extensions
                );
                return Err(LeafNodeValidationError::UnsupportedExtensions);
            }
        }
        Ok(())
    }

    /// Perform all checks that can be done without further context:
    /// - the used extensions are not known to be invalid in leaf nodes
    /// - the types of the used extensions are covered by the capabilities
    /// - the type of the credential is coveered by the capabilities
    pub(crate) fn validate_locally(&self) -> Result<(), LeafNodeValidationError> {
        // Check that no extension is invalid when used in leaf nodes.
        let invalid_extension_types = self
            .extensions()
            .iter()
            .filter(|ext| ext.extension_type().is_valid_in_leaf_node() == Some(false))
            .collect::<Vec<_>>();
        if !invalid_extension_types.is_empty() {
            log::error!(
                "Invalid extension used in leaf node: {:?}",
                invalid_extension_types
            );
            return Err(LeafNodeValidationError::UnsupportedExtensions);
        }

        // Check that all extensions are contained in the capabilities.
        if !self.capabilities().contains_extensions(self.extensions()) {
            log::error!(
                "Leaf node does not support all extensions it uses\n
                Supported extensions: {:?}\n
                Used extensions: {:?}",
                self.payload.capabilities.extensions,
                self.extensions()
            );
            return Err(LeafNodeValidationError::UnsupportedExtensions);
        }

        // Check that the capabilities contain the leaf node's credential type.
        if !self
            .capabilities()
            .contains_credential(self.credential().credential_type())
        {
            return Err(LeafNodeValidationError::UnsupportedCredentials);
        }

        Ok(())
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
struct LeafNodePayload {
    encryption_key: EncryptionKey,
    signature_key: SignaturePublicKey,
    credential: Credential,
    capabilities: Capabilities,
    leaf_node_source: LeafNodeSource,
    extensions: Extensions,
}

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
#[repr(u8)]
pub enum LeafNodeSource {
    #[tls_codec(discriminant = 1)]
    KeyPackage(Lifetime),
    Update,
    Commit(ParentHash),
}

pub type ParentHash = VLBytes;

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
///     // ... continued in [`TreeInfo`] ...
/// } LeafNodeTBS;
/// ```
#[derive(Debug, TlsSerialize, TlsSize)]
pub struct LeafNodeTbs {
    payload: LeafNodePayload,
    tree_info_tbs: TreeInfoTbs,
}

impl LeafNodeTbs {
    /// Build a [`LeafNodeTbs`] from a [`LeafNode`] and a [`TreeInfo`]
    /// to update a leaf node.
    pub(crate) fn from(leaf_node: LeafNode, tree_info_tbs: TreeInfoTbs) -> Self {
        Self {
            payload: leaf_node.payload,
            tree_info_tbs,
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
        tree_info_tbs: TreeInfoTbs,
    ) -> Self {
        let payload = LeafNodePayload {
            encryption_key,
            signature_key: credential_with_key.signature_key,
            credential: credential_with_key.credential,
            capabilities,
            leaf_node_source,
            extensions,
        };

        LeafNodeTbs {
            payload,
            tree_info_tbs,
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsSize)]
pub(crate) struct TreePosition {
    group_id: GroupId,
    leaf_index: LeafNodeIndex,
}

impl TreePosition {
    pub(crate) fn new(group_id: GroupId, leaf_index: LeafNodeIndex) -> Self {
        Self {
            group_id,
            leaf_index,
        }
    }

    #[cfg(feature = "test-utils")]
    pub(crate) fn into_parts(self) -> (GroupId, LeafNodeIndex) {
        (self.group_id, self.leaf_index)
    }
}

const LEAF_NODE_SIGNATURE_LABEL: &str = "LeafNodeTBS";

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
pub struct LeafNodeIn {
    payload: LeafNodePayload,
    signature: Signature,
}

impl LeafNodeIn {
    pub(crate) fn into_verifiable_leaf_node(self) -> VerifiableLeafNode {
        match self.payload.leaf_node_source {
            LeafNodeSource::KeyPackage(_) => {
                let verifiable = VerifiableKeyPackageLeafNode {
                    payload: self.payload,
                    signature: self.signature,
                };
                VerifiableLeafNode::KeyPackage(verifiable)
            }
            LeafNodeSource::Update => {
                let verifiable = VerifiableUpdateLeafNode {
                    payload: self.payload,
                    signature: self.signature,
                    tree_position: None,
                };
                VerifiableLeafNode::Update(verifiable)
            }
            LeafNodeSource::Commit(_) => {
                let verifiable = VerifiableCommitLeafNode {
                    payload: self.payload,
                    signature: self.signature,
                    tree_position: None,
                };
                VerifiableLeafNode::Commit(verifiable)
            }
        }
    }

    /// Returns the `signature_key` as byte slice.
    pub fn signature_key(&self) -> &SignaturePublicKey {
        &self.payload.signature_key
    }

    /// Returns the `signature_key` as byte slice.
    pub fn credential(&self) -> &Credential {
        &self.payload.credential
    }
}

impl From<LeafNode> for LeafNodeIn {
    fn from(leaf_node: LeafNode) -> Self {
        Self {
            payload: leaf_node.payload,
            signature: leaf_node.signature,
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<LeafNodeIn> for LeafNode {
    fn from(deserialized: LeafNodeIn) -> Self {
        Self {
            payload: deserialized.payload,
            signature: deserialized.signature,
        }
    }
}

impl From<KeyPackage> for LeafNode {
    fn from(key_package: KeyPackage) -> Self {
        key_package.leaf_node().clone()
    }
}

impl From<KeyPackageBundle> for LeafNode {
    fn from(key_package: KeyPackageBundle) -> Self {
        key_package.key_package().leaf_node().clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerifiableLeafNode {
    KeyPackage(VerifiableKeyPackageLeafNode),
    Update(VerifiableUpdateLeafNode),
    Commit(VerifiableCommitLeafNode),
}

impl VerifiableLeafNode {
    pub(crate) fn signature_key(&self) -> &SignaturePublicKey {
        match self {
            VerifiableLeafNode::KeyPackage(v) => v.signature_key(),
            VerifiableLeafNode::Update(v) => v.signature_key(),
            VerifiableLeafNode::Commit(v) => v.signature_key(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiableKeyPackageLeafNode {
    payload: LeafNodePayload,
    signature: Signature,
}

impl VerifiableKeyPackageLeafNode {
    pub(crate) fn signature_key(&self) -> &SignaturePublicKey {
        &self.payload.signature_key
    }
}

// https://validation.openmls.tech/#valn0102
impl Verifiable for VerifiableKeyPackageLeafNode {
    type VerifiedStruct = LeafNode;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.payload.tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn label(&self) -> &str {
        LEAF_NODE_SIGNATURE_LABEL
    }

    fn verify(
        self,
        crypto: &impl openmls_traits::crypto::OpenMlsCrypto,
        pk: &crate::ciphersuite::OpenMlsSignaturePublicKey,
    ) -> Result<Self::VerifiedStruct, crate::ciphersuite::signable::SignatureError> {
        self.verify_no_out(crypto, pk)?;
        Ok(LeafNode {
            payload: self.payload,
            signature: self.signature,
        })
    }
}

impl VerifiedStruct for LeafNode {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiableUpdateLeafNode {
    payload: LeafNodePayload,
    signature: Signature,
    tree_position: Option<TreePosition>,
}

impl VerifiableUpdateLeafNode {
    pub(crate) fn add_tree_position(&mut self, tree_info: TreePosition) {
        self.tree_position = Some(tree_info);
    }

    pub(crate) fn signature_key(&self) -> &SignaturePublicKey {
        &self.payload.signature_key
    }
}

impl Verifiable for VerifiableUpdateLeafNode {
    type VerifiedStruct = LeafNode;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        let tree_info_tbs = match &self.tree_position {
            Some(tree_position) => TreeInfoTbs::Commit(tree_position.clone()),
            None => return Err(tls_codec::Error::InvalidInput),
        };
        let leaf_node_tbs = LeafNodeTbs {
            payload: self.payload.clone(),
            tree_info_tbs,
        };
        leaf_node_tbs.tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn label(&self) -> &str {
        LEAF_NODE_SIGNATURE_LABEL
    }

    fn verify(
        self,
        crypto: &impl openmls_traits::crypto::OpenMlsCrypto,
        pk: &crate::ciphersuite::OpenMlsSignaturePublicKey,
    ) -> Result<Self::VerifiedStruct, crate::ciphersuite::signable::SignatureError> {
        self.verify_no_out(crypto, pk)?;
        Ok(LeafNode {
            payload: self.payload,
            signature: self.signature,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiableCommitLeafNode {
    payload: LeafNodePayload,
    signature: Signature,
    tree_position: Option<TreePosition>,
}

impl VerifiableCommitLeafNode {
    pub(crate) fn add_tree_position(&mut self, tree_info: TreePosition) {
        self.tree_position = Some(tree_info);
    }

    pub(crate) fn signature_key(&self) -> &SignaturePublicKey {
        &self.payload.signature_key
    }
}

impl Verifiable for VerifiableCommitLeafNode {
    type VerifiedStruct = LeafNode;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        let tree_info_tbs = match &self.tree_position {
            Some(tree_position) => TreeInfoTbs::Commit(tree_position.clone()),
            None => return Err(tls_codec::Error::InvalidInput),
        };
        let leaf_node_tbs = LeafNodeTbs {
            payload: self.payload.clone(),
            tree_info_tbs,
        };

        leaf_node_tbs.tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn label(&self) -> &str {
        LEAF_NODE_SIGNATURE_LABEL
    }

    fn verify(
        self,
        crypto: &impl openmls_traits::crypto::OpenMlsCrypto,
        pk: &crate::ciphersuite::OpenMlsSignaturePublicKey,
    ) -> Result<Self::VerifiedStruct, crate::ciphersuite::signable::SignatureError> {
        self.verify_no_out(crypto, pk)?;
        Ok(LeafNode {
            payload: self.payload,
            signature: self.signature,
        })
    }
}

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

#[cfg(test)]
#[derive(Error, Debug, PartialEq, Clone)]
pub enum LeafNodeGenerationError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),

    /// Error storing leaf private key in storage.
    #[error("Error storing leaf private key.")]
    StorageError(StorageError),
}

/// Leaf Node Update Error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum LeafNodeUpdateError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),

    /// Error storing leaf private key in storage.
    #[error("Error storing leaf private key.")]
    Storage(StorageError),

    /// Signature error.
    #[error(transparent)]
    Signature(#[from] crate::ciphersuite::signable::SignatureError),
}
