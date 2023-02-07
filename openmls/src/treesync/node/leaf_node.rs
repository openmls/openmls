//! This module contains the [`LeafNode`] struct and its implementation.
use openmls_traits::{
    key_store::OpenMlsKeyStore, signatures::Signer, types::Ciphersuite, OpenMlsCryptoProvider,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tls_codec::{Serialize as TlsSerializeTrait, TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    ciphersuite::{
        signable::{Signable, SignedStruct, Verifiable},
        HpkePublicKey, Signature, SignaturePublicKey,
    },
    credentials::{Credential, CredentialType, CredentialWithKey},
    error::LibraryError,
    extensions::{Extension, ExtensionType, Extensions, RequiredCapabilitiesExtension},
    group::{config::CryptoConfig, CoreGroup, GroupId},
    key_packages::KeyPackage,
    messages::proposals::ProposalType,
    prelude::PublicTreeError,
    treesync::errors::{LeafNodeValidationError, LifetimeError},
    versions::ProtocolVersion,
};

use super::encryption_keys::{EncryptionKey, EncryptionKeyPair};

mod capabilities;
mod codec;
mod lifetime;

pub use capabilities::*;
pub use lifetime::Lifetime;

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
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
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
        config: CryptoConfig,
        credential_with_key: CredentialWithKey,
        leaf_node_source: LeafNodeSource,
        capabilities: Capabilities,
        extensions: Extensions,
        backend: &impl OpenMlsCryptoProvider,
        signer: &impl Signer,
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
        signer: &impl Signer,
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
    #[cfg(test)]
    pub(crate) fn updated<KeyStore: OpenMlsKeyStore>(
        &self,
        config: CryptoConfig,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
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
        signer: &impl Signer,
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

    /// Validate the leaf node in the context of a key package.
    ///
    /// Basic:
    /// * ValSems from [`LeafNode::validate`]
    ///
    /// In key package:
    /// * ValSem306
    /// * ValSem307
    /// * ValSem308
    pub(crate) fn validate_in_key_package<'a>(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        group: &CoreGroup,
        exclude_signature_public_keys: &[SignaturePublicKey],
    ) -> Result<&Self, LeafNodeValidationError> {
        self.validate(
            backend,
            group,
            TreeInfoTbs::key_package(),
            exclude_signature_public_keys,
        )?;

        // ValSem306
        match self.payload.leaf_node_source {
            LeafNodeSource::KeyPackage(lifetime) => {
                // ValSem307
                if !lifetime.has_acceptable_range() {
                    return Err(LeafNodeValidationError::Lifetime(
                        LifetimeError::RangeTooBig,
                    ));
                }

                // ValSem308
                if !lifetime.is_valid() {
                    return Err(LeafNodeValidationError::Lifetime(LifetimeError::NotCurrent));
                }

                Ok(self)
            }
            _ => Err(LeafNodeValidationError::InvalidLeafNodeSource),
        }
    }

    /// Validate the leaf node in the context of an update.
    ///
    /// Basic:
    /// * ValSems from [`LeafNode::validate`]
    ///
    /// In update:
    /// * ValSem309
    pub(crate) fn validate_in_update<'a>(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        group: &CoreGroup,
        leaf_index: LeafNodeIndex,
        exclude_signature_public_keys: &[SignaturePublicKey],
    ) -> Result<&Self, LeafNodeValidationError> {
        self.validate(
            backend,
            group,
            TreeInfoTbs::update(group.group_id().clone(), leaf_index),
            exclude_signature_public_keys,
        )?;

        // ValSem309
        match self.payload.leaf_node_source {
            LeafNodeSource::Update => Ok(self),
            _ => Err(LeafNodeValidationError::InvalidLeafNodeSource),
        }
    }

    /// Validate the leaf node in the context of a commit.
    ///
    /// Basic:
    /// * ValSems from [`LeafNode::validate`]
    ///
    /// In commit:
    /// * ValSem310
    pub(crate) fn validate_in_commit<'a>(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        group: &CoreGroup,
        leaf_index: LeafNodeIndex,
        exclude_signature_public_keys: &[SignaturePublicKey],
    ) -> Result<&Self, LeafNodeValidationError> {
        self.validate(
            backend,
            group,
            TreeInfoTbs::commit(group.group_id().clone(), leaf_index),
            exclude_signature_public_keys,
        )?;

        // ValSem310
        match self.payload.leaf_node_source {
            LeafNodeSource::Commit(_) => Ok(self),
            _ => Err(LeafNodeValidationError::InvalidLeafNodeSource),
        }
    }

    /// Basic validation of leaf node called in all `validate_in_*` methods.
    ///
    /// * ValSem300
    /// * ValSem301
    /// * ValSem302
    /// * ValSem303_1
    /// * ValSem303_2
    /// * ValSem303_3
    /// * ValSem304
    /// * ValSem305
    ///
    /// Note: All AS validation must have happened before.
    fn validate<'a>(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        group: &CoreGroup,
        tree_info: TreeInfoTbs,
        exclude_signature_public_keys: &[SignaturePublicKey],
    ) -> Result<&Self, LeafNodeValidationError> {
        let filtered_signature_public_keys = group
            .signature_keys(false)
            .into_iter()
            .filter(|item| !exclude_signature_public_keys.contains(item))
            .collect::<Vec<_>>();

        self
            // ValSem300
            .validate_signature(backend, group.ciphersuite(), tree_info)?
            // ValSem301
            .validate_group_parameters(group.version(), group.ciphersuite())?
            // ValSem302
            .validate_required_capabilities(group.required_capabilities())?
            // ValSem303_1
            .validate_against_group_credentials(&group.members_supported_credentials())?
            // ValSem303_2
            .validate_credential_in_use(&group.members_used_credentials())?
            // ValSem303_3
            .validate_that_capabilities_contain_extension_types()?
            // TODO: ValSem? In spec?
            .validate_that_capabilities_contain_credential_type()?
            // ValSem304
            .validate_that_signature_key_is_unique(&filtered_signature_public_keys)?
            // ValSem305
            .validate_that_encryption_key_is_unique(&group.encryption_keys())?;

        Ok(self)
    }

    /// ValSem300
    pub(crate) fn validate_signature(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        tree_info: TreeInfoTbs,
    ) -> Result<&Self, LeafNodeValidationError> {
        let tbs = LeafNodeTbs::from(self.clone(), tree_info);

        let verifiable_leaf_node = VerifiableLeafNode {
            tbs: &tbs,
            signature: self.signature(),
        };

        let signature_public_key = self
            .signature_key()
            .clone()
            .into_signature_public_key_enriched(ciphersuite.signature_algorithm());

        if verifiable_leaf_node
            .verify_no_out(backend.crypto(), &signature_public_key)
            .is_ok()
        {
            Ok(self)
        } else {
            Err(LeafNodeValidationError::InvalidSignature)
        }
    }

    /// ValSem301
    pub(crate) fn validate_group_parameters(
        &self,
        version: ProtocolVersion,
        ciphersuite: Ciphersuite,
    ) -> Result<&Self, LeafNodeValidationError> {
        if !self.payload.capabilities.versions.contains(&version) {
            return Err(LeafNodeValidationError::UnsupportedVersion);
        }

        if !self
            .payload
            .capabilities
            .ciphersuites
            .contains(&ciphersuite)
        {
            return Err(LeafNodeValidationError::UnsupportedCiphersuite);
        }

        Ok(self)
    }

    /// ValSem302
    pub(crate) fn validate_required_capabilities<'a>(
        &self,
        required_capabilities: impl Into<Option<&'a RequiredCapabilitiesExtension>>,
    ) -> Result<&Self, LeafNodeValidationError> {
        // If the GroupContext has a required_capabilities extension, ...
        if let Some(required_capabilities) = required_capabilities.into() {
            // ... then the required extensions, ...
            for required_extension in required_capabilities.extension_types() {
                if !self.supports_extension(required_extension) {
                    return Err(LeafNodeValidationError::UnsupportedExtensions);
                }
            }

            // ... proposals, ...
            for required_proposal in required_capabilities.proposal_types() {
                if !self.supports_proposal(required_proposal) {
                    return Err(LeafNodeValidationError::UnsupportedProposals);
                }
            }

            // ... and credential types MUST be listed in the LeafNode's capabilities field.
            for required_credential in required_capabilities.credential_types() {
                if !self.supports_credential(required_credential) {
                    return Err(LeafNodeValidationError::UnsupportedCredentials);
                }
            }
        }

        Ok(self)
    }

    /// ValSem303_1
    fn validate_against_group_credentials(
        &self,
        members_supported_credentials: &[&[CredentialType]],
    ) -> Result<&Self, LeafNodeValidationError> {
        for member_supported_credentials in members_supported_credentials {
            if !member_supported_credentials.contains(&self.credential().credential_type()) {
                return Err(LeafNodeValidationError::LeafNodeCredentialNotSupportedByMember);
            }
        }

        Ok(self)
    }

    /// ValSem303_2
    fn validate_credential_in_use(
        &self,
        currently_in_use: &[CredentialType],
    ) -> Result<&Self, LeafNodeValidationError> {
        for credential in currently_in_use {
            if !self.payload.capabilities.credentials.contains(credential) {
                return Err(LeafNodeValidationError::MemberCredentialNotSupportedByLeafNode);
            }
        }

        Ok(self)
    }

    /// ValSem303_3
    pub(crate) fn validate_that_capabilities_contain_extension_types(
        &self,
    ) -> Result<&Self, LeafNodeValidationError> {
        for id in self
            .payload
            .extensions
            .iter()
            .map(Extension::extension_type)
        {
            if !self.supports_extension(&id) {
                return Err(LeafNodeValidationError::ExtensionsNotInCapabilities);
            }
        }

        Ok(self)
    }

    /// TODO
    fn validate_that_capabilities_contain_credential_type(
        &self,
    ) -> Result<&Self, LeafNodeValidationError> {
        if !self
            .payload
            .capabilities
            .credentials
            .contains(&self.payload.credential.credential_type())
        {
            return Err(LeafNodeValidationError::CredentialNotInCapabilities);
        }

        Ok(self)
    }

    /// ValSem304
    fn validate_that_signature_key_is_unique(
        &self,
        signature_keys: &[SignaturePublicKey],
    ) -> Result<&Self, LeafNodeValidationError> {
        if signature_keys.contains(self.signature_key()) {
            return Err(LeafNodeValidationError::SignatureKeyAlreadyInUse);
        }

        Ok(self)
    }

    /// ValSem305
    fn validate_that_encryption_key_is_unique(
        &self,
        encryption_keys: &[EncryptionKey],
    ) -> Result<&Self, LeafNodeValidationError> {
        if encryption_keys.contains(self.encryption_key()) {
            return Err(LeafNodeValidationError::EncryptionKeyAlreadyInUse);
        }

        Ok(self)
    }

    // ---------------------------------------------------------------------------------------------

    /// Returns `true` if the [`ExtensionType`] is supported by this leaf node.
    pub(crate) fn supports_extension(&self, extension_type: &ExtensionType) -> bool {
        self.payload
            .capabilities
            .extensions
            .contains(extension_type)
            || default_extensions().iter().any(|et| et == extension_type)
    }

    /// Returns `true` if the [`ProposalType`] is supported by this leaf node.
    pub(crate) fn supports_proposal(&self, proposal_type: &ProposalType) -> bool {
        self.payload.capabilities.proposals.contains(proposal_type)
            || default_proposals().iter().any(|pt| pt == proposal_type)
    }

    /// Returns `true` if the [`CredentialType`] is supported by this leaf node.
    pub(crate) fn supports_credential(&self, credential_type: &CredentialType) -> bool {
        self.payload
            .capabilities
            .credentials
            .contains(credential_type)
    }
}

#[cfg(test)]
impl LeafNode {
    /// Expose [`new_with_key`] for tests.
    pub(crate) fn create_new_with_key(
        encryption_key: EncryptionKey,
        credential_with_key: CredentialWithKey,
        leaf_node_source: LeafNodeSource,
        capabilities: Capabilities,
        extensions: Extensions,
        signer: &impl Signer,
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

    /// Return a mutable reference to [`Capabilities`].
    pub fn capabilities_mut(&mut self) -> &mut Capabilities {
        &mut self.payload.capabilities
    }

    /// Check whether the this leaf node supports all the required extensions
    /// in the provided list.
    pub(crate) fn check_extension_support(
        &self,
        extensions: &[ExtensionType],
    ) -> Result<(), LeafNodeValidationError> {
        for required in extensions.iter() {
            if !self.supports_extension(required) {
                return Err(LeafNodeValidationError::UnsupportedExtensions);
            }
        }
        Ok(())
    }

    #[allow(unused)]
    pub(crate) fn set_leaf_node_source(&mut self, new_leaf_node_source: LeafNodeSource) {
        self.payload.leaf_node_source = new_leaf_node_source;
    }
}

#[cfg(any(feature = "test-utils", test))]
impl LeafNode {
    /// Replace the credential in the KeyPackage.
    pub(crate) fn set_credential(&mut self, credential: Credential) {
        self.payload.credential = credential;
    }
}

impl From<OpenMlsLeafNode> for LeafNode {
    fn from(leaf: OpenMlsLeafNode) -> Self {
        leaf.leaf_node
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
#[derive(Debug)]
pub struct LeafNodeTbs {
    payload: LeafNodePayload,
    tree_info: TreeInfoTbs,
}

impl LeafNodeTbs {
    /// Build a [`LeafNodeTbs`] from a [`LeafNode`] and a [`TreeInfo`]
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
    pub(crate) fn key_package() -> Self {
        Self::KeyPackage
    }

    pub(crate) fn update(group_id: GroupId, leaf_index: LeafNodeIndex) -> Self {
        Self::Update(TreePosition {
            group_id,
            leaf_index,
        })
    }

    pub(crate) fn commit(group_id: GroupId, leaf_index: LeafNodeIndex) -> Self {
        Self::Commit(TreePosition {
            group_id,
            leaf_index,
        })
    }
}

#[derive(Debug, TlsSerialize, TlsDeserialize, TlsSize)]
pub(crate) struct TreePosition {
    group_id: GroupId,
    leaf_index: LeafNodeIndex,
}

const LEAF_NODE_SIGNATURE_LABEL: &str = "LeafNodeTBS";

/// Helper struct to verify incoming leaf nodes.
/// The [`LeafNode`] doesn't have all the information needed to verify.
/// In particular is the [`TreeInfo`] missing.
pub(crate) struct VerifiableLeafNode<'a> {
    pub(crate) tbs: &'a LeafNodeTbs,
    pub(crate) signature: &'a Signature,
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

impl<'a> Verifiable for VerifiableLeafNode<'a> {
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

impl OpenMlsLeafNode {
    /// Generate a new [`OpenMlsLeafNode`] for a new tree.
    pub(crate) fn new(
        config: CryptoConfig,
        leaf_node_source: LeafNodeSource,
        backend: &impl OpenMlsCryptoProvider,
        signer: &impl Signer,
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
        signer: &impl Signer,
    ) -> Result<(), PublicTreeError> {
        let tree_info = self.update_tree_info(group_id)?;
        // TODO: If we could take out the leaf_node without cloning, this would all be nicer.
        let mut leaf_node_tbs = LeafNodeTbs::from(self.leaf_node.clone(), tree_info);

        // Update credential
        if let Some(leaf_node) = leaf_node.into() {
            leaf_node_tbs.payload.credential = leaf_node.credential().clone();
            leaf_node_tbs.payload.encryption_key = leaf_node.encryption_key().clone();
        } else if let Some(new_encryption_key) = new_encryption_key.into() {
            // If there's no new leaf, the encryption key must be provided
            // explicitly.
            leaf_node_tbs.payload.encryption_key = new_encryption_key;
        } else {
            debug_assert!(false, "update_and_re_sign needs to be called with a new leaf node or a new encryption key. Neither was the case.");
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
        signer: &impl Signer,
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

    /// Create the [`TreeInfo`] for an update for this leaf.
    fn update_tree_info(&self, group_id: GroupId) -> Result<TreeInfoTbs, LibraryError> {
        debug_assert!(
            self.leaf_index.is_some(),
            "TreeInfo for Update can't be created without a leaf index. \
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
                LibraryError::custom("TreeInfo for Update can't be created without a leaf index.")
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
        signer: &impl Signer,
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
    ) -> Result<(), LeafNodeValidationError> {
        self.leaf_node
            .validate_required_capabilities(required_capabilities)
            .map(|_| ())
    }

    /// Returns a reference to the encryption key of the leaf node.
    pub(crate) fn encryption_key(&self) -> &EncryptionKey {
        self.leaf_node.encryption_key()
    }

    /// Replace the public key in the leaf node and re-sign.
    #[cfg(any(feature = "test-utils", test))]
    pub fn set_public_key(&mut self, public_key: HpkePublicKey, signer: &impl Signer) {
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

#[derive(Error, Debug, PartialEq, Clone)]
pub enum LeafNodeGenerationError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Error storing leaf private key in key store.
    #[error("Error storing leaf private key in key store.")]
    KeyStoreError(KeyStoreError),
}
