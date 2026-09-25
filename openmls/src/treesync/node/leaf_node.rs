//! This module contains the [`LeafNode`] struct and its implementation.
use std::collections::HashSet;

use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    signatures::Signer,
    types::{Ciphersuite, VerifiableCiphersuite},
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
    extensions::{Extension, ExtensionType, Extensions, RequiredCapabilitiesExtension},
    group::{GroupContext, GroupId},
    key_packages::{KeyPackage, Lifetime},
    prelude::KeyPackageBundle,
    storage::OpenMlsProvider,
    versions::ProtocolVersion,
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
    pub(crate) extensions: Extensions<LeafNode>,
    pub(crate) tree_info_tbs: TreeInfoTbs,
    /// What the group the leaf is built for requires of it. Empty for a
    /// `KeyPackage`, which has no group.
    pub(crate) constraints: LeafNodeConstraints,
    /// How `capabilities` is treated when it doesn't cover what the leaf
    /// needs. See [`LeafNodePayload::enforce_capabilities`].
    pub(crate) capabilities_policy: CapabilitiesPolicy,
}

/// Set of LeafNode parameters that are used when regenerating a LeafNodes
/// during an update operation.
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct UpdateLeafNodeParams {
    pub(crate) credential_with_key: CredentialWithKey,
    pub(crate) capabilities: Capabilities,
    pub(crate) extensions: Extensions<LeafNode>,
    /// What the group the leaf is built for requires.
    pub(crate) constraints: LeafNodeConstraints,
    /// How `capabilities` is treated when it doesn't cover what the leaf
    /// needs. See [`LeafNodePayload::enforce_capabilities`].
    pub(crate) capabilities_policy: CapabilitiesPolicy,
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
            // This reconstructs an already-consistent leaf; there's no group
            // available here to source constraints from.
            constraints: LeafNodeConstraints::default(),
            capabilities_policy: CapabilitiesPolicy::Reject,
        }
    }
}

/// We need to build a leaf node that's compatible with the group.
///
/// These are the checks a receiving member applies to the leaf's capabilities
/// (see [`PublicGroup::validate_leaf_node`] and the GroupContext extension
/// checks), so a leaf that passes them is valid for the group.
///
/// The default requires nothing, which is used for [`KeyPackage`].
///
/// [`PublicGroup::validate_leaf_node`]: crate::group::PublicGroup::validate_leaf_node
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct LeafNodeConstraints {
    /// Commits may change the required capabilities.
    /// The leaf must support all of them.
    required_capabilities: Vec<RequiredCapabilitiesExtension>,

    /// Group context extensions.
    group_context_extensions: HashSet<ExtensionType>,

    /// Credential types of the members.
    /// The leaf must support all of them.
    credentials_in_use: HashSet<CredentialType>,

    /// Credential types every member supports.
    /// The leaf's own credential must be one of them.
    /// Empty, i.e. no restriction, while there are no members (the group
    /// creator, a key package). Never empty with members, since each
    /// supports every credential type in use (valn0104).
    credentials_supported_by_all: HashSet<CredentialType>,
}

impl LeafNodeConstraints {
    /// Constraints from a group's GroupContext extensions alone, e.g. for the
    /// creator of a group that has no other members yet.
    pub(crate) fn from_group_context_extensions(extensions: &Extensions<GroupContext>) -> Self {
        let mut constraints = Self::default();
        constraints.add_group_context_extensions(extensions);
        constraints
    }

    /// Also demand support for `extensions` and their required capabilities.
    pub(crate) fn add_group_context_extensions(&mut self, extensions: &Extensions<GroupContext>) {
        if let Some(required_capabilities) = extensions.required_capabilities() {
            self.required_capabilities
                .push(required_capabilities.clone());
        }
        self.group_context_extensions
            .extend(extensions.iter().map(Extension::extension_type));
    }

    /// Add compatibility with the credential of `member`.
    pub(crate) fn add_member(&mut self, member: &LeafNode) {
        let supported = member.capabilities().credentials();
        let is_first_member = self.credentials_in_use.is_empty();
        if is_first_member {
            self.credentials_supported_by_all = supported.iter().copied().collect();
        } else {
            self.credentials_supported_by_all
                .retain(|credential_type| supported.contains(credential_type));
        }
        self.credentials_in_use
            .insert(member.credential().credential_type());
    }

    /// Check `capabilities` against the constraints.
    fn check(
        &self,
        capabilities: &Capabilities,
        credential_type: CredentialType,
    ) -> Result<(), LeafNodeValidationError> {
        // https://validation.openmls.tech/#valn0103
        for required_capabilities in &self.required_capabilities {
            capabilities.supports_required_capabilities(required_capabilities)?;
        }

        // https://validation.openmls.tech/#valn0602
        // https://validation.openmls.tech/#valn1210
        if self.group_context_extensions.iter().any(|extension_type| {
            !extension_type.is_default() && !capabilities.extensions().contains(extension_type)
        }) {
            return Err(LeafNodeValidationError::UnsupportedExtensions);
        }

        // https://validation.openmls.tech/#valn0104
        if !self.credentials_supported_by_all.is_empty()
            && !self.credentials_supported_by_all.contains(&credential_type)
        {
            return Err(LeafNodeValidationError::LeafNodeCredentialNotSupportedByMember);
        }
        if self
            .credentials_in_use
            .iter()
            .any(|in_use| !capabilities.contains_credential(*in_use))
        {
            return Err(LeafNodeValidationError::MemberCredentialNotSupportedByLeafNode);
        }

        Ok(())
    }
}

/// Parameters for a leaf node that can be chosen by the application.
#[derive(Debug, PartialEq, Clone, Default)]
pub struct LeafNodeParameters {
    credential_with_key: Option<CredentialWithKey>,
    capabilities: Option<Capabilities>,
    extensions: Option<Extensions<LeafNode>>,
    capabilities_policy: Option<CapabilitiesPolicy>,
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
    pub fn extensions(&self) -> Option<&Extensions<LeafNode>> {
        self.extensions.as_ref()
    }

    /// Returns the capabilities policy the caller set, if any. `None` lets
    /// [`resolve_capabilities`] pick, which depends on whether `capabilities`
    /// was set as well.
    pub(crate) fn capabilities_policy(&self) -> Option<CapabilitiesPolicy> {
        self.capabilities_policy
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.credential_with_key.is_none()
            && self.capabilities.is_none()
            && self.extensions.is_none()
    }

    pub(crate) fn set_credential_with_key(&mut self, credential_with_key: CredentialWithKey) {
        self.credential_with_key = Some(credential_with_key);
    }

    #[cfg(feature = "virtual-clients-draft")]
    pub(crate) fn set_extensions(&mut self, extensions: Extensions<LeafNode>) {
        self.extensions = Some(extensions);
    }
}

/// Builder for [`LeafNodeParameters`].
#[derive(Debug, Default)]
pub struct LeafNodeParametersBuilder {
    credential_with_key: Option<CredentialWithKey>,
    capabilities: Option<Capabilities>,
    extensions: Option<Extensions<LeafNode>>,
    capabilities_policy: Option<CapabilitiesPolicy>,
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
    ///
    /// Returns an error if one or more of the extensions is invalid in leaf nodes.
    pub fn with_extensions(mut self, extensions: Extensions<LeafNode>) -> Self {
        self.extensions = Some(extensions);
        self
    }

    /// Set how `capabilities` is treated when it doesn't cover what the leaf
    /// needs.
    ///
    /// If never called, explicitly set capabilities are used and unset
    /// capabilities are derived from the leaf.
    pub fn with_capabilities_policy(mut self, policy: CapabilitiesPolicy) -> Self {
        self.capabilities_policy = Some(policy);
        self
    }

    /// Build the [`LeafNodeParameters`].
    pub fn build(self) -> LeafNodeParameters {
        LeafNodeParameters {
            credential_with_key: self.credential_with_key,
            capabilities: self.capabilities,
            extensions: self.extensions,
            capabilities_policy: self.capabilities_policy,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub struct LeafNode {
    payload: LeafNodePayload,
    signature: Signature,
}

/// Error building a [`LeafNode`]: either the leaf's capabilities don't
/// cover what the leaf uses under [`CapabilitiesPolicy::Reject`],
/// or an unrelated library error occurred (key generation, signing).
#[derive(Error, Debug, PartialEq, Clone)]
pub enum LeafNodeBuildError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`LeafNodeValidationError`] for more details.
    #[error(transparent)]
    Validation(#[from] LeafNodeValidationError),
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
    ) -> Result<(Self, EncryptionKeyPair), LeafNodeBuildError> {
        let NewLeafNodeParams {
            ciphersuite,
            credential_with_key,
            leaf_node_source,
            capabilities,
            extensions,
            tree_info_tbs,
            constraints,
            capabilities_policy,
        } = new_leaf_node_params;

        // Create a new encryption key pair.
        let encryption_key_pair =
            EncryptionKeyPair::random(provider.rand(), provider.crypto(), ciphersuite)?;

        let leaf_node = Self::new_with_key(
            ciphersuite,
            encryption_key_pair.public_key().clone(),
            credential_with_key,
            leaf_node_source,
            capabilities,
            extensions,
            tree_info_tbs,
            &constraints,
            capabilities_policy,
            signer,
        )?;

        Ok((leaf_node, encryption_key_pair))
    }

    /// Create a new [`LeafNode`] from a caller-provided encryption key pair.
    ///
    /// Mirrors [`LeafNode::new`] but uses `encryption_key_pair` instead of
    /// generating a fresh one. This is the virtual-clients KeyPackage build
    /// hook: the encryption key is derived from the per-operation secret so a
    /// sibling can reproduce it.
    #[cfg(feature = "virtual-clients-draft")]
    pub(crate) fn new_with_encryption_key_pair(
        signer: &impl Signer,
        new_leaf_node_params: NewLeafNodeParams,
        encryption_key_pair: EncryptionKeyPair,
    ) -> Result<(Self, EncryptionKeyPair), LeafNodeBuildError> {
        let NewLeafNodeParams {
            ciphersuite,
            credential_with_key,
            leaf_node_source,
            capabilities,
            extensions,
            tree_info_tbs,
            constraints,
            capabilities_policy,
        } = new_leaf_node_params;

        let leaf_node = Self::new_with_key(
            ciphersuite,
            encryption_key_pair.public_key().clone(),
            credential_with_key,
            leaf_node_source,
            capabilities,
            extensions,
            tree_info_tbs,
            &constraints,
            capabilities_policy,
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
            capabilities: Capabilities::empty(),
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
    #[allow(clippy::too_many_arguments)]
    fn new_with_key(
        ciphersuite: Ciphersuite,
        encryption_key: EncryptionKey,
        credential_with_key: CredentialWithKey,
        leaf_node_source: LeafNodeSource,
        capabilities: Capabilities,
        extensions: Extensions<LeafNode>,
        tree_info_tbs: TreeInfoTbs,
        constraints: &LeafNodeConstraints,
        capabilities_policy: CapabilitiesPolicy,
        signer: &impl Signer,
    ) -> Result<Self, LeafNodeBuildError> {
        let leaf_node_tbs = LeafNodeTbs::new(
            ciphersuite,
            encryption_key,
            credential_with_key,
            capabilities,
            leaf_node_source,
            extensions,
            tree_info_tbs,
            constraints,
            capabilities_policy,
        )?;

        leaf_node_tbs
            .sign(signer)
            .map_err(|_| LibraryError::custom("Signing failed").into())
    }

    /// New [`LeafNode`] with a parent hash.
    ///
    /// With the `virtual-clients-draft` feature, an
    /// `encryption_key_pair_override` may be supplied. If `Some`, it is used
    /// as the leaf's encryption keypair instead of generating a fresh one.
    /// This is the hook for the virtual-clients-draft sender.
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
        #[cfg(feature = "virtual-clients-draft")] encryption_key_pair_override: Option<
            EncryptionKeyPair,
        >,
    ) -> Result<(Self, EncryptionKeyPair), LeafNodeBuildError> {
        #[cfg(feature = "virtual-clients-draft")]
        let encryption_key_pair = match encryption_key_pair_override {
            Some(kp) => kp,
            None => EncryptionKeyPair::random(rand, crypto, ciphersuite)?,
        };
        #[cfg(not(feature = "virtual-clients-draft"))]
        let encryption_key_pair = EncryptionKeyPair::random(rand, crypto, ciphersuite)?;

        let leaf_node_tbs = LeafNodeTbs::new(
            ciphersuite,
            encryption_key_pair.public_key().clone(),
            leaf_node_params.credential_with_key,
            leaf_node_params.capabilities,
            LeafNodeSource::Commit(parent_hash.into()),
            leaf_node_params.extensions,
            TreeInfoTbs::Commit(TreePosition {
                group_id,
                leaf_index,
            }),
            &leaf_node_params.constraints,
            leaf_node_params.capabilities_policy,
        )?;

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
    #[cfg(all(test, feature = "generate-kats"))]
    pub(crate) fn generate_update<Provider: OpenMlsProvider>(
        ciphersuite: Ciphersuite,
        credential_with_key: CredentialWithKey,
        capabilities: Capabilities,
        extensions: Extensions<LeafNode>,
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
            // KAT generation only; there's no group to source constraints
            // from, and the leaf built here is expected to already be
            // self-consistent.
            constraints: LeafNodeConstraints::default(),
            capabilities_policy: CapabilitiesPolicy::Reject,
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
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn update<Provider: OpenMlsProvider>(
        &mut self,
        ciphersuite: Ciphersuite,
        provider: &Provider,
        signer: &impl Signer,
        group_id: GroupId,
        leaf_index: LeafNodeIndex,
        leaf_node_parmeters: LeafNodeParameters,
        constraints: &LeafNodeConstraints,
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
        let (capabilities, capabilities_policy) = resolve_capabilities_for_existing_leaf(
            leaf_node_parmeters.capabilities,
            leaf_node_parmeters.capabilities_policy,
            &leaf_node_tbs.payload.capabilities,
        );
        leaf_node_tbs.payload.capabilities = capabilities;

        // Set the leaf node source to update
        leaf_node_tbs.payload.leaf_node_source = LeafNodeSource::Update;

        // `LeafNodeTbs::from` above bypasses `LeafNodeTbs::new`, the usual
        // enforcement chokepoint, so it is applied here explicitly instead.
        // This runs before the key pair below is generated and stored, so a
        // rejected update leaves nothing behind in the key store.
        leaf_node_tbs.payload.enforce_capabilities(
            ciphersuite,
            ProtocolVersion::default(),
            constraints,
            capabilities_policy,
        )?;

        // Create a new encryption key pair
        let encryption_key_pair =
            EncryptionKeyPair::random(provider.rand(), provider.crypto(), ciphersuite)?;
        leaf_node_tbs.payload.encryption_key = encryption_key_pair.public_key().clone();

        // Store the encryption key pair in the key store.
        encryption_key_pair
            .write(provider.storage())
            .map_err(LeafNodeUpdateError::Storage)?;

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

    /// Returns the `credential`.
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
    pub fn extensions(&self) -> &Extensions<LeafNode> {
        &self.payload.extensions
    }

    /// The virtual-client derivation info this leaf might contain.
    #[cfg(feature = "virtual-clients-draft")]
    pub(crate) fn vc_derivation_info(
        &self,
    ) -> Result<
        Option<crate::components::vc_derivation_info::DerivationInfo>,
        crate::components::vc_derivation_info::VirtualClientsError,
    > {
        use tls_codec::DeserializeBytes as _;

        use crate::components::vc_derivation_info::{
            DerivationInfo, VirtualClientsError, VC_COMPONENT_ID,
        };

        let Some(bytes) = self
            .extensions()
            .app_data_dictionary()
            .and_then(|dict| dict.dictionary().get(&VC_COMPONENT_ID))
        else {
            return Ok(None);
        };
        DerivationInfo::tls_deserialize_exact_bytes(bytes)
            .map(Some)
            .map_err(|e| {
                log::error!("vc: leaf derivation info deserialize failed: {e:?}");
                VirtualClientsError::DerivationInfoMalformed
            })
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
        let mut required = extensions.iter().filter(|e| !e.is_default()).peekable();

        // Skip building the lookup if there are no non-default extensions.
        if required.peek().is_none() {
            return Ok(());
        }

        let supported: HashSet<ExtensionType> = self
            .payload
            .capabilities
            .extensions
            .iter()
            .copied()
            .collect();

        if let Some(unsupported) = required.find(|e| !supported.contains(e)) {
            log::error!(
                "Leaf node does not support required extension {:?}\n
                    Supported extensions: {:?}",
                unsupported,
                self.payload.capabilities.extensions
            );
            return Err(LeafNodeValidationError::UnsupportedExtensions);
        }

        Ok(())
    }

    /// Perform all checks that can be done without further context:
    /// - the used extensions are not known to be invalid in leaf nodes
    /// - the types of the used extensions are covered by the capabilities
    /// - the type of the credential is covered by the capabilities
    pub(crate) fn validate_locally(&self) -> Result<(), LeafNodeValidationError> {
        self.payload.validate_locally()
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
    extensions: Extensions<LeafNode>,
}

impl LeafNodePayload {
    /// Perform all checks that can be done without further context:
    /// - the used extensions are not known to be invalid in leaf nodes
    /// - the types of the used extensions are covered by the capabilities
    /// - the type of the credential is covered by the capabilities
    ///
    /// This lives on the payload rather than on [`LeafNode`] so that leaf
    /// construction can run it *before* signing, and so that a leaf we build
    /// is held to exactly the checks a peer will apply on receipt.
    pub(crate) fn validate_locally(&self) -> Result<(), LeafNodeValidationError> {
        // Check that no extension is invalid when used in leaf nodes.
        // https://validation.openmls.tech/#valn1601
        // NOTE: This check is conducted manually for now, instead of using the method
        // Extensions::validate_extension_types_for_leaf_node(),
        // in order to collect the invalid extension types for the log message below.
        // However, it could be better to instead return the list of invalid extension types
        // as part of Extensions::validate_extension_types_for_leaf_node(),
        // as part of the error message.
        let invalid_extension_types = self
            .extensions
            .iter()
            .filter(|ext| !ext.extension_type().is_valid_in_leaf_node())
            .collect::<Vec<_>>();
        if !invalid_extension_types.is_empty() {
            log::error!("Invalid extension used in leaf node: {invalid_extension_types:?}");
            return Err(LeafNodeValidationError::UnsupportedExtensions);
        }

        // Check that all extensions are contained in the capabilities.
        if !self.capabilities.contains_extensions(&self.extensions) {
            log::error!(
                "Leaf node does not support all extensions it uses\n
                Supported extensions: {:?}\n
                Used extensions: {:?}",
                self.capabilities.extensions(),
                self.extensions
            );
            return Err(LeafNodeValidationError::ExtensionsNotInCapabilities);
        }

        // Check that the capabilities contain the leaf node's credential type.
        // (https://validation.openmls.tech/#valn0113)
        if !self
            .capabilities
            .contains_credential(self.credential.credential_type())
        {
            return Err(LeafNodeValidationError::CredentialNotInCapabilities);
        }

        Ok(())
    }

    /// Apply `policy` to this leaf's capabilities, then check them.
    ///
    /// This is the single enforcement point for every leaf OpenMLS builds. It
    /// is reached from [`LeafNodeTbs::new`] (every freshly-built leaf) and from
    /// [`LeafNode::update`], which mutates an existing signed leaf in place and
    /// so bypasses `LeafNodeTbs::new`.
    ///
    /// The checks run under both policies, so widening is verified as well.
    /// Together with `constraints` they are the capability checks a
    /// peer applies on receipt ([`LeafNodePayload::validate_locally`]) and
    /// [`LeafNodeConstraints`]. Widening never covers `constraints`.
    fn enforce_capabilities(
        &mut self,
        ciphersuite: Ciphersuite,
        version: ProtocolVersion,
        constraints: &LeafNodeConstraints,
        policy: CapabilitiesPolicy,
    ) -> Result<(), LeafNodeValidationError> {
        if matches!(policy, CapabilitiesPolicy::Widen) {
            self.capabilities.widen_for(
                ciphersuite,
                self.credential.credential_type(),
                &self.extensions,
            );
        }
        self.capabilities.ensure_version(version);

        self.validate_locally()?;

        if !self
            .capabilities
            .contains_ciphersuite(VerifiableCiphersuite::from(ciphersuite))
        {
            return Err(LeafNodeValidationError::CiphersuiteNotInCapabilities);
        }

        constraints.check(&self.capabilities, self.credential.credential_type())?;

        Ok(())
    }
}

/// The source of the `LeafNode`.
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
    /// The leaf node was added to the group as part of a key package.
    #[tls_codec(discriminant = 1)]
    KeyPackage(Lifetime),
    /// The leaf node was added through an Update proposal.
    Update,
    /// The leaf node was added via a Commit.
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
    ///
    /// This is the single point through which every leaf node the library
    /// creates is built, so it is where we enforce that a leaf's capabilities
    /// are consistent with the leaf itself and the group's requirements — see
    /// [`LeafNodePayload::enforce_capabilities`].
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        ciphersuite: Ciphersuite,
        encryption_key: EncryptionKey,
        credential_with_key: CredentialWithKey,
        capabilities: Capabilities,
        leaf_node_source: LeafNodeSource,
        extensions: Extensions<LeafNode>,
        tree_info_tbs: TreeInfoTbs,
        constraints: &LeafNodeConstraints,
        capabilities_policy: CapabilitiesPolicy,
    ) -> Result<Self, LeafNodeValidationError> {
        let mut payload = LeafNodePayload {
            encryption_key,
            signature_key: credential_with_key.signature_key,
            credential: credential_with_key.credential,
            capabilities,
            leaf_node_source,
            extensions,
        };

        payload.enforce_capabilities(
            ciphersuite,
            ProtocolVersion::default(),
            constraints,
            capabilities_policy,
        )?;

        Ok(LeafNodeTbs {
            payload,
            tree_info_tbs,
        })
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

    /// Returns the `encryption_key` as byte slice.
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

    /// Assume that signature is valid and return the corresponding [`LeafNode`].
    ///
    /// # Safety
    ///
    /// The caller must guarantee that the leaf node is verified.
    #[cfg(feature = "unchecked-conversions")]
    pub fn into_unchecked(self) -> LeafNode {
        LeafNode {
            payload: self.payload,
            signature: self.signature,
        }
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
    fn from_payload(tbs: LeafNodeTbs, signature: Signature, _serialized_payload: Vec<u8>) -> Self {
        Self {
            payload: tbs.payload,
            signature,
        }
    }
}

#[cfg(all(test, feature = "generate-kats"))]
#[derive(Error, Debug, PartialEq, Clone)]
pub enum LeafNodeGenerationError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),

    /// See [`LeafNodeBuildError`] for more details.
    #[error(transparent)]
    Build(#[from] LeafNodeBuildError),

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

    /// See [`LeafNodeValidationError`] for more details.
    #[error(transparent)]
    Validation(#[from] LeafNodeValidationError),
}
