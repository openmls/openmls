//! ### Don't Panic!
//!
//! Functions in this module should never panic. However, if there is a bug in
//! the implementation, a function will return an unrecoverable `LibraryError`.
//! This means that some functions that are not expected to fail and throw an
//! error, will still return a `Result` since they may throw a `LibraryError`.

// Private
mod new_from_welcome;

// Crate
pub(crate) mod create_commit_params;
pub(crate) mod new_from_external_init;
pub(crate) mod past_secrets;
pub(crate) mod process;
pub(crate) mod proposals;
pub(crate) mod staged_commit;

// Tests
#[cfg(test)]
pub(crate) mod test_core_group;
#[cfg(test)]
mod test_create_commit_params;
#[cfg(test)]
mod test_external_init;
#[cfg(test)]
mod test_past_secrets;
#[cfg(test)]
mod test_proposals;

use super::builder::TempBuilderPG1;
use super::errors::CreateCommitError;

use self::create_commit_params::{CommitType, CreateCommitParams};
#[cfg(test)]
use super::errors::CreateGroupContextExtProposalError;
use super::public_group::diff::compute_path::PathComputationResult;
use super::public_group::PublicGroup;
use crate::binary_tree::array_representation::TreeSize;
#[cfg(test)]
use std::io::{Error, Read, Write};

use log::{debug, trace};
use openmls_traits::{key_store::OpenMlsKeyStore, signatures::Signer, types::Ciphersuite};
use serde::{Deserialize, Serialize};
use tls_codec::Serialize as TlsSerializeTrait;

use self::staged_commit::{MemberStagedCommitState, StagedCommitState};
use self::{past_secrets::MessageSecretsStore, staged_commit::StagedCommit};
use super::{
    errors::{CoreGroupBuildError, CreateAddProposalError, ExporterError, ValidationError},
    group_context::*,
};
use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    ciphersuite::{signable::Signable, HpkePublicKey, SignaturePublicKey},
    credentials::*,
    error::LibraryError,
    framing::{mls_auth_content::AuthenticatedContent, *},
    group::{config::CryptoConfig, *},
    key_packages::*,
    messages::{
        group_info::{GroupInfo, GroupInfoTBS, VerifiableGroupInfo},
        proposals::*,
        *,
    },
    schedule::{message_secrets::*, psk::*, *},
    tree::{secret_tree::SecretTreeError, sender_ratchet::SenderRatchetConfiguration},
    treesync::{
        node::{
            encryption_keys::{EncryptionKey, EncryptionKeyPair},
            leaf_node::{Lifetime, OpenMlsLeafNode},
        },
        *,
    },
    versions::ProtocolVersion,
};

#[derive(Debug)]
pub(crate) struct CreateCommitResult {
    pub(crate) commit: AuthenticatedContent,
    pub(crate) welcome_option: Option<Welcome>,
    pub(crate) staged_commit: StagedCommit,
    pub(crate) group_info: Option<GroupInfo>,
}

/// A member in the group is identified by this [`Member`] struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// The member's leaf index in the ratchet tree.
    pub index: LeafNodeIndex,
    /// The member's credential.
    pub credential: Credential,
    /// The member's public HPHKE encryption key.
    pub encryption_key: Vec<u8>,
    /// The member's public signature key.
    pub signature_key: Vec<u8>,
}

impl Member {
    /// Create new member.
    pub fn new(
        index: LeafNodeIndex,
        encryption_key: Vec<u8>,
        signature_key: Vec<u8>,
        credential: Credential,
    ) -> Self {
        Self {
            index,
            encryption_key,
            signature_key,
            credential,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct CoreGroup {
    public_group: PublicGroup,
    group_epoch_secrets: GroupEpochSecrets,
    own_leaf_index: LeafNodeIndex,
    // Group config.
    // Set to true if the ratchet tree extension is added to the `GroupInfo`.
    // Defaults to `false`.
    use_ratchet_tree_extension: bool,
    /// A [`MessageSecretsStore`] that stores message secrets.
    /// By default this store has the length of 1, i.e. only the [`MessageSecrets`]
    /// of the current epoch is kept.
    /// If more secrets from past epochs should be kept in order to be
    /// able to decrypt application messages from previous epochs, the size of
    /// the store must be increased through [`max_past_epochs()`].
    message_secrets_store: MessageSecretsStore,
}

/// Builder for [`CoreGroup`].
pub(crate) struct CoreGroupBuilder {
    public_group_builder: TempBuilderPG1,
    config: Option<CoreGroupConfig>,
    psk_ids: Vec<PreSharedKeyId>,
    max_past_epochs: usize,
}

impl CoreGroupBuilder {
    /// Create a new [`CoreGroupBuilder`].
    pub(crate) fn new(
        group_id: GroupId,
        crypto_config: CryptoConfig,
        credential_with_key: CredentialWithKey,
    ) -> Self {
        let public_group_builder =
            PublicGroup::builder(group_id, crypto_config, credential_with_key);
        Self {
            config: None,
            psk_ids: vec![],
            max_past_epochs: 0,
            public_group_builder,
        }
    }
    /// Set the [`CoreGroupConfig`] of the [`CoreGroup`].
    pub(crate) fn with_config(mut self, config: CoreGroupConfig) -> Self {
        self.config = Some(config);
        self
    }
    /// Set the [`Vec<PreSharedKeyId>`] of the [`CoreGroup`].
    #[cfg(test)]
    pub(crate) fn with_psk(mut self, psk_ids: Vec<PreSharedKeyId>) -> Self {
        self.psk_ids = psk_ids;
        self
    }
    /// Set the [`RequiredCapabilitiesExtension`] of the [`CoreGroup`].
    pub(crate) fn with_required_capabilities(
        mut self,
        required_capabilities: RequiredCapabilitiesExtension,
    ) -> Self {
        self.public_group_builder = self
            .public_group_builder
            .with_required_capabilities(required_capabilities);
        self
    }
    /// Set the number of past epochs the group should keep secrets.
    pub fn with_max_past_epoch_secrets(mut self, max_past_epochs: usize) -> Self {
        self.max_past_epochs = max_past_epochs;
        self
    }
    /// Set the [`Lifetime`] for the own leaf in the group.
    pub fn with_lifetime(mut self, lifetime: Lifetime) -> Self {
        self.public_group_builder = self.public_group_builder.with_lifetime(lifetime);
        self
    }

    /// Build the [`CoreGroup`].
    /// Any values that haven't been set in the builder are set to their default
    /// values (which might be random).
    ///
    /// This function performs cryptographic operations and there requires an
    /// [`OpenMlsCryptoProvider`].
    pub(crate) fn build<KeyStore: OpenMlsKeyStore>(
        self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
    ) -> Result<CoreGroup, CoreGroupBuildError<KeyStore::Error>> {
        let (public_group_builder, commit_secret, leaf_keypair) =
            self.public_group_builder.get_secrets(backend, signer)?;

        let ciphersuite = public_group_builder.crypto_config().ciphersuite;
        let config = self.config.unwrap_or_default();
        let version = public_group_builder.crypto_config().version;

        let serialized_group_context = public_group_builder
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        debug!("Created group {:x?}", public_group_builder.group_id());
        trace!(" >>> with {:?}, {:?}", ciphersuite, config);
        // Derive an initial joiner secret based on the commit secret.
        // Derive an epoch secret from the joiner secret.
        // We use a random `InitSecret` for initialization.
        let joiner_secret = JoinerSecret::new(
            backend,
            commit_secret,
            &InitSecret::random(ciphersuite, backend, version)
                .map_err(LibraryError::unexpected_crypto_error)?,
            &serialized_group_context,
        )
        .map_err(LibraryError::unexpected_crypto_error)?;

        // Prepare the PskSecret
        let psk_secret = PskSecret::new(ciphersuite, backend, &self.psk_ids)?;

        let mut key_schedule = KeySchedule::init(ciphersuite, backend, &joiner_secret, psk_secret)?;
        key_schedule
            .add_context(backend, &serialized_group_context)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;

        let epoch_secrets = key_schedule
            .epoch_secrets(backend)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;

        let (group_epoch_secrets, message_secrets) = epoch_secrets.split_secrets(
            serialized_group_context,
            TreeSize::new(1),
            LeafNodeIndex::new(0u32),
        );

        let initial_confirmation_tag = message_secrets
            .confirmation_key()
            .tag(backend, &[])
            .map_err(LibraryError::unexpected_crypto_error)?;

        let message_secrets_store =
            MessageSecretsStore::new_with_secret(self.max_past_epochs, message_secrets);

        let public_group = public_group_builder
            .with_confirmation_tag(initial_confirmation_tag)
            .build();

        let group = CoreGroup {
            public_group,
            group_epoch_secrets,
            use_ratchet_tree_extension: config.add_ratchet_tree_extension,
            message_secrets_store,
            own_leaf_index: LeafNodeIndex::new(0),
        };

        // Store the private key of the own leaf in the key store as an epoch keypair.
        group
            .store_epoch_keypairs(backend, &[leaf_keypair])
            .map_err(CoreGroupBuildError::KeyStoreError)?;

        Ok(group)
    }
}

/// Public [`CoreGroup`] functions.
impl CoreGroup {
    /// Get a builder for [`CoreGroup`].
    pub(crate) fn builder(
        group_id: GroupId,
        crypto_config: CryptoConfig,
        credential_with_key: CredentialWithKey,
    ) -> CoreGroupBuilder {
        CoreGroupBuilder::new(group_id, crypto_config, credential_with_key)
    }

    // === Create handshake messages ===
    // TODO: share functionality between these.

    // 11.1.1. Add
    // struct {
    //     KeyPackage key_package;
    // } Add;
    pub(crate) fn create_add_proposal(
        &self,
        framing_parameters: FramingParameters,
        joiner_key_package: KeyPackage,
        signer: &impl Signer,
    ) -> Result<AuthenticatedContent, CreateAddProposalError> {
        joiner_key_package
            .leaf_node()
            .validate_required_capabilities(self.required_capabilities())?;
        let add_proposal = AddProposal {
            key_package: joiner_key_package,
        };
        let proposal = Proposal::Add(add_proposal);
        AuthenticatedContent::member_proposal(
            framing_parameters,
            self.own_leaf_index(),
            proposal,
            self.context(),
            signer,
        )
        .map_err(|e| e.into())
    }

    // 11.1.2. Update
    // struct {
    //     KeyPackage key_package;
    // } Update;
    pub(crate) fn create_update_proposal(
        &self,
        framing_parameters: FramingParameters,
        // XXX: There's no need to own this. The [`UpdateProposal`] should
        //      operate on a reference to make this more efficient.
        leaf_node: LeafNode,
        signer: &impl Signer,
    ) -> Result<AuthenticatedContent, LibraryError> {
        let update_proposal = UpdateProposal { leaf_node };
        let proposal = Proposal::Update(update_proposal);
        AuthenticatedContent::member_proposal(
            framing_parameters,
            self.own_leaf_index(),
            proposal,
            self.context(),
            signer,
        )
    }

    // 11.1.3. Remove
    // struct {
    //     KeyPackageRef removed;
    // } Remove;
    pub(crate) fn create_remove_proposal(
        &self,
        framing_parameters: FramingParameters,
        removed: LeafNodeIndex,
        signer: &impl Signer,
    ) -> Result<AuthenticatedContent, ValidationError> {
        if !self.treesync().is_leaf_in_tree(removed) {
            return Err(ValidationError::UnknownMember);
        }
        let remove_proposal = RemoveProposal { removed };
        let proposal = Proposal::Remove(remove_proposal);
        AuthenticatedContent::member_proposal(
            framing_parameters,
            self.own_leaf_index(),
            proposal,
            self.context(),
            signer,
        )
        .map_err(ValidationError::LibraryError)
    }

    // 11.1.4. PreSharedKey
    // struct {
    //     PreSharedKeyID psk;
    // } PreSharedKey;
    // TODO: #751
    #[cfg(test)]
    pub(crate) fn create_presharedkey_proposal(
        &self,
        framing_parameters: FramingParameters,
        psk: PreSharedKeyId,
        signer: &impl Signer,
    ) -> Result<AuthenticatedContent, LibraryError> {
        let presharedkey_proposal = PreSharedKeyProposal::new(psk);
        let proposal = Proposal::PreSharedKey(presharedkey_proposal);
        AuthenticatedContent::member_proposal(
            framing_parameters,
            self.own_leaf_index(),
            proposal,
            self.context(),
            signer,
        )
    }

    /// Create a `GroupContextExtensions` proposal.
    #[cfg(test)]
    pub(crate) fn create_group_context_ext_proposal(
        &self,
        framing_parameters: FramingParameters,
        extensions: Extensions,
        signer: &impl Signer,
    ) -> Result<AuthenticatedContent, CreateGroupContextExtProposalError> {
        // Ensure that the group supports all the extensions that are wanted.

        let required_extension = extensions
            .iter()
            .find(|extension| extension.extension_type() == ExtensionType::RequiredCapabilities);
        if let Some(required_extension) = required_extension {
            let required_capabilities = required_extension.as_required_capabilities_extension()?;
            // Ensure we support all the capabilities.
            required_capabilities.check_support()?;
            self.own_leaf_node()?
                .validate_required_capabilities(required_capabilities)?;
            // Ensure that all other leaf nodes support all the required
            // extensions as well.
            self.treesync()
                .check_extension_support(required_capabilities.extension_types())?;
        }
        let proposal = GroupContextExtensionProposal::new(extensions);
        let proposal = Proposal::GroupContextExtensions(proposal);
        AuthenticatedContent::member_proposal(
            framing_parameters,
            self.own_leaf_index(),
            proposal,
            self.context(),
            signer,
        )
        .map_err(|e| e.into())
    }

    // Create application message
    pub(crate) fn create_application_message(
        &mut self,
        aad: &[u8],
        msg: &[u8],
        padding_size: usize,
        backend: &impl OpenMlsCryptoProvider,
        signer: &impl Signer,
    ) -> Result<PrivateMessage, MessageEncryptionError> {
        let public_message = AuthenticatedContent::new_application(
            self.own_leaf_index(),
            aad,
            msg,
            self.context(),
            signer,
        )?;
        self.encrypt(public_message, padding_size, backend)
    }

    // Encrypt an PublicMessage into an PrivateMessage
    pub(crate) fn encrypt(
        &mut self,
        public_message: AuthenticatedContent,
        padding_size: usize,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<PrivateMessage, MessageEncryptionError> {
        log::trace!("{:?}", public_message.confirmation_tag());
        PrivateMessage::try_from_authenticated_content(
            &public_message,
            self.ciphersuite(),
            backend,
            self.message_secrets_store.message_secrets_mut(),
            padding_size,
        )
    }

    /// Decrypt an PrivateMessage into an PublicMessage
    #[cfg(test)]
    pub(crate) fn decrypt(
        &mut self,
        private_message: &PrivateMessage,
        backend: &impl OpenMlsCryptoProvider,
        sender_ratchet_configuration: &SenderRatchetConfiguration,
    ) -> Result<VerifiableAuthenticatedContent, MessageDecryptionError> {
        let ciphersuite = self.ciphersuite();
        let message_secrets = self
            .message_secrets_mut(private_message.epoch())
            .map_err(|_| MessageDecryptionError::AeadError)?;
        let sender_data = private_message.sender_data(message_secrets, backend, ciphersuite)?;
        if !self.treesync().is_leaf_in_tree(sender_data.leaf_index) {
            return Err(MessageDecryptionError::SenderError(
                SenderError::UnknownSender,
            ));
        }
        let message_secrets = self
            .message_secrets_mut(private_message.epoch())
            .map_err(|_| MessageDecryptionError::AeadError)?;
        private_message.to_verifiable_content(
            ciphersuite,
            backend,
            message_secrets,
            sender_data.leaf_index,
            sender_ratchet_configuration,
            sender_data,
        )
    }

    /// Exporter
    pub(crate) fn export_secret(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, ExporterError> {
        if key_length > u16::MAX.into() {
            log::error!("Got a key that is larger than u16::MAX");
            return Err(ExporterError::KeyLengthTooLong);
        }
        Ok(self
            .group_epoch_secrets
            .exporter_secret()
            .derive_exported_secret(self.ciphersuite(), backend, label, context, key_length)
            .map_err(LibraryError::unexpected_crypto_error)?)
    }

    pub(crate) fn export_group_info(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        signer: &impl Signer,
        with_ratchet_tree: bool,
    ) -> Result<GroupInfo, LibraryError> {
        let extensions = {
            let ratchet_tree_extension = || {
                Extension::RatchetTree(RatchetTreeExtension::new(self.treesync().export_nodes()))
            };

            let external_pub_extension = || {
                let external_pub = self
                    .group_epoch_secrets()
                    .external_secret()
                    .derive_external_keypair(backend.crypto(), self.ciphersuite())
                    .public;
                Extension::ExternalPub(ExternalPubExtension::new(HpkePublicKey::from(external_pub)))
            };

            if with_ratchet_tree {
                Extensions::from_vec(vec![ratchet_tree_extension(), external_pub_extension()])
                    .map_err(|_| {
                        LibraryError::custom(
                            "There should not have been duplicate extensions here.",
                        )
                    })?
            } else {
                Extensions::single(external_pub_extension())
            }
        };

        // Create to-be-signed group info.
        let group_info_tbs = GroupInfoTBS::new(
            self.context().clone(),
            extensions,
            self.message_secrets()
                .confirmation_key()
                .tag(backend, self.context().confirmed_transcript_hash())
                .map_err(LibraryError::unexpected_crypto_error)?,
            self.own_leaf_index(),
        );

        // Sign to-be-signed group info.
        group_info_tbs
            .sign(signer)
            .map_err(|_| LibraryError::custom("Signing failed"))
    }

    /// Returns the epoch authenticator
    pub(crate) fn epoch_authenticator(&self) -> &EpochAuthenticator {
        self.group_epoch_secrets().epoch_authenticator()
    }

    /// Returns the resumption PSK secret
    pub(crate) fn resumption_psk_secret(&self) -> &ResumptionPskSecret {
        self.group_epoch_secrets().resumption_psk()
    }

    /// Loads the state from persisted state
    #[cfg(test)]
    pub(crate) fn load<R: Read>(reader: R) -> Result<CoreGroup, Error> {
        serde_json::from_reader(reader).map_err(|e| e.into())
    }

    /// Persists the state
    #[cfg(test)]
    pub(crate) fn save<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        let serialized_core_group = serde_json::to_string_pretty(self)?;
        writer.write_all(&serialized_core_group.into_bytes())
    }

    /// Returns a reference to the ratchet tree
    pub(crate) fn treesync(&self) -> &TreeSync {
        self.public_group.treesync()
    }

    /// Get the ciphersuite implementation used in this group.
    pub(crate) fn ciphersuite(&self) -> Ciphersuite {
        self.public_group.ciphersuite()
    }

    /// Get the MLS version used in this group.
    pub(crate) fn version(&self) -> ProtocolVersion {
        self.public_group.version()
    }

    /// Get the group context
    pub(crate) fn context(&self) -> &GroupContext {
        self.public_group.group_context()
    }

    /// Get the group ID
    pub(crate) fn group_id(&self) -> &GroupId {
        self.public_group.group_id()
    }

    /// Get the group context extensions.
    #[cfg(test)]
    pub(crate) fn group_context_extensions(&self) -> &Extensions {
        self.public_group.group_context().extensions()
    }

    /// Get the required capabilities extension of this group.
    pub(crate) fn required_capabilities(&self) -> Option<&RequiredCapabilitiesExtension> {
        self.public_group.required_capabilities()
    }

    /// Returns `true` if the group uses the ratchet tree extension anf `false
    /// otherwise
    #[cfg(test)]
    pub(crate) fn use_ratchet_tree_extension(&self) -> bool {
        self.use_ratchet_tree_extension
    }
}

// Private and crate functions
impl CoreGroup {
    /// Get the leaf index of this client.
    pub(crate) fn own_leaf_index(&self) -> LeafNodeIndex {
        self.own_leaf_index
    }

    /// Get the identity of the client's [`Credential`] owning this group.
    pub(crate) fn own_identity(&self) -> Option<&[u8]> {
        self.treesync()
            .leaf(self.own_leaf_index)
            .map(|node| node.credential().identity())
    }

    /// Get a reference to the group epoch secrets from the group
    pub(crate) fn group_epoch_secrets(&self) -> &GroupEpochSecrets {
        &self.group_epoch_secrets
    }

    /// Get a reference to the message secrets from a group
    pub(crate) fn message_secrets(&self) -> &MessageSecrets {
        self.message_secrets_store.message_secrets()
    }

    /// Sets the size of the [`MessageSecretsStore`], i.e. the number of past
    /// epochs to keep.
    /// This allows application messages from previous epochs to be decrypted.
    pub(crate) fn set_max_past_epochs(&mut self, max_past_epochs: usize) {
        self.message_secrets_store.resize(max_past_epochs);
    }

    /// Get the message secrets. Either from the secrets store or from the group.
    pub(crate) fn message_secrets_mut(
        &mut self,
        epoch: GroupEpoch,
    ) -> Result<&mut MessageSecrets, SecretTreeError> {
        if epoch < self.context().epoch() {
            self.message_secrets_store
                .secrets_for_epoch_mut(epoch)
                .ok_or(SecretTreeError::TooDistantInThePast)
        } else {
            Ok(self.message_secrets_store.message_secrets_mut())
        }
    }

    /// Get the message secrets. Either from the secrets store or from the group.
    pub(crate) fn message_secrets_for_epoch(
        &self,
        epoch: GroupEpoch,
    ) -> Result<&MessageSecrets, SecretTreeError> {
        if epoch < self.context().epoch() {
            self.message_secrets_store
                .secrets_for_epoch(epoch)
                .ok_or(SecretTreeError::TooDistantInThePast)
        } else {
            Ok(self.message_secrets_store.message_secrets())
        }
    }

    /// Get the message secrets and leaves for the given epoch. Either from the
    /// secrets store or from the group.
    ///
    /// Note that the leaves vector is empty for message secrets of the current
    /// epoch. The caller can use treesync in this case.
    pub(crate) fn message_secrets_and_leaves_mut(
        &mut self,
        epoch: GroupEpoch,
    ) -> Result<(&mut MessageSecrets, &[Member]), MessageDecryptionError> {
        if epoch < self.context().epoch() {
            self.message_secrets_store
                .secrets_and_leaves_for_epoch_mut(epoch)
                .ok_or({
                    MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast)
                })
        } else {
            // No need for leaves here. The tree of the current epoch is
            // available to the caller.
            Ok((self.message_secrets_store.message_secrets_mut(), &[]))
        }
    }

    pub(crate) fn own_leaf_node(&self) -> Result<&OpenMlsLeafNode, LibraryError> {
        self.treesync()
            .leaf(self.own_leaf_index())
            .ok_or_else(|| LibraryError::custom("Tree has no own leaf."))
    }

    /// Store the given [`EncryptionKeyPair`]s in the `backend`'s key store
    /// indexed by this group's [`GroupId`] and [`GroupEpoch`].
    ///
    /// Returns an error if access to the key store fails.
    pub(super) fn store_epoch_keypairs<KeyStore: OpenMlsKeyStore>(
        &self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        keypair_references: &[EncryptionKeyPair],
    ) -> Result<(), KeyStore::Error> {
        let k = EpochKeypairId::new(
            self.group_id(),
            self.context().epoch().as_u64(),
            self.own_leaf_index(),
        );
        backend
            .key_store()
            .store(&k.0, &keypair_references.to_vec())
    }

    /// Read the [`EncryptionKeyPair`]s of this group and its current
    /// [`GroupEpoch`] from the `backend`'s key store.
    ///
    /// Returns `None` if access to the key store fails.
    pub(super) fn read_epoch_keypairs<KeyStore: OpenMlsKeyStore>(
        &self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
    ) -> Vec<EncryptionKeyPair> {
        let k = EpochKeypairId::new(
            self.group_id(),
            self.context().epoch().as_u64(),
            self.own_leaf_index(),
        );
        backend
            .key_store()
            .read::<Vec<EncryptionKeyPair>>(&k.0)
            .unwrap_or_default()
    }

    /// Delete the [`EncryptionKeyPair`]s from the previous [`GroupEpoch`] from
    /// the `backend`'s key store.
    ///
    /// Returns an error if access to the key store fails.
    pub(super) fn delete_previous_epoch_keypairs<KeyStore: OpenMlsKeyStore>(
        &self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
    ) -> Result<(), KeyStore::Error> {
        let k = EpochKeypairId::new(
            self.group_id(),
            self.context().epoch().as_u64() - 1,
            self.own_leaf_index(),
        );
        backend.key_store().delete::<Vec<EncryptionKeyPair>>(&k.0)
    }

    pub(crate) fn create_commit<KeyStore: OpenMlsKeyStore>(
        &self,
        mut params: CreateCommitParams,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
    ) -> Result<CreateCommitResult, CreateCommitError<KeyStore::Error>> {
        let ciphersuite = self.ciphersuite();

        let sender = match params.commit_type() {
            CommitType::External => Sender::NewMemberCommit,
            CommitType::Member => Sender::build_member(self.own_leaf_index()),
        };

        // Filter proposals
        let (proposal_queue, contains_own_updates) = ProposalQueue::filter_proposals(
            ciphersuite,
            backend,
            sender.clone(),
            params.proposal_store(),
            params.inline_proposals(),
            self.own_leaf_index(),
        )
        .map_err(|e| match e {
            crate::group::errors::ProposalQueueError::LibraryError(e) => e.into(),
            crate::group::errors::ProposalQueueError::ProposalNotFound => {
                CreateCommitError::MissingProposal
            }
            crate::group::errors::ProposalQueueError::SenderError(_) => {
                CreateCommitError::WrongProposalSenderType
            }
        })?;

        // TODO: #581 Filter proposals by support
        // 11.2:
        // Proposals with a non-default proposal type MUST NOT be included in a commit
        // unless the proposal type is supported by all the members of the group that
        // will process the Commit (i.e., not including any members being added
        // or removed by the Commit).

        let proposal_reference_list = proposal_queue.commit_list();

        // Validate the proposals by doing the following checks:

        // ValSem101
        // ValSem102
        // ValSem104
        // ValSem106
        self.public_group.validate_add_proposals(&proposal_queue)?;
        // ValSem107
        // ValSem108
        self.public_group
            .validate_remove_proposals(&proposal_queue)?;
        // Validate update proposals for member commits
        if let Sender::Member(sender_index) = &sender {
            // ValSem110
            // ValSem111
            // ValSem112
            self.public_group
                .validate_update_proposals(&proposal_queue, *sender_index)?;
        }

        // Make a copy of the public group to apply proposals safely
        let mut diff = self.public_group.empty_diff();

        // Apply proposals to tree
        let apply_proposals_values =
            diff.apply_proposals(&proposal_queue, self.own_leaf_index())?;
        if apply_proposals_values.self_removed && params.commit_type() != CommitType::External {
            return Err(CreateCommitError::CannotRemoveSelf);
        }

        let path_computation_result =
            // If path is needed, compute path values
            if apply_proposals_values.path_required
                || contains_own_updates
                || params.force_self_update()
            {
                // Process the path. This includes updating the provisional
                // group context by updating the epoch and computing the new
                // tree hash.
                diff.compute_path(
                    backend,
                    self.own_leaf_index(),
                    apply_proposals_values.exclusion_list(),
                    params.commit_type(),
                    signer,
                    params.take_credential_with_key()
                )?
            } else {
                // If path is not needed, update the group context and return
                // empty path processing results
                diff.update_group_context(backend)?;
                PathComputationResult::default()
            };

        // Create commit message
        let commit = Commit {
            proposals: proposal_reference_list,
            path: path_computation_result.encrypted_path,
        };

        // Build AuthenticatedContent
        let mut commit = AuthenticatedContent::commit(
            *params.framing_parameters(),
            sender,
            commit,
            self.public_group.group_context(),
            signer,
        )?;

        // Update the confirmed transcript hash using the commit we just created.
        diff.update_confirmed_transcript_hash(backend, &commit)?;

        let serialized_provisional_group_context = diff
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        let joiner_secret = JoinerSecret::new(
            backend,
            path_computation_result.commit_secret,
            self.group_epoch_secrets().init_secret(),
            &serialized_provisional_group_context,
        )
        .map_err(LibraryError::unexpected_crypto_error)?;

        // Prepare the PskSecret
        let psk_secret =
            PskSecret::new(ciphersuite, backend, &apply_proposals_values.presharedkeys)?;

        // Create key schedule
        let mut key_schedule = KeySchedule::init(ciphersuite, backend, &joiner_secret, psk_secret)?;

        let serialized_provisional_group_context = diff
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        let welcome_secret = key_schedule
            .welcome(backend)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        key_schedule
            .add_context(backend, &serialized_provisional_group_context)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        let provisional_epoch_secrets = key_schedule
            .epoch_secrets(backend)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;

        // Calculate the confirmation tag
        let confirmation_tag = provisional_epoch_secrets
            .confirmation_key()
            .tag(backend, diff.group_context().confirmed_transcript_hash())
            .map_err(LibraryError::unexpected_crypto_error)?;

        // Set the confirmation tag
        commit.set_confirmation_tag(confirmation_tag.clone());

        diff.update_interim_transcript_hash(ciphersuite, backend, confirmation_tag.clone())?;

        // only computes the group info if necessary
        let group_info = if !apply_proposals_values.invitation_list.is_empty()
            || self.use_ratchet_tree_extension
        {
            // Create the ratchet tree extension if necessary
            let external_pub = provisional_epoch_secrets
                .external_secret()
                .derive_external_keypair(backend.crypto(), ciphersuite)
                .public;
            let external_pub_extension =
                Extension::ExternalPub(ExternalPubExtension::new(external_pub.into()));
            let other_extensions: Extensions = if self.use_ratchet_tree_extension {
                Extensions::from_vec(vec![
                    Extension::RatchetTree(RatchetTreeExtension::new(diff.export_nodes())),
                    external_pub_extension,
                ])?
            } else {
                Extensions::single(external_pub_extension)
            };

            // Create to-be-signed group info.
            let group_info_tbs = {
                GroupInfoTBS::new(
                    diff.group_context().clone(),
                    other_extensions,
                    confirmation_tag,
                    self.own_leaf_index(),
                )
            };
            // Sign to-be-signed group info.
            Some(group_info_tbs.sign(signer)?)
        } else {
            None
        };

        // Check if new members were added and, if so, create welcome messages
        let welcome_option = if !apply_proposals_values.invitation_list.is_empty() {
            // Encrypt GroupInfo object
            let (welcome_key, welcome_nonce) = welcome_secret
                .derive_welcome_key_nonce(backend)
                .map_err(LibraryError::unexpected_crypto_error)?;
            let encrypted_group_info = welcome_key
                .aead_seal(
                    backend,
                    group_info
                        .as_ref()
                        .ok_or_else(|| LibraryError::custom("GroupInfo was not computed"))?
                        .tls_serialize_detached()
                        .map_err(LibraryError::missing_bound_check)?
                        .as_slice(),
                    &[],
                    &welcome_nonce,
                )
                .map_err(LibraryError::unexpected_crypto_error)?;

            // Create group secrets for later use, so we can afterwards consume the
            // `joiner_secret`.
            let encrypted_secrets = diff.encrypt_group_secrets(
                &joiner_secret,
                apply_proposals_values.invitation_list,
                path_computation_result.plain_path.as_deref(),
                &apply_proposals_values.presharedkeys,
                &encrypted_group_info,
                backend,
                self.own_leaf_index(),
            )?;

            // Create welcome message
            let welcome = Welcome::new(self.ciphersuite(), encrypted_secrets, encrypted_group_info);
            Some(welcome)
        } else {
            None
        };

        let (provisional_group_epoch_secrets, provisional_message_secrets) =
            provisional_epoch_secrets.split_secrets(
                serialized_provisional_group_context,
                diff.tree_size(),
                self.own_leaf_index(),
            );

        let staged_commit_state = MemberStagedCommitState::new(
            provisional_group_epoch_secrets,
            provisional_message_secrets,
            diff.into_staged_diff(backend, ciphersuite)?,
            path_computation_result.new_keypairs,
            // The committer is not allowed to include their own update
            // proposal, so there is no extra keypair to store here.
            None,
        );
        let staged_commit = StagedCommit::new(
            proposal_queue,
            StagedCommitState::GroupMember(Box::new(staged_commit_state)),
        );

        Ok(CreateCommitResult {
            commit,
            welcome_option,
            staged_commit,
            group_info: group_info.filter(|_| self.use_ratchet_tree_extension),
        })
    }

    /// Return supported credentials of all members.
    // TODO(#1186)
    #[allow(unused)]
    pub(crate) fn members_supported_credentials(
        &self,
    ) -> impl Iterator<Item = &[CredentialType]> + '_ {
        self.treesync()
            .full_leaves()
            .map(|leaf_node| leaf_node.leaf_node().capabilities().credentials())
    }

    /// Return currently used credentials of all members.
    // TODO(#1186)
    #[allow(unused)]
    pub(crate) fn members_used_credentials(&self) -> impl Iterator<Item = CredentialType> + '_ {
        self.treesync()
            .full_leave_members()
            .map(|Member { credential, .. }| credential.credential_type())
    }

    /// Return currently used signature keys of all members.
    // TODO(#1186)
    #[allow(unused)]
    pub(crate) fn signature_keys(
        &self,
        exclude_own: bool,
    ) -> impl Iterator<Item = SignaturePublicKey> + '_ {
        self.treesync()
            .full_leave_members()
            .filter(move |member| {
                if exclude_own {
                    member.index != self.own_leaf_index
                } else {
                    true
                }
            })
            .map(|Member { signature_key, .. }| SignaturePublicKey::from(signature_key))
    }

    /// Return currently used encryption keys of all members.
    // TODO(#1186)
    #[allow(unused)]
    pub(crate) fn encryption_keys(&self) -> impl Iterator<Item = EncryptionKey> + '_ {
        self.treesync()
            .full_leave_members()
            .map(|Member { encryption_key, .. }| {
                EncryptionKey::from(HpkePublicKey::new(encryption_key))
            })
    }
}

/// Composite key for key material of a client within an epoch
pub struct EpochKeypairId(Vec<u8>);

impl EpochKeypairId {
    fn new(group_id: &GroupId, epoch: u64, leaf_index: LeafNodeIndex) -> Self {
        Self(
            [
                group_id.as_slice(),
                &leaf_index.u32().to_be_bytes(),
                &epoch.to_be_bytes(),
            ]
            .concat(),
        )
    }
}

#[cfg(any(feature = "test-utils", test))]
impl CoreGroup {
    pub(crate) fn context_mut(&mut self) -> &mut GroupContext {
        self.public_group.context_mut()
    }

    pub(crate) fn message_secrets_test_mut(&mut self) -> &mut MessageSecrets {
        self.message_secrets_store.message_secrets_mut()
    }

    pub(crate) fn print_tree(&self, message: &str) {
        use super::tests::tree_printing::print_tree;

        print_tree(self, message);
    }
}

/// Configuration for core group.
#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct CoreGroupConfig {
    /// Flag whether to send the ratchet tree along with the `GroupInfo` or not.
    /// Defaults to false.
    pub(crate) add_ratchet_tree_extension: bool,
}
