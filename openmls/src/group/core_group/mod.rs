//! ### Don't Panic!
//!
//! Functions in this module should never panic. However, if there is a bug in
//! the implementation, a function will return an unrecoverable `LibraryError`.
//! This means that some functions that are not expected to fail and throw an
//! error, will still return a `Result` since they may throw a `LibraryError`.

// Private
pub(super) mod new_from_welcome;

// Crate
pub(crate) mod create_commit_params;
pub(crate) mod new_from_external_init;
pub(crate) mod past_secrets;
pub(crate) mod process;
pub(crate) mod proposals;
pub(crate) mod staged_commit;

use log::{debug, trace};
use openmls_traits::{
    crypto::OpenMlsCrypto, signatures::Signer, storage::StorageProvider as _, types::Ciphersuite,
};
use serde::{Deserialize, Serialize};
use tls_codec::Serialize as TlsSerializeTrait;

use self::{
    create_commit_params::{CommitType, CreateCommitParams},
    node::leaf_node::Capabilities,
    past_secrets::MessageSecretsStore,
    staged_commit::{MemberStagedCommitState, StagedCommit, StagedCommitState},
};

use super::{
    builder::TempBuilderPG1,
    errors::{
        CoreGroupBuildError, CreateAddProposalError, CreateCommitError, ExporterError,
        ValidationError,
    },
    group_context::*,
    public_group::{diff::compute_path::PathComputationResult, PublicGroup},
};

use crate::{
    binary_tree::array_representation::{LeafNodeIndex, TreeSize},
    ciphersuite::{signable::Signable, HpkePublicKey},
    credentials::*,
    error::LibraryError,
    extensions::errors::InvalidExtensionError,
    framing::{mls_auth_content::AuthenticatedContent, *},
    group::*,
    key_packages::*,
    messages::{
        group_info::{GroupInfo, GroupInfoTBS, VerifiableGroupInfo},
        proposals::*,
        *,
    },
    schedule::{
        message_secrets::*,
        psk::{load_psks, store::ResumptionPskStore, PskSecret},
        *,
    },
    storage::{OpenMlsProvider, StorageProvider},
    tree::{secret_tree::SecretTreeError, sender_ratchet::SenderRatchetConfiguration},
    treesync::{node::encryption_keys::EncryptionKeyPair, *},
    versions::ProtocolVersion,
};

#[cfg(test)]
use super::errors::CreateGroupContextExtProposalError;
#[cfg(test)]
use crate::treesync::node::leaf_node::TreePosition;

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

/// A [`StagedCoreWelcome`] can be inspected and then turned into a [`CoreGroup`].
/// This allows checking who authored the Welcome message.
#[derive(Debug)]
pub(crate) struct StagedCoreWelcome {
    public_group: PublicGroup,
    group_epoch_secrets: GroupEpochSecrets,
    own_leaf_index: LeafNodeIndex,

    /// Group config.
    /// Set to true if the ratchet tree extension is added to the `GroupInfo`.
    /// Defaults to `false`.
    use_ratchet_tree_extension: bool,

    /// A [`MessageSecretsStore`] that stores message secrets.
    /// By default this store has the length of 1, i.e. only the [`MessageSecrets`]
    /// of the current epoch is kept.
    /// If more secrets from past epochs should be kept in order to be
    /// able to decrypt application messages from previous epochs, the size of
    /// the store must be increased through [`max_past_epochs()`].
    message_secrets_store: MessageSecretsStore,

    /// Resumption psk store. This is where the resumption psks are kept in a rollover list.
    pub(crate) resumption_psk_store: ResumptionPskStore,

    /// The [`VerifiableGroupInfo`] from the [`Welcome`] message.
    verifiable_group_info: VerifiableGroupInfo,

    /// The key package bundle used for this welcome.
    pub(crate) key_package_bundle: KeyPackageBundle,

    /// If we got a path secret, these are the derived path keys.
    path_keypairs: Option<Vec<EncryptionKeyPair>>,
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
        ciphersuite: Ciphersuite,
        credential_with_key: CredentialWithKey,
    ) -> Self {
        let public_group_builder = PublicGroup::builder(group_id, ciphersuite, credential_with_key);
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

    /// Set the [`Capabilities`] of the group's creator.
    pub(crate) fn with_capabilities(mut self, capabilities: Capabilities) -> Self {
        self.public_group_builder = self.public_group_builder.with_capabilities(capabilities);
        self
    }

    /// Sets initial group context extensions. Note that RequiredCapabilities
    /// extensions will be overwritten, and should be set using a call to
    /// `required_capabilities`. If `ExternalSenders` extensions are provided
    /// both in this call, and a call to `external_senders`, only the one from
    /// the call to `external_senders` will be included.
    pub(crate) fn with_group_context_extensions(
        mut self,
        extensions: Extensions,
    ) -> Result<Self, InvalidExtensionError> {
        self.public_group_builder = self
            .public_group_builder
            .with_group_context_extensions(extensions)?;
        Ok(self)
    }

    /// Sets extensions of the group creator's [`LeafNode`].
    pub(crate) fn with_leaf_node_extensions(
        mut self,
        extensions: Extensions,
    ) -> Result<Self, InvalidExtensionError> {
        self.public_group_builder = self
            .public_group_builder
            .with_leaf_node_extensions(extensions)?;
        Ok(self)
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
    /// [`OpenMlsProvider`].
    pub(crate) fn build<Provider: OpenMlsProvider>(
        self,
        provider: &Provider,
        signer: &impl Signer,
    ) -> Result<CoreGroup, CoreGroupBuildError<Provider::StorageError>> {
        let (public_group_builder, commit_secret, leaf_keypair) =
            self.public_group_builder.get_secrets(provider, signer)?;

        let ciphersuite = public_group_builder.group_context().ciphersuite();
        let config = self.config.unwrap_or_default();

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
            provider.crypto(),
            ciphersuite,
            commit_secret,
            &InitSecret::random(ciphersuite, provider.rand())
                .map_err(LibraryError::unexpected_crypto_error)?,
            &serialized_group_context,
        )
        .map_err(LibraryError::unexpected_crypto_error)?;

        // TODO(#1357)
        let resumption_psk_store = ResumptionPskStore::new(32);

        // Prepare the PskSecret
        let psk_secret = {
            let psks = load_psks(provider.storage(), &resumption_psk_store, &self.psk_ids)?;

            PskSecret::new(provider.crypto(), ciphersuite, psks)?
        };

        let mut key_schedule =
            KeySchedule::init(ciphersuite, provider.crypto(), &joiner_secret, psk_secret)?;
        key_schedule
            .add_context(provider.crypto(), &serialized_group_context)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;

        let epoch_secrets = key_schedule
            .epoch_secrets(provider.crypto(), ciphersuite)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;

        let (group_epoch_secrets, message_secrets) = epoch_secrets.split_secrets(
            serialized_group_context,
            TreeSize::new(1),
            LeafNodeIndex::new(0u32),
        );

        let initial_confirmation_tag = message_secrets
            .confirmation_key()
            .tag(provider.crypto(), ciphersuite, &[])
            .map_err(LibraryError::unexpected_crypto_error)?;

        let message_secrets_store =
            MessageSecretsStore::new_with_secret(self.max_past_epochs, message_secrets);

        let public_group = public_group_builder
            .with_confirmation_tag(initial_confirmation_tag)
            .build(provider.crypto())?;

        let group = CoreGroup {
            public_group,
            group_epoch_secrets,
            use_ratchet_tree_extension: config.add_ratchet_tree_extension,
            message_secrets_store,
            own_leaf_index: LeafNodeIndex::new(0),
            resumption_psk_store,
        };

        // Store the group state
        group
            .store(provider.storage())
            .map_err(CoreGroupBuildError::StorageError)?;

        // Store the private key of the own leaf in the key store as an epoch keypair.
        group
            .store_epoch_keypairs(provider.storage(), &[leaf_keypair])
            .map_err(CoreGroupBuildError::StorageError)?;

        Ok(group)
    }
}

impl MlsGroup {
    /// Get a builder for [`CoreGroup`].
    pub(crate) fn internal_builder(
        group_id: GroupId,
        ciphersuite: Ciphersuite,
        credential_with_key: CredentialWithKey,
    ) -> CoreGroupBuilder {
        CoreGroupBuilder::new(group_id, ciphersuite, credential_with_key)
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
        if let Some(required_capabilities) = self.required_capabilities() {
            joiner_key_package
                .leaf_node()
                .capabilities()
                .supports_required_capabilities(required_capabilities)?;
        }
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
        if self.public_group().leaf(removed).is_none() {
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

    pub(crate) fn create_custom_proposal(
        &self,
        framing_parameters: FramingParameters,
        custom_proposal: CustomProposal,
        signer: &impl Signer,
    ) -> Result<AuthenticatedContent, LibraryError> {
        let proposal = Proposal::Custom(custom_proposal);
        AuthenticatedContent::member_proposal(
            framing_parameters,
            self.own_leaf_index(),
            proposal,
            self.context(),
            signer,
        )
    }

    // Create application message
    pub(crate) fn create_application_message<Provider: OpenMlsProvider>(
        &mut self,
        aad: &[u8],
        msg: &[u8],
        padding_size: usize,
        provider: &Provider,
        signer: &impl Signer,
    ) -> Result<PrivateMessage, MessageEncryptionError<Provider::StorageError>> {
        let public_message = AuthenticatedContent::new_application(
            self.own_leaf_index(),
            aad,
            msg,
            self.context(),
            signer,
        )?;
        self.encrypt(public_message, padding_size, provider)
    }

    // Encrypt an PublicMessage into an PrivateMessage
    pub(crate) fn encrypt<Provider: OpenMlsProvider>(
        &mut self,
        public_message: AuthenticatedContent,
        padding_size: usize,
        provider: &Provider,
    ) -> Result<PrivateMessage, MessageEncryptionError<Provider::StorageError>> {
        let msg = PrivateMessage::try_from_authenticated_content(
            &public_message,
            self.ciphersuite(),
            provider,
            self.message_secrets_store.message_secrets_mut(),
            padding_size,
        )?;

        provider
            .storage()
            .write_message_secrets(self.group_id(), &self.message_secrets_store)
            .map_err(MessageEncryptionError::StorageError)?;

        Ok(msg)
    }

    /// Exporter
    pub(crate) fn export_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
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
            .derive_exported_secret(self.ciphersuite(), crypto, label, context, key_length)
            .map_err(LibraryError::unexpected_crypto_error)?)
    }

    pub(crate) fn export_group_info(
        &self,
        crypto: &impl OpenMlsCrypto,
        signer: &impl Signer,
        with_ratchet_tree: bool,
    ) -> Result<GroupInfo, LibraryError> {
        let extensions = {
            let ratchet_tree_extension = || {
                Extension::RatchetTree(RatchetTreeExtension::new(
                    self.public_group().export_ratchet_tree(),
                ))
            };

            let external_pub_extension = || {
                let external_pub = self
                    .group_epoch_secrets()
                    .external_secret()
                    .derive_external_keypair(crypto, self.ciphersuite())
                    .map_err(LibraryError::unexpected_crypto_error)?
                    .public;
                Ok(Extension::ExternalPub(ExternalPubExtension::new(
                    HpkePublicKey::from(external_pub),
                )))
            };

            if with_ratchet_tree {
                Extensions::from_vec(vec![ratchet_tree_extension(), external_pub_extension()?])
                    .map_err(|_| {
                        LibraryError::custom(
                            "There should not have been duplicate extensions here.",
                        )
                    })?
            } else {
                Extensions::single(external_pub_extension()?)
            }
        };

        // Create to-be-signed group info.
        let group_info_tbs = GroupInfoTBS::new(
            self.context().clone(),
            extensions,
            self.message_secrets()
                .confirmation_key()
                .tag(
                    crypto,
                    self.ciphersuite(),
                    self.context().confirmed_transcript_hash(),
                )
                .map_err(LibraryError::unexpected_crypto_error)?,
            self.own_leaf_index(),
        );

        // Sign to-be-signed group info.
        group_info_tbs
            .sign(signer)
            .map_err(|_| LibraryError::custom("Signing failed"))
    }
}

// Test functions
#[cfg(test)]
impl CoreGroup {
    pub(crate) fn set_own_leaf_index(&mut self, own_leaf_index: LeafNodeIndex) {
        self.own_leaf_index = own_leaf_index;
    }

    pub(crate) fn own_tree_position(&self) -> TreePosition {
        TreePosition::new(self.group_id().clone(), self.own_leaf_index())
    }

    pub(crate) fn message_secrets_store(&self) -> &MessageSecretsStore {
        &self.message_secrets_store
    }

    pub(crate) fn set_group_context(&mut self, group_context: GroupContext) {
        self.public_group.set_group_context(group_context)
    }
}

// Test and test-utils functions
#[cfg_attr(all(not(test), feature = "test-utils"), allow(dead_code))]
#[cfg(any(feature = "test-utils", test))]
impl CoreGroup {
    pub(crate) fn context_mut(&mut self) -> &mut GroupContext {
        self.public_group.context_mut()
    }

    pub(crate) fn message_secrets_test_mut(&mut self) -> &mut MessageSecrets {
        self.message_secrets_store.message_secrets_mut()
    }

    pub(crate) fn print_ratchet_tree(&self, message: &str) {
        println!("{}: {}", message, self.public_group().export_ratchet_tree());
    }

    pub(crate) fn resumption_psk_store(&self) -> &ResumptionPskStore {
        &self.resumption_psk_store
    }
}

/// Configuration for core group.
#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct CoreGroupConfig {
    /// Flag whether to send the ratchet tree along with the `GroupInfo` or not.
    /// Defaults to false.
    pub(crate) add_ratchet_tree_extension: bool,
}
