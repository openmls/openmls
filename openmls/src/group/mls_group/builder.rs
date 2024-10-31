use openmls_traits::{signatures::Signer, types::Ciphersuite};
use tls_codec::Serialize;

use crate::{
    binary_tree::array_representation::TreeSize,
    credentials::CredentialWithKey,
    error::LibraryError,
    extensions::{errors::InvalidExtensionError, Extensions},
    group::{
        public_group::errors::PublicGroupBuildError, GroupId, MlsGroupCreateConfig,
        MlsGroupCreateConfigBuilder, NewGroupError, PublicGroup, WireFormatPolicy,
    },
    key_packages::Lifetime,
    prelude::LeafNodeIndex,
    schedule::{
        psk::{load_psks, store::ResumptionPskStore, PskSecret},
        InitSecret, JoinerSecret, KeySchedule, PreSharedKeyId,
    },
    storage::OpenMlsProvider,
    tree::sender_ratchet::SenderRatchetConfiguration,
    treesync::{errors::LeafNodeValidationError, node::leaf_node::Capabilities},
};

use super::{past_secrets::MessageSecretsStore, MlsGroup, MlsGroupState};

#[derive(Default, Debug)]
pub struct MlsGroupBuilder {
    group_id: Option<GroupId>,
    mls_group_create_config_builder: MlsGroupCreateConfigBuilder,
    psk_ids: Vec<PreSharedKeyId>,
}

impl MlsGroupBuilder {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Sets the group ID of the [`MlsGroup`].
    pub fn with_group_id(mut self, group_id: GroupId) -> Self {
        self.group_id = Some(group_id);
        self
    }

    /// Build a new group as configured by this builder.
    pub fn build<Provider: OpenMlsProvider>(
        self,
        provider: &Provider,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
    ) -> Result<MlsGroup, NewGroupError<Provider::StorageError>> {
        self.build_internal(provider, signer, credential_with_key, None)
    }

    /// Build a new group with the given group ID.
    ///
    /// If an [`MlsGroupCreateConfig`] is provided, it will be used to configure the
    /// group. Otherwise, the internal builder is used to build one with the
    /// parameters set on this builder.
    pub(super) fn build_internal<Provider: OpenMlsProvider>(
        self,
        provider: &Provider,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
        mls_group_create_config_option: Option<MlsGroupCreateConfig>,
    ) -> Result<MlsGroup, NewGroupError<Provider::StorageError>> {
        let mls_group_create_config = mls_group_create_config_option
            .unwrap_or_else(|| self.mls_group_create_config_builder.build());
        let group_id = self
            .group_id
            .unwrap_or_else(|| GroupId::random(provider.rand()));
        let ciphersuite = mls_group_create_config.ciphersuite;

        let (public_group_builder, commit_secret, leaf_keypair) =
            PublicGroup::builder(group_id, ciphersuite, credential_with_key)
                .with_group_context_extensions(
                    mls_group_create_config.group_context_extensions.clone(),
                )?
                .with_leaf_node_extensions(mls_group_create_config.leaf_node_extensions.clone())?
                .with_lifetime(*mls_group_create_config.lifetime())
                .with_capabilities(mls_group_create_config.capabilities.clone())
                .get_secrets(provider, signer)
                .map_err(|e| match e {
                    PublicGroupBuildError::LibraryError(e) => NewGroupError::LibraryError(e),
                    PublicGroupBuildError::InvalidExtensions(e) => e.into(),
                })?;

        let serialized_group_context = public_group_builder
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

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
        let mut resumption_psk_store = ResumptionPskStore::new(32);

        // Prepare the PskSecret
        let psk_secret = load_psks(provider.storage(), &resumption_psk_store, &self.psk_ids)
            .and_then(|psks| PskSecret::new(provider.crypto(), ciphersuite, psks))
            .map_err(|e| {
                log::debug!("Unexpected PSK error: {:?}", e);
                LibraryError::custom("Unexpected PSK error")
            })?;

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

        let message_secrets_store = MessageSecretsStore::new_with_secret(
            mls_group_create_config.max_past_epochs(),
            message_secrets,
        );

        let public_group = public_group_builder
            .with_confirmation_tag(initial_confirmation_tag)
            .build(provider.crypto())?;

        // We already add a resumption PSK for epoch 0 to make things more unified.
        let resumption_psk = group_epoch_secrets.resumption_psk();
        resumption_psk_store.add(public_group.group_context().epoch(), resumption_psk.clone());

        let mls_group = MlsGroup {
            mls_group_config: mls_group_create_config.join_config.clone(),
            own_leaf_nodes: vec![],
            aad: vec![],
            group_state: MlsGroupState::Operational,
            public_group,
            group_epoch_secrets,
            own_leaf_index: LeafNodeIndex::new(0),
            message_secrets_store,
            resumption_psk_store,
        };

        mls_group
            .store(provider.storage())
            .map_err(NewGroupError::StorageError)?;
        mls_group
            .store_epoch_keypairs(provider.storage(), &[leaf_keypair])
            .map_err(NewGroupError::StorageError)?;

        Ok(mls_group)
    }

    // MlsGroupCreateConfigBuilder options

    /// Sets the `wire_format` property of the MlsGroup.
    pub fn with_wire_format_policy(mut self, wire_format_policy: WireFormatPolicy) -> Self {
        self.mls_group_create_config_builder = self
            .mls_group_create_config_builder
            .wire_format_policy(wire_format_policy);
        self
    }

    /// Sets the `padding_size` property of the MlsGroup.
    pub fn padding_size(mut self, padding_size: usize) -> Self {
        self.mls_group_create_config_builder = self
            .mls_group_create_config_builder
            .padding_size(padding_size);
        self
    }

    /// Sets the `max_past_epochs` property of the MlsGroup.
    /// This allows application messages from previous epochs to be decrypted.
    ///
    /// **WARNING**
    ///
    /// This feature enables the storage of message secrets from past epochs.
    /// It is a trade-off between functionality and forward secrecy and should only be enabled
    /// if the Delivery Service cannot guarantee that application messages will be sent in
    /// the same epoch in which they were generated. The number for `max_epochs` should be
    /// as low as possible.
    pub fn max_past_epochs(mut self, max_past_epochs: usize) -> Self {
        self.mls_group_create_config_builder = self
            .mls_group_create_config_builder
            .max_past_epochs(max_past_epochs);
        self
    }

    /// Sets the `number_of_resumption_psks` property of the MlsGroup.
    pub fn number_of_resumption_psks(mut self, number_of_resumption_psks: usize) -> Self {
        self.mls_group_create_config_builder = self
            .mls_group_create_config_builder
            .number_of_resumption_psks(number_of_resumption_psks);
        self
    }

    /// Sets the `use_ratchet_tree_extension` property of the MlsGroup.
    pub fn use_ratchet_tree_extension(mut self, use_ratchet_tree_extension: bool) -> Self {
        self.mls_group_create_config_builder = self
            .mls_group_create_config_builder
            .use_ratchet_tree_extension(use_ratchet_tree_extension);
        self
    }

    /// Sets the `sender_ratchet_configuration` property of the MlsGroup.
    /// See [`SenderRatchetConfiguration`] for more information.
    pub fn sender_ratchet_configuration(
        mut self,
        sender_ratchet_configuration: SenderRatchetConfiguration,
    ) -> Self {
        self.mls_group_create_config_builder = self
            .mls_group_create_config_builder
            .sender_ratchet_configuration(sender_ratchet_configuration);
        self
    }

    /// Sets the `lifetime` of the group creator's leaf.
    pub fn lifetime(mut self, lifetime: Lifetime) -> Self {
        self.mls_group_create_config_builder =
            self.mls_group_create_config_builder.lifetime(lifetime);
        self
    }

    /// Sets the `ciphersuite` of the MlsGroup.
    pub fn ciphersuite(mut self, ciphersuite: Ciphersuite) -> Self {
        self.mls_group_create_config_builder = self
            .mls_group_create_config_builder
            .ciphersuite(ciphersuite);
        self
    }

    /// Sets the initial group context extensions
    pub fn with_group_context_extensions(
        mut self,
        extensions: Extensions,
    ) -> Result<Self, InvalidExtensionError> {
        self.mls_group_create_config_builder = self
            .mls_group_create_config_builder
            .with_group_context_extensions(extensions)?;
        Ok(self)
    }

    /// Sets the initial leaf node extensions
    pub fn with_leaf_node_extensions(
        mut self,
        extensions: Extensions,
    ) -> Result<Self, LeafNodeValidationError> {
        self.mls_group_create_config_builder = self
            .mls_group_create_config_builder
            .with_leaf_node_extensions(extensions)?;
        Ok(self)
    }

    /// Sets the group creator's [`Capabilities`]
    pub fn with_capabilities(mut self, capabilities: Capabilities) -> Self {
        self.mls_group_create_config_builder = self
            .mls_group_create_config_builder
            .capabilities(capabilities);
        self
    }
}
