use openmls_traits::{signatures::Signer, types::Ciphersuite};

use crate::{
    credentials::CredentialWithKey,
    error::LibraryError,
    extensions::{errors::InvalidExtensionError, Extensions},
    group::{
        public_group::errors::PublicGroupBuildError, CoreGroup, CoreGroupBuildError,
        CoreGroupConfig, GroupId, MlsGroupCreateConfig, MlsGroupCreateConfigBuilder, NewGroupError,
        ProposalStore, WireFormatPolicy,
    },
    key_packages::Lifetime,
    storage::RefinedProvider,
    tree::sender_ratchet::SenderRatchetConfiguration,
    treesync::node::leaf_node::Capabilities,
};

use super::{MlsGroup, MlsGroupState};

#[derive(Default, Debug)]
pub struct MlsGroupBuilder {
    group_id: Option<GroupId>,
    mls_group_create_config_builder: MlsGroupCreateConfigBuilder,
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
    pub fn build<Provider: RefinedProvider>(
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
    pub(super) fn build_internal<Provider: RefinedProvider>(
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
        // TODO #751
        let group_config = CoreGroupConfig {
            add_ratchet_tree_extension: mls_group_create_config
                .join_config
                .use_ratchet_tree_extension,
        };

        let mut group = CoreGroup::builder(
            group_id,
            mls_group_create_config.ciphersuite,
            credential_with_key,
        )
        .with_config(group_config)
        .with_group_context_extensions(mls_group_create_config.group_context_extensions.clone())?
        .with_leaf_node_extensions(mls_group_create_config.leaf_node_extensions.clone())?
        .with_capabilities(mls_group_create_config.capabilities.clone())
        .with_max_past_epoch_secrets(mls_group_create_config.join_config.max_past_epochs)
        .with_lifetime(*mls_group_create_config.lifetime())
        .build(provider, signer)
        .map_err(|e| match e {
            CoreGroupBuildError::LibraryError(e) => e.into(),
            // We don't support PSKs yet
            CoreGroupBuildError::Psk(e) => {
                log::debug!("Unexpected PSK error: {:?}", e);
                LibraryError::custom("Unexpected PSK error").into()
            }
            CoreGroupBuildError::StorageError(e) => NewGroupError::StorageError(e),
            CoreGroupBuildError::PublicGroupBuildError(e) => match e {
                PublicGroupBuildError::LibraryError(e) => e.into(),
                PublicGroupBuildError::InvalidExtensions(e) => NewGroupError::InvalidExtensions(e),
            },
        })?;

        // We already add a resumption PSK for epoch 0 to make things more unified.
        let resumption_psk = group.group_epoch_secrets().resumption_psk();
        group
            .resumption_psk_store
            .add(group.context().epoch(), resumption_psk.clone());

        let mls_group = MlsGroup {
            mls_group_config: mls_group_create_config.join_config.clone(),
            group,
            proposal_store: ProposalStore::new(),
            own_leaf_nodes: vec![],
            aad: vec![],
            group_state: MlsGroupState::Operational,
        };

        use openmls_traits::storage::StorageProvider as _;

        provider
            .storage()
            .write_mls_join_config(mls_group.group_id(), &mls_group.mls_group_config)
            .map_err(NewGroupError::StorageError)?;
        provider
            .storage()
            .write_group_state(mls_group.group_id(), &mls_group.group_state)
            .map_err(NewGroupError::StorageError)?;
        mls_group
            .group
            .store(provider.storage())
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
    ) -> Result<Self, InvalidExtensionError> {
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
