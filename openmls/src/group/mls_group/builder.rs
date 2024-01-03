use openmls_traits::{key_store::OpenMlsKeyStore, signatures::Signer, OpenMlsProvider};

use crate::{
    credentials::CredentialWithKey,
    group::{
        config::CryptoConfig, public_group::errors::PublicGroupBuildError, CoreGroup,
        CoreGroupBuildError, CoreGroupConfig, GroupId, MlsGroupConfig, MlsGroupConfigBuilder,
        NewGroupError, ProposalStore, WireFormatPolicy,
    },
    prelude::{LibraryError, Lifetime, SenderRatchetConfiguration},
};

use super::{InnerState, MlsGroup, MlsGroupState};

#[derive(Default)]
pub struct MlsGroupBuilder {
    group_id: Option<GroupId>,
    mls_group_config_builder: MlsGroupConfigBuilder,
}

impl MlsGroupBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_group_id(mut self, group_id: GroupId) -> Self {
        self.group_id = Some(group_id);
        self
    }

    pub fn build<KeyStore: OpenMlsKeyStore>(
        self,
        provider: &impl OpenMlsProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
    ) -> Result<MlsGroup, NewGroupError<KeyStore::Error>> {
        self.build_internal(provider, signer, credential_with_key, None)
    }

    /// Build a new group with the given group ID.
    ///
    /// If an [`MlsGroupConfig`] is provided, it will be used to configure the
    /// group. Otherwise, the internal builder is used to build one with the
    /// parameters set on this builder.
    pub(super) fn build_internal<KeyStore: OpenMlsKeyStore>(
        self,
        provider: &impl OpenMlsProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
        mls_group_config_option: Option<MlsGroupConfig>,
    ) -> Result<MlsGroup, NewGroupError<KeyStore::Error>> {
        let mls_group_config =
            mls_group_config_option.unwrap_or_else(|| self.mls_group_config_builder.build());
        let group_id = self
            .group_id
            .unwrap_or_else(|| GroupId::random(provider.rand()));
        // TODO #751
        let group_config = CoreGroupConfig {
            add_ratchet_tree_extension: mls_group_config.use_ratchet_tree_extension,
        };

        let mut group = CoreGroup::builder(
            group_id,
            mls_group_config.crypto_config,
            credential_with_key,
        )
        .with_config(group_config)
        .with_required_capabilities(mls_group_config.required_capabilities.clone())
        .with_external_senders(mls_group_config.external_senders.clone())
        .with_max_past_epoch_secrets(mls_group_config.max_past_epochs)
        .with_lifetime(*mls_group_config.lifetime())
        .build(provider, signer)
        .map_err(|e| match e {
            CoreGroupBuildError::LibraryError(e) => e.into(),
            // We don't support PSKs yet
            CoreGroupBuildError::Psk(e) => {
                log::debug!("Unexpected PSK error: {:?}", e);
                LibraryError::custom("Unexpected PSK error").into()
            }
            CoreGroupBuildError::KeyStoreError(e) => NewGroupError::KeyStoreError(e),
            CoreGroupBuildError::PublicGroupBuildError(e) => match e {
                PublicGroupBuildError::LibraryError(e) => e.into(),
                PublicGroupBuildError::UnsupportedProposalType => {
                    NewGroupError::UnsupportedProposalType
                }
                PublicGroupBuildError::UnsupportedExtensionType => {
                    NewGroupError::UnsupportedExtensionType
                }
                PublicGroupBuildError::InvalidExtensions(e) => NewGroupError::InvalidExtensions(e),
            },
        })?;

        // We already add a resumption PSK for epoch 0 to make things more unified.
        let resumption_psk = group.group_epoch_secrets().resumption_psk();
        group
            .resumption_psk_store
            .add(group.context().epoch(), resumption_psk.clone());

        let mls_group = MlsGroup {
            mls_group_config: mls_group_config.clone(),
            group,
            proposal_store: ProposalStore::new(),
            own_leaf_nodes: vec![],
            aad: vec![],
            group_state: MlsGroupState::Operational,
            state_changed: InnerState::Changed,
        };

        Ok(mls_group)
    }

    // MLSGroupConfigBuilder options

    /// Sets the `wire_format` property of the MlsGroupConfig.
    pub fn with_wire_format_policy(mut self, wire_format_policy: WireFormatPolicy) -> Self {
        self.mls_group_config_builder = self
            .mls_group_config_builder
            .wire_format_policy(wire_format_policy);
        self
    }

    /// Sets the `padding_size` property of the MlsGroupConfig.
    pub fn padding_size(mut self, padding_size: usize) -> Self {
        self.mls_group_config_builder = self.mls_group_config_builder.padding_size(padding_size);
        self
    }

    /// Sets the `max_past_epochs` property of the MlsGroupConfig.
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
        self.mls_group_config_builder = self
            .mls_group_config_builder
            .max_past_epochs(max_past_epochs);
        self
    }

    /// Sets the `number_of_resumption_psks` property of the MlsGroupConfig.
    pub fn number_of_resumption_psks(mut self, number_of_resumption_psks: usize) -> Self {
        self.mls_group_config_builder = self
            .mls_group_config_builder
            .number_of_resumption_psks(number_of_resumption_psks);
        self
    }

    /// Sets the `use_ratchet_tree_extension` property of the MlsGroupConfig.
    pub fn use_ratchet_tree_extension(mut self, use_ratchet_tree_extension: bool) -> Self {
        self.mls_group_config_builder = self
            .mls_group_config_builder
            .use_ratchet_tree_extension(use_ratchet_tree_extension);
        self
    }

    /// Sets the `sender_ratchet_configuration` property of the MlsGroupConfig.
    /// See [`SenderRatchetConfiguration`] for more information.
    pub fn sender_ratchet_configuration(
        mut self,
        sender_ratchet_configuration: SenderRatchetConfiguration,
    ) -> Self {
        self.mls_group_config_builder = self
            .mls_group_config_builder
            .sender_ratchet_configuration(sender_ratchet_configuration);
        self
    }

    /// Sets the `lifetime` property of the MlsGroupConfig.
    pub fn lifetime(mut self, lifetime: Lifetime) -> Self {
        self.mls_group_config_builder = self.mls_group_config_builder.lifetime(lifetime);
        self
    }

    /// Sets the `crypto_config` property of the MlsGroupConfig.
    pub fn crypto_config(mut self, config: CryptoConfig) -> Self {
        self.mls_group_config_builder = self.mls_group_config_builder.crypto_config(config);
        self
    }
}
