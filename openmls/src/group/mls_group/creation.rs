use super::*;

impl MlsGroup {
    // === Group creation ===

    /// Creates a new group from scratch with only the creator as a member. This
    /// function removes the `KeyPackageBundle` corresponding to the
    /// `key_package_hash` from the `backend`. Throws an error if no
    /// `KeyPackageBundle` can be found.
    pub fn new(
        backend: &impl OpenMlsCryptoProvider,
        mls_group_config: &MlsGroupConfig,
        group_id: GroupId,
        key_package_hash: &[u8],
    ) -> Result<Self, MlsGroupError> {
        // TODO #141
        let kph = key_package_hash.to_vec();
        let key_package_bundle: KeyPackageBundle = backend
            .key_store()
            .read(&kph)
            .ok_or(MlsGroupError::NoMatchingKeyPackageBundle)?;
        backend
            .key_store()
            .delete(&kph)
            .map_err(|_| MlsGroupError::KeyStoreError)?;
        let group_config = CoreGroupConfig {
            add_ratchet_tree_extension: mls_group_config.use_ratchet_tree_extension,
            ..Default::default()
        };
        let group = CoreGroup::builder(group_id, key_package_bundle)
            .with_config(group_config)
            .with_required_capabilities(mls_group_config.required_capabilities.clone())
            .build(backend)?;

        let resumption_secret_store =
            ResumptionSecretStore::new(mls_group_config.number_of_resumption_secrets);

        let mls_group = MlsGroup {
            mls_group_config: mls_group_config.clone(),
            group,
            proposal_store: ProposalStore::new(),
            message_secrets_store: MessageSecretsStore::new(mls_group_config.max_past_epochs()),
            own_kpbs: vec![],
            aad: vec![],
            resumption_secret_store,
            active: true,
            state_changed: InnerState::Changed,
        };

        Ok(mls_group)
    }

    /// Creates a new group from a `Welcome` message
    pub fn new_from_welcome(
        backend: &impl OpenMlsCryptoProvider,
        mls_group_config: &MlsGroupConfig,
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
    ) -> Result<Self, MlsGroupError> {
        let resumption_secret_store =
            ResumptionSecretStore::new(mls_group_config.number_of_resumption_secrets);
        let key_package_bundle = welcome
            .secrets()
            .iter()
            .find_map(|egs| {
                backend
                    .key_store()
                    .read(&egs.key_package_hash.as_slice().to_vec())
            })
            .ok_or(MlsGroupError::NoMatchingKeyPackageBundle)?;
        // TODO #141
        let group =
            CoreGroup::new_from_welcome(welcome, ratchet_tree, key_package_bundle, backend)?;

        let mls_group = MlsGroup {
            mls_group_config: mls_group_config.clone(),
            group,
            proposal_store: ProposalStore::new(),
            message_secrets_store: MessageSecretsStore::new(mls_group_config.max_past_epochs()),
            own_kpbs: vec![],
            aad: vec![],
            resumption_secret_store,
            active: true,
            state_changed: InnerState::Changed,
        };

        Ok(mls_group)
    }
}
