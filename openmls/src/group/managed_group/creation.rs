use super::*;

impl ManagedGroup {
    // === Group creation ===

    /// Creates a new group from scratch with only the creator as a member. This
    /// function removes the `KeyPackageBundle` corresponding to the
    /// `key_package_hash` from the `backend`. Throws an error if no
    /// `KeyPackageBundle` can be found.
    pub fn new(
        backend: &impl OpenMlsCryptoProvider,
        managed_group_config: &ManagedGroupConfig,
        group_id: GroupId,
        key_package_hash: &[u8],
    ) -> Result<Self, ManagedGroupError> {
        // TODO #141
        let kph = key_package_hash.to_vec();
        let key_package_bundle: KeyPackageBundle = backend
            .key_store()
            .read(&kph)
            .ok_or(ManagedGroupError::NoMatchingKeyPackageBundle)?;
        backend
            .key_store()
            .delete(&kph)
            .map_err(|_| ManagedGroupError::KeyStoreError)?;
        let group_config = MlsGroupConfig {
            add_ratchet_tree_extension: managed_group_config.use_ratchet_tree_extension,
            ..Default::default()
        };
        let group = MlsGroup::new(
            group_id.as_slice(),
            key_package_bundle.key_package().ciphersuite_name(),
            backend,
            key_package_bundle,
            group_config,
            None, /* Initial PSK */
            None, /* MLS version */
            managed_group_config.required_capabilities.clone(),
        )?;

        let resumption_secret_store =
            ResumptionSecretStore::new(managed_group_config.number_of_resumption_secrets);

        let managed_group = ManagedGroup {
            managed_group_config: managed_group_config.clone(),
            group,
            proposal_store: ProposalStore::new(),
            own_kpbs: vec![],
            aad: vec![],
            resumption_secret_store,
            active: true,
        };

        // Since the state of the group was changed, call the auto-save function
        managed_group.auto_save();

        Ok(managed_group)
    }

    /// Creates a new group from a `Welcome` message
    pub fn new_from_welcome(
        backend: &impl OpenMlsCryptoProvider,
        managed_group_config: &ManagedGroupConfig,
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
    ) -> Result<Self, ManagedGroupError> {
        let resumption_secret_store =
            ResumptionSecretStore::new(managed_group_config.number_of_resumption_secrets);
        let key_package_bundle = welcome
            .secrets()
            .iter()
            .find_map(|egs| {
                backend
                    .key_store()
                    .read(&egs.key_package_hash.as_slice().to_vec())
            })
            .ok_or(ManagedGroupError::NoMatchingKeyPackageBundle)?;
        // TODO #141
        let group =
            MlsGroup::new_from_welcome(welcome, ratchet_tree, key_package_bundle, None, backend)?;

        let managed_group = ManagedGroup {
            managed_group_config: managed_group_config.clone(),
            group,
            proposal_store: ProposalStore::new(),
            own_kpbs: vec![],
            aad: vec![],
            resumption_secret_store,
            active: true,
        };

        // Since the state of the group was changed, call the auto-save function
        managed_group.auto_save();

        Ok(managed_group)
    }
}
