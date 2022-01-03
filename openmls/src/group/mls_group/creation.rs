use crate::{
    config::Config, group::core_group::create_commit_params::CreateCommitParams,
    messages::VerifiablePublicGroupState,
};

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
            .with_max_past_epoch_secrets(mls_group_config.max_past_epochs)
            .build(backend)?;

        let resumption_secret_store =
            ResumptionSecretStore::new(mls_group_config.number_of_resumption_secrets);

        let mls_group = MlsGroup {
            mls_group_config: mls_group_config.clone(),
            group,
            proposal_store: ProposalStore::new(),
            own_kpbs: vec![],
            aad: vec![],
            resumption_secret_store,
            group_state: MlsGroupState::Operational,
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
        let mut group =
            CoreGroup::new_from_welcome(welcome, ratchet_tree, key_package_bundle, backend)?;
        group.set_max_past_epochs(mls_group_config.max_past_epochs);

        let mls_group = MlsGroup {
            mls_group_config: mls_group_config.clone(),
            group,
            proposal_store: ProposalStore::new(),
            own_kpbs: vec![],
            aad: vec![],
            resumption_secret_store,
            group_state: MlsGroupState::Operational,
            state_changed: InnerState::Changed,
        };

        Ok(mls_group)
    }

    /// Join an existing group through an External Commit.
    /// The resulting [`MlsGroup`] instance starts off with a pending
    /// commit (the external commit, which adds this client to the group).
    /// Merging this commit is necessary for this [`MlsGroup`] instance to
    /// function properly, as, for example, this client is not yet part of the
    /// tree. As a result, it is not possible to clear the pending commit. If
    /// the external commit was rejected due to an epoch change, the
    /// [`MlsGroup`] instance has to be discarded and a new one has to be
    /// created using this function based on the latest `ratchet_tree` and
    /// public group state. For more information on the external init process,
    /// please see Section 11.2.1 in the MLS specification.
    pub fn join_by_external_commit(
        backend: &impl OpenMlsCryptoProvider,
        tree_option: Option<&[Option<Node>]>,
        verifiable_public_group_state: VerifiablePublicGroupState,
        mls_group_config: &MlsGroupConfig,
        aad: &[u8],
        credential_bundle: &CredentialBundle,
        proposals_by_reference: &[MlsPlaintext],
    ) -> Result<(Self, MlsMessageOut), MlsGroupError> {
        let resumption_secret_store =
            ResumptionSecretStore::new(mls_group_config.number_of_resumption_secrets);

        // Prepare the commit parameters
        let framing_parameters = FramingParameters::new(aad, mls_group_config.wire_format());
        let ciphersuite = Config::ciphersuite(verifiable_public_group_state.ciphersuite())?;
        let mut proposal_store = ProposalStore::new();
        for proposal in proposals_by_reference {
            let queued_proposal =
                QueuedProposal::from_mls_plaintext(ciphersuite, backend, proposal.clone())
                    .map_err(CoreGroupError::QueuedProposalError)?;
            proposal_store.add(queued_proposal);
        }

        let params = CreateCommitParams::builder()
            .framing_parameters(framing_parameters)
            .credential_bundle(credential_bundle)
            .proposal_store(&proposal_store)
            .build();
        let (mut group, create_commit_result) = CoreGroup::join_by_external_commit(
            backend,
            params,
            tree_option,
            verifiable_public_group_state,
        )?;
        group.set_max_past_epochs(mls_group_config.max_past_epochs);

        let mls_group = MlsGroup {
            mls_group_config: mls_group_config.clone(),
            group,
            proposal_store: ProposalStore::new(),
            own_kpbs: vec![],
            aad: vec![],
            resumption_secret_store,
            group_state: MlsGroupState::PendingCommit(Box::new(PendingCommitState::External(
                create_commit_result.staged_commit,
            ))),
            state_changed: InnerState::Changed,
        };

        Ok((mls_group, create_commit_result.commit.into()))
    }
}
