use crate::{
    ciphersuite::signature::SignaturePublicKey,
    group::{
        core_group::create_commit_params::CreateCommitParams,
        errors::{CoreGroupBuildError, ExternalCommitError, WelcomeError},
    },
    messages::VerifiableGroupInfo,
};

use super::*;

impl MlsGroup {
    // === Group creation ===

    /// Creates a new group with the creator as the only member (and a random group ID).
    ///
    /// This function removes the private key corresponding to the
    /// `key_package` from the key store.
    ///
    /// Returns an error ([`NewGroupError::NoMatchingCredentialBundle`]) if the
    /// private key for the [`SignaturePublicKey`] can not be found.
    pub fn new<KeyStore: OpenMlsKeyStore>(
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        mls_group_config: &MlsGroupConfig,
        signature_key: SignaturePublicKey,
        credential: Credential,
    ) -> Result<Self, NewGroupError<KeyStore::Error>> {
        Self::new_with_group_id(
            backend,
            mls_group_config,
            GroupId::random(backend),
            signature_key,
            credential,
        )
    }

    /// Creates a new group with a given group ID with the creator as the only member.
    ///
    /// Returns an error ([`NewGroupError::NoMatchingCredentialBundle`]) if the
    /// private key for the [`SignaturePublicKey`] can not be found.
    pub fn new_with_group_id<KeyStore: OpenMlsKeyStore>(
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        mls_group_config: &MlsGroupConfig,
        group_id: GroupId,
        signature_key: SignaturePublicKey,
        credential: Credential,
    ) -> Result<Self, NewGroupError<KeyStore::Error>> {
        // TODO #751
        let group_config = CoreGroupConfig {
            add_ratchet_tree_extension: mls_group_config.use_ratchet_tree_extension,
        };

        let group = CoreGroup::builder(
            group_id,
            mls_group_config.crypto_config,
            credential,
            signature_key,
        )
        .with_config(group_config)
        .with_required_capabilities(mls_group_config.required_capabilities.clone())
        .with_max_past_epoch_secrets(mls_group_config.max_past_epochs)
        .with_lifetime(*mls_group_config.lifetime())
        .build(backend)
        .map_err(|e| match e {
            CoreGroupBuildError::LibraryError(e) => e.into(),
            CoreGroupBuildError::UnsupportedProposalType => NewGroupError::UnsupportedProposalType,
            CoreGroupBuildError::UnsupportedExtensionType => {
                NewGroupError::UnsupportedExtensionType
            }
            // We don't support PSKs yet
            CoreGroupBuildError::PskError(e) => {
                log::debug!("Unexpected PSK error: {:?}", e);
                LibraryError::custom("Unexpected PSK error").into()
            }
            CoreGroupBuildError::KeyStoreError(e) => NewGroupError::KeyStoreError(e),
        })?;

        let resumption_psk_store =
            ResumptionPskStore::new(mls_group_config.number_of_resumption_psks);

        let mls_group = MlsGroup {
            mls_group_config: mls_group_config.clone(),
            group,
            proposal_store: ProposalStore::new(),
            own_leaf_nodes: vec![],
            aad: vec![],
            resumption_psk_store,
            group_state: MlsGroupState::Operational,
            state_changed: InnerState::Changed,
        };

        Ok(mls_group)
    }

    /// Creates a new group from a [`Welcome`] message. Returns an error
    /// ([`WelcomeError::NoMatchingKeyPackage`]) if no [`KeyPackage`]
    /// can be found.
    pub fn new_from_welcome<KeyStore: OpenMlsKeyStore>(
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        mls_group_config: &MlsGroupConfig,
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
    ) -> Result<Self, WelcomeError<KeyStore::Error>> {
        let resumption_psk_store =
            ResumptionPskStore::new(mls_group_config.number_of_resumption_psks);
        let (key_package, _) = welcome
            .secrets()
            .iter()
            .find_map(|egs| {
                let hash_ref = egs.new_member().as_slice().to_vec();
                backend
                    .key_store()
                    .read(&hash_ref)
                    .map(|kp: KeyPackage| (kp, hash_ref))
            })
            .ok_or(WelcomeError::NoMatchingKeyPackage)?;

        // TODO #751
        let private_key: Vec<u8> = backend
            .key_store()
            .read(key_package.hpke_init_key().as_slice())
            .ok_or(WelcomeError::NoMatchingKeyPackage)?;
        let key_package_bundle = KeyPackageBundle {
            key_package,
            private_key: private_key.into(),
        };

        // Delete the [`KeyPackage`] and the corresponding private key from the
        // key store
        key_package_bundle
            .key_package
            .delete(backend)
            .map_err(WelcomeError::KeyStoreError)?;

        let mut group =
            CoreGroup::new_from_welcome(welcome, ratchet_tree, key_package_bundle, backend)?;
        group.set_max_past_epochs(mls_group_config.max_past_epochs);

        let mls_group = MlsGroup {
            mls_group_config: mls_group_config.clone(),
            group,
            proposal_store: ProposalStore::new(),
            own_leaf_nodes: vec![],
            aad: vec![],
            resumption_psk_store,
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
    /// group info. For more information on the external init process,
    /// please see Section 11.2.1 in the MLS specification.
    pub fn join_by_external_commit(
        backend: &impl OpenMlsCryptoProvider,
        tree_option: Option<&[Option<Node>]>,
        verifiable_group_info: VerifiableGroupInfo,
        mls_group_config: &MlsGroupConfig,
        aad: &[u8],
        credential: Credential,
        signature_key: SignaturePublicKey,
    ) -> Result<(Self, MlsMessageOut), ExternalCommitError> {
        let resumption_psk_store =
            ResumptionPskStore::new(mls_group_config.number_of_resumption_psks);

        // Prepare the commit parameters
        let framing_parameters = FramingParameters::new(aad, WireFormat::PublicMessage);

        let proposal_store = ProposalStore::new();
        let params = CreateCommitParams::builder()
            .framing_parameters(framing_parameters)
            .proposal_store(&proposal_store)
            .credential(credential)
            .signature_key(signature_key)
            .build();
        let (mut group, create_commit_result) = CoreGroup::join_by_external_commit(
            backend,
            params,
            tree_option,
            verifiable_group_info,
        )?;
        group.set_max_past_epochs(mls_group_config.max_past_epochs);

        let mls_group = MlsGroup {
            mls_group_config: mls_group_config.clone(),
            group,
            proposal_store: ProposalStore::new(),
            own_leaf_nodes: vec![],
            aad: vec![],
            resumption_psk_store,
            group_state: MlsGroupState::PendingCommit(Box::new(PendingCommitState::External(
                create_commit_result.staged_commit,
            ))),
            state_changed: InnerState::Changed,
        };

        let public_message: PublicMessage = create_commit_result.commit.into();
        Ok((mls_group, public_message.into()))
    }
}
