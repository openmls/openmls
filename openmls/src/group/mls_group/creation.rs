use openmls_traits::{signatures::Signer, storage};

use super::{builder::MlsGroupBuilder, *};
use crate::{
    ciphersuite::HpkePrivateKey,
    credentials::CredentialWithKey,
    group::{
        core_group::create_commit_params::CreateCommitParams,
        errors::{ExternalCommitError, WelcomeError},
    },
    messages::{
        group_info::{GroupInfo, VerifiableGroupInfo},
        Welcome,
    },
    schedule::psk::store::ResumptionPskStore,
    storage::RefinedProvider,
    treesync::RatchetTreeIn,
};

impl MlsGroup {
    // === Group creation ===

    /// Creates a builder which can be used to configure and build
    /// a new [`MlsGroup`].
    pub fn builder() -> MlsGroupBuilder {
        MlsGroupBuilder::new()
    }

    /// Creates a new group with the creator as the only member (and a random
    /// group ID).
    ///
    /// This function removes the private key corresponding to the
    /// `key_package` from the key store.
    pub fn new<KeyStore: OpenMlsKeyStore>(
        provider: &impl OpenMlsProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        mls_group_create_config: &MlsGroupCreateConfig,
        credential_with_key: CredentialWithKey,
    ) -> Result<Self, NewGroupError<KeyStore::Error>> {
        MlsGroupBuilder::new().build_internal(
            provider,
            signer,
            credential_with_key,
            Some(mls_group_create_config.clone()),
        )
    }

    /// Creates a new group with a given group ID with the creator as the only
    /// member.
    pub fn new_with_group_id<KeyStore: OpenMlsKeyStore>(
        provider: &impl OpenMlsProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        mls_group_create_config: &MlsGroupCreateConfig,
        group_id: GroupId,
        credential_with_key: CredentialWithKey,
    ) -> Result<Self, NewGroupError<KeyStore::Error>> {
        MlsGroupBuilder::new()
            .with_group_id(group_id)
            .build_internal(
                provider,
                signer,
                credential_with_key,
                Some(mls_group_create_config.clone()),
            )
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
    ///
    /// Note: If there is a group member in the group with the same identity as
    /// us, this will create a remove proposal.
    pub fn join_by_external_commit<Provider: RefinedProvider>(
        provider: &Provider,
        signer: &impl Signer,
        ratchet_tree: Option<RatchetTreeIn>,
        verifiable_group_info: VerifiableGroupInfo,
        mls_group_config: &MlsGroupJoinConfig,
        aad: &[u8],
        credential_with_key: CredentialWithKey,
    ) -> Result<(Self, MlsMessageOut, Option<GroupInfo>), ExternalCommitError<Provider::StorageError>>
    {
        // Prepare the commit parameters
        let framing_parameters = FramingParameters::new(aad, WireFormat::PublicMessage);

        let proposal_store = ProposalStore::new();
        let params = CreateCommitParams::builder()
            .framing_parameters(framing_parameters)
            .proposal_store(&proposal_store)
            .credential_with_key(credential_with_key)
            .build();
        let (mut group, create_commit_result) = CoreGroup::join_by_external_commit(
            provider,
            signer,
            params,
            ratchet_tree,
            verifiable_group_info,
        )?;
        group.set_max_past_epochs(mls_group_config.max_past_epochs);

        let mls_group = MlsGroup {
            mls_group_config: mls_group_config.clone(),
            group,
            proposal_store: ProposalStore::new(),
            own_leaf_nodes: vec![],
            aad: vec![],
            group_state: MlsGroupState::PendingCommit(Box::new(PendingCommitState::External(
                create_commit_result.staged_commit,
            ))),
            state_changed: InnerState::Changed,
        };

        let public_message: PublicMessage = create_commit_result.commit.into();

        Ok((
            mls_group,
            public_message.into(),
            create_commit_result.group_info,
        ))
    }
}

fn transpose_err_opt<T, E>(v: Result<Option<T>, E>) -> Option<Result<T, E>> {
    match v {
        Ok(Some(v)) => Some(Ok(v)),
        Ok(None) => None,
        Err(err) => Some(Err(err)),
    }
}

impl StagedWelcome {
    /// Creates a new staged welcome from a [`Welcome`] message. Returns an error
    /// ([`WelcomeError::NoMatchingKeyPackage`]) if no [`KeyPackage`]
    /// can be found.
    /// Note: calling this function will consume the key material for decrypting the [`Welcome`]
    /// message, even if the caller does not turn the [`StagedWelcome`] into an [`MlsGroup`].
    ///
    /// [`Welcome`]: crate::messages::Welcome
    pub fn new_from_welcome<
        KeyStore: OpenMlsKeyStore,
        Storage: StorageProvider<{ storage::CURRENT_VERSION }>,
    >(
        provider: &impl OpenMlsProvider<KeyStoreProvider = KeyStore, StorageProvider = Storage>,
        mls_group_config: &MlsGroupJoinConfig,
        welcome: Welcome,
        ratchet_tree: Option<RatchetTreeIn>,
    ) -> Result<Self, WelcomeError<Storage::Error>> {
        let resumption_psk_store =
            ResumptionPskStore::new(mls_group_config.number_of_resumption_psks);
        let key_package: KeyPackage = welcome
            .secrets()
            .iter()
            .find_map(|egs| {
                let hash_ref = egs.new_member();

                transpose_err_opt(
                    provider
                        .storage()
                        .key_package(&hash_ref)
                        .map_err(WelcomeError::StorageError),
                )
            })
            .ok_or(WelcomeError::NoMatchingKeyPackage)??;

        // TODO #751
        let private_key = provider
            .key_store()
            .read::<HpkePrivateKey>(key_package.hpke_init_key().as_slice())
            .ok_or(WelcomeError::NoMatchingKeyPackage)?;
        let key_package_bundle = KeyPackageBundle {
            key_package,
            private_key,
        };

        // Delete the [`KeyPackage`] and the corresponding private key from the
        // key store, but only if it doesn't have a last resort extension.
        if !key_package_bundle.key_package().last_resort() {
            key_package_bundle
                .key_package
                .delete(provider, false)
                .unwrap(); // FIXME: error handling
        } else {
            log::debug!("Key package has last resort extension, not deleting");
        }

        let group = StagedCoreWelcome::new_from_welcome(
            welcome,
            ratchet_tree,
            key_package_bundle,
            provider,
            resumption_psk_store,
        )?;

        let staged_welcome = StagedWelcome {
            mls_group_config: mls_group_config.clone(),
            group,
        };

        Ok(staged_welcome)
    }

    /// Returns the [`LeafNodeIndex`] of the group member that authored the [`Welcome`] message.
    ///
    /// [`Welcome`]: crate::messages::Welcome
    pub fn welcome_sender_index(&self) -> LeafNodeIndex {
        self.group.welcome_sender_index()
    }

    /// Returns the [`LeafNode`] of the group member that authored the [`Welcome`] message.
    ///
    /// [`Welcome`]: crate::messages::Welcome
    pub fn welcome_sender(&self) -> Result<&LeafNode, LibraryError> {
        self.group.welcome_sender()
    }

    /// Consumes the [`StagedWelcome`] and returns the respective [`MlsGroup`].
    pub fn into_group<
        KeyStore: OpenMlsKeyStore,
        Storage: StorageProvider<{ storage::CURRENT_VERSION }>,
    >(
        self,
        provider: &impl OpenMlsProvider<KeyStoreProvider = KeyStore, StorageProvider = Storage>,
    ) -> Result<MlsGroup, WelcomeError<Storage::Error>> {
        let mut group = self.group.into_core_group(provider)?;
        group.set_max_past_epochs(self.mls_group_config.max_past_epochs);

        let mls_group = MlsGroup {
            mls_group_config: self.mls_group_config,
            group,
            proposal_store: ProposalStore::new(),
            own_leaf_nodes: vec![],
            aad: vec![],
            group_state: MlsGroupState::Operational,
            state_changed: InnerState::Changed,
        };

        Ok(mls_group)
    }
}
