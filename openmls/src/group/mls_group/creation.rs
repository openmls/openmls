use errors::NewGroupError;
use openmls_traits::{signatures::Signer, storage::StorageProvider as StorageProviderTrait};

use super::{builder::MlsGroupBuilder, *};
use crate::{
    credentials::CredentialWithKey,
    group::errors::{ExternalCommitError, WelcomeError},
    messages::{
        group_info::{GroupInfo, VerifiableGroupInfo},
        Welcome,
    },
    schedule::{
        psk::{store::ResumptionPskStore, PreSharedKeyId},
        EpochSecrets, InitSecret,
    },
    storage::OpenMlsProvider,
    treesync::{
        errors::{DerivePathError, PublicTreeError},
        node::leaf_node::{Capabilities, LeafNodeParameters},
        RatchetTreeIn,
    },
};

#[cfg(doc)]
use crate::key_packages::KeyPackage;

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
    pub fn new<Provider: OpenMlsProvider>(
        provider: &Provider,
        signer: &impl Signer,
        mls_group_create_config: &MlsGroupCreateConfig,
        credential_with_key: CredentialWithKey,
    ) -> Result<Self, NewGroupError<Provider::StorageError>> {
        MlsGroupBuilder::new().build_internal(
            provider,
            signer,
            credential_with_key,
            Some(mls_group_create_config.clone()),
        )
    }

    /// Creates a new group with a given group ID with the creator as the only
    /// member.
    pub fn new_with_group_id<Provider: OpenMlsProvider>(
        provider: &Provider,
        signer: &impl Signer,
        mls_group_create_config: &MlsGroupCreateConfig,
        group_id: GroupId,
        credential_with_key: CredentialWithKey,
    ) -> Result<Self, NewGroupError<Provider::StorageError>> {
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
    #[allow(clippy::too_many_arguments)]
    pub fn join_by_external_commit<Provider: OpenMlsProvider>(
        provider: &Provider,
        signer: &impl Signer,
        ratchet_tree: Option<RatchetTreeIn>,
        verifiable_group_info: VerifiableGroupInfo,
        mls_group_config: &MlsGroupJoinConfig,
        capabilities: Option<Capabilities>,
        extensions: Option<Extensions>,
        aad: &[u8],
        credential_with_key: CredentialWithKey,
    ) -> Result<(Self, MlsMessageOut, Option<GroupInfo>), ExternalCommitError<Provider::StorageError>>
    {
        // Prepare the commit parameters
        let framing_parameters = FramingParameters::new(aad, WireFormat::PublicMessage);

        let leaf_node_parameters = LeafNodeParameters::builder()
            .with_capabilities(capabilities.unwrap_or_default())
            .with_extensions(extensions.unwrap_or_default())
            .build();
        let mut params = CreateCommitParams::builder()
            .external_commit(credential_with_key, framing_parameters)
            .leaf_node_parameters(leaf_node_parameters)
            .build();

        // Build the ratchet tree

        // Set nodes either from the extension or from the `nodes_option`.
        // If we got a ratchet tree extension in the welcome, we enable it for
        // this group. Note that this is not strictly necessary. But there's
        // currently no other mechanism to enable the extension.
        let ratchet_tree = match verifiable_group_info.extensions().ratchet_tree() {
            Some(extension) => extension.ratchet_tree().clone(),
            None => match ratchet_tree {
                Some(ratchet_tree) => ratchet_tree,
                None => return Err(ExternalCommitError::MissingRatchetTree),
            },
        };

        let (public_group, group_info) = PublicGroup::from_external(
            provider.crypto(),
            provider.storage(),
            ratchet_tree,
            verifiable_group_info,
            // Existing proposals are discarded when joining by external commit.
            ProposalStore::new(),
        )?;
        let group_context = public_group.group_context();

        // Obtain external_pub from GroupInfo extensions.
        let external_pub = group_info
            .extensions()
            .external_pub()
            .ok_or(ExternalCommitError::MissingExternalPub)?
            .external_pub();

        let (init_secret, kem_output) = InitSecret::from_group_context(
            provider.crypto(),
            group_context,
            external_pub.as_slice(),
        )
        .map_err(|_| ExternalCommitError::UnsupportedCiphersuite)?;

        // The `EpochSecrets` we create here are essentially zero, with the
        // exception of the `InitSecret`, which is all we need here for the
        // external commit.
        let epoch_secrets = EpochSecrets::with_init_secret(
            provider.crypto(),
            group_info.group_context().ciphersuite(),
            init_secret,
        )
        .map_err(LibraryError::unexpected_crypto_error)?;
        let (group_epoch_secrets, message_secrets) = epoch_secrets.split_secrets(
            group_context
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?,
            public_group.tree_size(),
            // We use a fake own index of 0 here, as we're not going to use the
            // tree for encryption until after the first commit. This issue is
            // tracked in #767.
            LeafNodeIndex::new(0u32),
        );
        let message_secrets_store = MessageSecretsStore::new_with_secret(0, message_secrets);

        let external_init_proposal = Proposal::ExternalInit(ExternalInitProposal::from(kem_output));

        let mut inline_proposals = vec![external_init_proposal];

        // If there is a group member in the group with the same identity as us,
        // commit a remove proposal.
        let signature_key = params.credential_with_key().signature_key.as_slice();
        if let Some(us) = public_group
            .members()
            .find(|member| member.signature_key == signature_key)
        {
            let remove_proposal = Proposal::Remove(RemoveProposal { removed: us.index });
            inline_proposals.push(remove_proposal);
        };

        let own_leaf_index = public_group.leftmost_free_index(inline_proposals.iter().map(Some))?;
        params.set_inline_proposals(inline_proposals);

        let mut mls_group = MlsGroup {
            mls_group_config: mls_group_config.clone(),
            own_leaf_nodes: vec![],
            aad: vec![],
            group_state: MlsGroupState::Operational,
            public_group,
            group_epoch_secrets,
            own_leaf_index,
            message_secrets_store,
            resumption_psk_store: ResumptionPskStore::new(32),
        };

        mls_group.set_max_past_epochs(mls_group_config.max_past_epochs);

        // Immediately create the commit to add ourselves to the group.
        let create_commit_result = mls_group
            .create_external_commit(params, provider, signer)
            .map_err(|_| ExternalCommitError::CommitError)?;

        mls_group.group_state = MlsGroupState::PendingCommit(Box::new(
            PendingCommitState::External(create_commit_result.staged_commit),
        ));

        mls_group
            .store(provider.storage())
            .map_err(ExternalCommitError::StorageError)?;

        let public_message: PublicMessage = create_commit_result.commit.into();

        Ok((
            mls_group,
            public_message.into(),
            create_commit_result.group_info,
        ))
    }
}

impl ProcessedWelcome {
    /// Creates a new processed [`Welcome`] message , which can be
    /// inspected before creating a [`StagedWelcome`].
    ///
    /// This does not require a ratchet tree yet.
    ///
    /// [`Welcome`]: crate::messages::Welcome
    pub fn new_from_welcome<Provider: OpenMlsProvider>(
        provider: &Provider,
        mls_group_config: &MlsGroupJoinConfig,
        welcome: Welcome,
    ) -> Result<Self, WelcomeError<Provider::StorageError>> {
        let (resumption_psk_store, key_package_bundle) =
            keys_for_welcome(mls_group_config, &welcome, provider)?;

        let ciphersuite = welcome.ciphersuite();
        let Some(egs) = welcome.find_encrypted_group_secret(
            key_package_bundle
                .key_package()
                .hash_ref(provider.crypto())?,
        ) else {
            return Err(WelcomeError::JoinerSecretNotFound);
        };

        // This check seems to be superfluous from the perspective of the RFC, but still doesn't
        // seem like a bad idea.
        if welcome.ciphersuite() != key_package_bundle.key_package().ciphersuite() {
            let e = WelcomeError::CiphersuiteMismatch;
            log::debug!("new_from_welcome {:?}", e);
            return Err(e);
        }

        let group_secrets = GroupSecrets::try_from_ciphertext(
            key_package_bundle.init_private_key(),
            egs.encrypted_group_secrets(),
            welcome.encrypted_group_info(),
            ciphersuite,
            provider.crypto(),
        )?;
        let psk_secret = {
            let psks = load_psks(
                provider.storage(),
                &resumption_psk_store,
                &group_secrets.psks,
            )?;

            PskSecret::new(provider.crypto(), ciphersuite, psks)?
        };
        let key_schedule = KeySchedule::init(
            ciphersuite,
            provider.crypto(),
            &group_secrets.joiner_secret,
            psk_secret,
        )?;
        let (welcome_key, welcome_nonce) = key_schedule
            .welcome(provider.crypto(), ciphersuite)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?
            .derive_welcome_key_nonce(provider.crypto(), ciphersuite)
            .map_err(LibraryError::unexpected_crypto_error)?;
        let verifiable_group_info = VerifiableGroupInfo::try_from_ciphertext(
            &welcome_key,
            &welcome_nonce,
            welcome.encrypted_group_info(),
            &[],
            provider.crypto(),
        )?;
        if let Some(required_capabilities) =
            verifiable_group_info.extensions().required_capabilities()
        {
            // Also check that our key package actually supports the extensions.
            // As per the spec, the sender must have checked this. But you never know.
            key_package_bundle
                .key_package()
                .leaf_node()
                .capabilities()
                .supports_required_capabilities(required_capabilities)?;
        }

        // https://validation.openmls.tech/#valn1404
        // Verify that the cipher_suite in the GroupInfo matches the cipher_suite in the
        // KeyPackage.
        if verifiable_group_info.ciphersuite() != key_package_bundle.key_package().ciphersuite() {
            let e = WelcomeError::CiphersuiteMismatch;
            log::debug!("new_from_welcome {:?}", e);
            return Err(e);
        }

        Ok(Self {
            mls_group_config: mls_group_config.clone(),
            ciphersuite,
            group_secrets,
            key_schedule,
            verifiable_group_info,
            resumption_psk_store,
            key_package_bundle,
        })
    }

    /// Get a reference to the GroupInfo in this Welcome message.
    ///
    /// **NOTE:** The group info contains **unverified** values. Use with caution.
    pub fn unverified_group_info(&self) -> &VerifiableGroupInfo {
        &self.verifiable_group_info
    }

    /// Get a reference to the PSKs in this Welcome message.
    ///
    /// **NOTE:** The group info contains **unverified** values. Use with caution.
    pub fn psks(&self) -> &[PreSharedKeyId] {
        &self.group_secrets.psks
    }

    /// Consume the `ProcessedWelcome` and combine it witht he ratchet tree into
    /// a `StagedWelcome`.
    pub fn into_staged_welcome<Provider: OpenMlsProvider>(
        mut self,
        provider: &Provider,
        ratchet_tree: Option<RatchetTreeIn>,
    ) -> Result<StagedWelcome, WelcomeError<Provider::StorageError>> {
        // Build the ratchet tree and group

        // Set nodes either from the extension or from the `nodes_option`.
        // If we got a ratchet tree extension in the welcome, we enable it for
        // this group. Note that this is not strictly necessary. But there's
        // currently no other mechanism to enable the extension.
        let ratchet_tree = match self.verifiable_group_info.extensions().ratchet_tree() {
            Some(extension) => extension.ratchet_tree().clone(),
            None => match ratchet_tree {
                Some(ratchet_tree) => ratchet_tree,
                None => return Err(WelcomeError::MissingRatchetTree),
            },
        };

        // Since there is currently only the external pub extension, there is no
        // group info extension of interest here.
        let (public_group, _group_info_extensions) = PublicGroup::from_external(
            provider.crypto(),
            provider.storage(),
            ratchet_tree,
            self.verifiable_group_info.clone(),
            ProposalStore::new(),
        )?;

        // Find our own leaf in the tree.
        let own_leaf_index = public_group
            .members()
            .find_map(|m| {
                if m.signature_key
                    == self
                        .key_package_bundle
                        .key_package()
                        .leaf_node()
                        .signature_key()
                        .as_slice()
                {
                    Some(m.index)
                } else {
                    None
                }
            })
            .ok_or(WelcomeError::PublicTreeError(
                PublicTreeError::MalformedTree,
            ))?;

        let (group_epoch_secrets, message_secrets) = {
            let serialized_group_context = public_group
                .group_context()
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?;

            // TODO #751: Implement PSK
            self.key_schedule
                .add_context(provider.crypto(), &serialized_group_context)
                .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;

            let epoch_secrets = self
                .key_schedule
                .epoch_secrets(provider.crypto(), self.ciphersuite)
                .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;

            epoch_secrets.split_secrets(
                serialized_group_context,
                public_group.tree_size(),
                own_leaf_index,
            )
        };

        let confirmation_tag = message_secrets
            .confirmation_key()
            .tag(
                provider.crypto(),
                self.ciphersuite,
                public_group.group_context().confirmed_transcript_hash(),
            )
            .map_err(LibraryError::unexpected_crypto_error)?;

        // Verify confirmation tag
        // https://validation.openmls.tech/#valn1410
        if &confirmation_tag != public_group.confirmation_tag() {
            log::error!("Confirmation tag mismatch");
            log_crypto!(trace, "  Got:      {:x?}", confirmation_tag);
            log_crypto!(trace, "  Expected: {:x?}", public_group.confirmation_tag());
            debug_assert!(false, "Confirmation tag mismatch");

            // in some tests we need to be able to proceed despite the tag being wrong,
            // e.g. to test whether a later validation check is performed correctly.
            if !crate::skip_validation::is_disabled::confirmation_tag() {
                return Err(WelcomeError::ConfirmationTagMismatch);
            }
        }

        let message_secrets_store = MessageSecretsStore::new_with_secret(0, message_secrets);

        // Extract and store the resumption PSK for the current epoch.
        let resumption_psk = group_epoch_secrets.resumption_psk();
        self.resumption_psk_store
            .add(public_group.group_context().epoch(), resumption_psk.clone());

        let welcome_sender_index = self.verifiable_group_info.signer();
        let path_keypairs = if let Some(path_secret) = self.group_secrets.path_secret {
            let (path_keypairs, _commit_secret) = public_group
                .derive_path_secrets(
                    provider.crypto(),
                    self.ciphersuite,
                    path_secret,
                    welcome_sender_index,
                    own_leaf_index,
                )
                .map_err(|e| match e {
                    DerivePathError::LibraryError(e) => e.into(),
                    DerivePathError::PublicKeyMismatch => {
                        WelcomeError::PublicTreeError(PublicTreeError::PublicKeyMismatch)
                    }
                })?;
            Some(path_keypairs)
        } else {
            None
        };

        let staged_welcome = StagedWelcome {
            mls_group_config: self.mls_group_config,
            public_group,
            group_epoch_secrets,
            own_leaf_index,
            message_secrets_store,
            resumption_psk_store: self.resumption_psk_store,
            verifiable_group_info: self.verifiable_group_info,
            key_package_bundle: self.key_package_bundle,
            path_keypairs,
        };

        Ok(staged_welcome)
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
    pub fn new_from_welcome<Provider: OpenMlsProvider>(
        provider: &Provider,
        mls_group_config: &MlsGroupJoinConfig,
        welcome: Welcome,
        ratchet_tree: Option<RatchetTreeIn>,
    ) -> Result<Self, WelcomeError<Provider::StorageError>> {
        let processed_welcome =
            ProcessedWelcome::new_from_welcome(provider, mls_group_config, welcome)?;

        processed_welcome.into_staged_welcome(provider, ratchet_tree)
    }

    /// Returns the [`LeafNodeIndex`] of the group member that authored the [`Welcome`] message.
    ///
    /// [`Welcome`]: crate::messages::Welcome
    pub fn welcome_sender_index(&self) -> LeafNodeIndex {
        self.verifiable_group_info.signer()
    }

    /// Returns the [`LeafNode`] of the group member that authored the [`Welcome`] message.
    ///
    /// [`Welcome`]: crate::messages::Welcome
    pub fn welcome_sender(&self) -> Result<&LeafNode, LibraryError> {
        let sender_index = self.welcome_sender_index();
        self.public_group
            .leaf(sender_index)
            .ok_or(LibraryError::custom(
                "no leaf with given welcome sender index exists",
            ))
    }

    /// Get the [`GroupContext`] of this welcome's [`PublicGroup`].
    pub fn group_context(&self) -> &GroupContext {
        self.public_group.group_context()
    }

    /// Get an iterator over all [`Member`]s of this welcome's [`PublicGroup`].
    pub fn members(&self) -> impl Iterator<Item = Member> + '_ {
        self.public_group.members()
    }

    /// Consumes the [`StagedWelcome`] and returns the respective [`MlsGroup`].
    pub fn into_group<Provider: OpenMlsProvider>(
        self,
        provider: &Provider,
    ) -> Result<MlsGroup, WelcomeError<Provider::StorageError>> {
        // If we got a path secret, derive the path (which also checks if the
        // public keys match) and store the derived keys in the key store.
        let group_keypairs = if let Some(path_keypairs) = self.path_keypairs {
            let mut keypairs = vec![self.key_package_bundle.encryption_key_pair()];
            keypairs.extend_from_slice(&path_keypairs);
            keypairs
        } else {
            vec![self.key_package_bundle.encryption_key_pair()]
        };

        let mut mls_group = MlsGroup {
            mls_group_config: self.mls_group_config,
            own_leaf_nodes: vec![],
            aad: vec![],
            group_state: MlsGroupState::Operational,
            public_group: self.public_group,
            group_epoch_secrets: self.group_epoch_secrets,
            own_leaf_index: self.own_leaf_index,
            message_secrets_store: self.message_secrets_store,
            resumption_psk_store: self.resumption_psk_store,
        };

        mls_group
            .store_epoch_keypairs(provider.storage(), group_keypairs.as_slice())
            .map_err(WelcomeError::StorageError)?;
        mls_group.set_max_past_epochs(mls_group.mls_group_config.max_past_epochs);

        mls_group
            .store(provider.storage())
            .map_err(WelcomeError::StorageError)?;

        Ok(mls_group)
    }
}

fn keys_for_welcome<Provider: OpenMlsProvider>(
    mls_group_config: &MlsGroupJoinConfig,
    welcome: &Welcome,
    provider: &Provider,
) -> Result<
    (ResumptionPskStore, KeyPackageBundle),
    WelcomeError<<Provider as OpenMlsProvider>::StorageError>,
> {
    let resumption_psk_store = ResumptionPskStore::new(mls_group_config.number_of_resumption_psks);
    let key_package_bundle: KeyPackageBundle = welcome
        .secrets()
        .iter()
        .find_map(|egs| {
            let hash_ref = egs.new_member();

            provider
                .storage()
                .key_package(&hash_ref)
                .map_err(WelcomeError::StorageError)
                .transpose()
        })
        .ok_or(WelcomeError::NoMatchingKeyPackage)??;
    if !key_package_bundle.key_package().last_resort() {
        provider
            .storage()
            .delete_key_package(&key_package_bundle.key_package.hash_ref(provider.crypto())?)
            .map_err(WelcomeError::StorageError)?;
    } else {
        log::debug!("Key package has last resort extension, not deleting");
    }
    Ok((resumption_psk_store, key_package_bundle))
}
