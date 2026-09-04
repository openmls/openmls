use errors::NewGroupError;
use openmls_traits::{crypto::OpenMlsCrypto, storage::StorageProvider as StorageProviderTrait};

use super::{builder::MlsGroupBuilder, *};
use crate::{
    credentials::CredentialWithKey,
    extensions::Extensions,
    group::{
        commit_builder::external_commits::ExternalCommitBuilder,
        errors::{ExportSecretError, ExternalCommitError, WelcomeError},
    },
    messages::{
        group_info::{GroupInfo, VerifiableGroupInfo},
        Welcome,
    },
    schedule::{
        psk::{store::ResumptionPskStore, PreSharedKeyId, Psk, ResumptionPskUsage},
        EpochSecretsResult,
    },
    storage::OpenMlsProvider,
    treesync::{
        errors::{DerivePathError, PublicTreeError},
        node::leaf_node::{Capabilities, LeafNodeParameters},
        RatchetTreeIn,
    },
};

use crate::key_packages::KeyPackage;

#[cfg(feature = "virtual-clients-draft")]
use crate::{
    component::ComponentId,
    framing::mls_auth_content::AuthenticatedContent,
    group::mls_group::processing::{AppDataDictionaryUpdater, AppDataUpdates},
    messages::proposals::{AppDataUpdateProposal, AppEphemeralProposal},
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
    #[deprecated(
        since = "0.7.1",
        note = "Use the `MlsGroup::external_commit_builder` instead."
    )]
    pub fn join_by_external_commit<Provider: OpenMlsProvider>(
        provider: &Provider,
        signer: &impl Signer,
        ratchet_tree: Option<RatchetTreeIn>,
        verifiable_group_info: VerifiableGroupInfo,
        mls_group_config: &MlsGroupJoinConfig,
        capabilities: Option<Capabilities>,
        extensions: Option<Extensions<LeafNode>>,
        aad: &[u8],
        credential_with_key: CredentialWithKey,
    ) -> Result<(Self, MlsMessageOut, Option<GroupInfo>), ExternalCommitError<Provider::StorageError>>
    {
        let leaf_node_parameters = LeafNodeParameters::builder()
            .with_capabilities(capabilities.unwrap_or_default())
            .with_extensions(extensions.unwrap_or_default())
            .build();

        let mut external_commit_builder = ExternalCommitBuilder::new()
            .with_aad(aad.to_vec())
            .with_config(mls_group_config.clone());

        if let Some(ratchet_tree) = ratchet_tree {
            external_commit_builder = external_commit_builder.with_ratchet_tree(ratchet_tree)
        }

        let (mls_group, commit_message_bundle) = external_commit_builder
            .build_group(provider, verifiable_group_info, credential_with_key)?
            .leaf_node_parameters(leaf_node_parameters)
            .load_psks(provider.storage())
            .map_err(|e| {
                log::error!("Error loading PSKs for external commit: {e:?}");
                LibraryError::custom("Error loading PSKs for external commit")
            })?
            .build(provider.rand(), provider.crypto(), signer, |_| true)?
            .finalize(provider)?;

        let (commit, _, group_info) = commit_message_bundle.into_contents();

        Ok((mls_group, commit, group_info))
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
        Self::new_from_welcome_inner(provider, mls_group_config, welcome, None)
    }

    /// Like [`ProcessedWelcome::new_from_welcome`], but allows injecting a
    /// resumption PSK secret that is not held in storage.
    ///
    /// This is used for subgroup branching (RFC 9420 §11.3): the branch PSK
    /// secret comes from the parent group and is injected at the sentinel epoch
    /// 0, where [`load_psks`](crate::schedule::psk::load_psks) looks it up for
    /// branch usage. See [`StagedWelcome::build_from_branch`].
    pub(crate) fn new_from_welcome_inner<Provider: OpenMlsProvider>(
        provider: &Provider,
        mls_group_config: &MlsGroupJoinConfig,
        welcome: Welcome,
        branch_info: Option<&BranchInfo>,
    ) -> Result<Self, WelcomeError<Provider::StorageError>> {
        let (resumption_psk_store, key_material, group_secrets) =
            decrypt_group_secrets(provider, mls_group_config, &welcome)?;

        finish_processed_welcome(
            provider,
            mls_group_config,
            welcome.ciphersuite(),
            resumption_psk_store,
            key_material,
            group_secrets,
            &welcome,
            branch_info,
        )
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

    /// Consume the `ProcessedWelcome` and combine it with the ratchet tree into
    /// a `StagedWelcome`.
    pub fn into_staged_welcome<Provider: OpenMlsProvider>(
        self,
        provider: &Provider,
        ratchet_tree: Option<RatchetTreeIn>,
    ) -> Result<StagedWelcome, WelcomeError<Provider::StorageError>> {
        self.into_staged_welcome_inner(
            provider,
            ratchet_tree,
            LeafNodeLifetimePolicy::Verify,
            false,
        )
    }

    /// Consume the `ProcessedWelcome` and combine it with the ratchet tree into
    /// a `StagedWelcome`.
    pub(crate) fn into_staged_welcome_inner<Provider: OpenMlsProvider>(
        mut self,
        provider: &Provider,
        ratchet_tree: Option<RatchetTreeIn>,
        validate_lifetimes: LeafNodeLifetimePolicy,
        replace_old_group: bool,
    ) -> Result<StagedWelcome, WelcomeError<Provider::StorageError>> {
        // Check if we need to replace an old group
        if !replace_old_group
            && MlsGroup::load(provider.storage(), self.verifiable_group_info.group_id())
                .map_err(WelcomeError::StorageError)?
                .is_some()
        {
            return Err(WelcomeError::GroupAlreadyExists);
        }

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
        let (public_group, _group_info_extensions) = PublicGroup::from_ratchet_tree(
            provider.crypto(),
            ratchet_tree,
            self.verifiable_group_info.clone(),
            ProposalStore::new(),
            validate_lifetimes,
        )?;

        // Find our own leaf in the tree. On the bundle path this is the leaf
        // whose signature key matches the local KeyPackage. On the
        // virtual-client path there is no local signature key, so the leaf is
        // located by its derived encryption key and validated against the
        // derivation epoch's derivation info.
        let own_leaf_index = match &self.key_material.inner() {
            WelcomeKeyMaterialInner::KeyPackage(key_package_bundle) => {
                // Check that the leaf node of the added key package supports all extensions in
                // the group context.
                // https://validation.openmls.tech/#valn1415
                let added_leaf_supports_all_group_context_extensions = public_group
                    .group_context()
                    .extensions()
                    .iter()
                    .all(|extension| {
                        key_package_bundle
                            .key_package
                            .leaf_node()
                            .supports_extension(&extension.extension_type())
                    });
                if !added_leaf_supports_all_group_context_extensions {
                    return Err(WelcomeError::UnsupportedExtensions);
                }

                public_group
                    .members()
                    .find_map(|m| {
                        if m.signature_key
                            == key_package_bundle
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
                    ))?
            }
            #[cfg(feature = "virtual-clients-draft")]
            WelcomeKeyMaterialInner::VirtualClient(material) => {
                find_and_validate_vc_own_leaf(provider, &public_group, material)?
            }
        };

        struct KeyScheduleResult {
            group_epoch_secrets: GroupEpochSecrets,
            message_secrets: MessageSecrets,
            #[cfg(feature = "extensions-draft")]
            application_exporter: ApplicationExportSecret,
        }
        let KeyScheduleResult {
            group_epoch_secrets,
            message_secrets,
            #[cfg(feature = "extensions-draft")]
                application_exporter: application_export_secret,
        } = {
            let serialized_group_context = public_group
                .group_context()
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?;

            let EpochSecretsResult {
                epoch_secrets,
                #[cfg(feature = "extensions-draft")]
                application_exporter,
            } = self.epoch_secrets;

            let (group_epoch_secrets, message_secrets) = epoch_secrets.split_secrets(
                serialized_group_context,
                public_group.tree_size(),
                own_leaf_index,
            );

            KeyScheduleResult {
                group_epoch_secrets,
                message_secrets,
                #[cfg(feature = "extensions-draft")]
                application_exporter,
            }
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
        // https://validation.openmls.tech/#valn1411
        if &confirmation_tag != public_group.confirmation_tag() {
            log::error!("Confirmation tag mismatch");
            log_crypto!(trace, "  Got:      {:x?}", confirmation_tag);
            log_crypto!(trace, "  Expected: {:x?}", public_group.confirmation_tag());

            // in some tests we need to be able to proceed despite the tag being wrong,
            // e.g. to test whether a later validation check is performed correctly.
            if !crate::skip_validation::is_disabled::confirmation_tag() {
                return Err(WelcomeError::ConfirmationTagMismatch);
            }
        }

        let message_secrets_store = MessageSecretsStore::new_with_secret(
            &PastEpochDeletionPolicy::MaxEpochs(0),
            message_secrets,
        );

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
            #[cfg(feature = "extensions-draft")]
            application_export_secret,
            resumption_psk_store: self.resumption_psk_store,
            verifiable_group_info: self.verifiable_group_info,
            key_material: self.key_material,
            path_keypairs,
            #[cfg(feature = "virtual-clients-draft")]
            emulation_group: false,
        };

        Ok(staged_welcome)
    }

    /// Exports a secret from the epoch of the group that is joined
    /// using this [`ProcessedWelcome`].
    /// Returns [`ExportSecretError::KeyLengthTooLong`] if the requested
    /// key length is too long.
    pub fn export_secret<CryptoProvider: OpenMlsCrypto>(
        &self,
        crypto: &CryptoProvider,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<ExportedSecret<ProcessedWelcomeExport>, ExportSecretError> {
        if key_length > u16::MAX as usize {
            log::error!("Got a key that is larger than u16::MAX");
            return Err(ExportSecretError::KeyLengthTooLong);
        }

        Ok(ExportedSecret::new(
            self.epoch_secrets
                .epoch_secrets
                .exporter_secret()
                .derive_exported_secret(self.ciphersuite, crypto, label, context, key_length)
                .map_err(LibraryError::unexpected_crypto_error)?,
        ))
    }

    /// Retrieve a reference to the own [`KeyPackage`] that was retrieved from local storage as
    /// part of [`Welcome`] processing, and is used to build the group
    pub fn own_key_package(&self) -> Option<&KeyPackage> {
        self.key_material
            .key_package_bundle()
            .map(|bundle| bundle.key_package())
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

    /// Similar to [`StagedWelcome::new_from_welcome`] but as a builder.
    ///
    /// The builder allows to set the ratchet tree, skip leaf node lifetime
    /// validation, and get the [`ProcessedWelcome`] for inspection before staging.
    pub fn build_from_welcome<'a, Provider: OpenMlsProvider>(
        provider: &'a Provider,
        mls_group_config: &MlsGroupJoinConfig,
        welcome: Welcome,
    ) -> Result<JoinBuilder<'a, Provider>, WelcomeError<Provider::StorageError>> {
        let processed_welcome =
            ProcessedWelcome::new_from_welcome(provider, mls_group_config, welcome)?;

        // processed_welcome.into_staged_welcome(provider, ratchet_tree)
        Ok(JoinBuilder::new(provider, processed_welcome))
    }

    /// Builder to create a [`StagedWelcome`] for a subgroup branched from a
    /// parent group, as described in [RFC 9420 §11.3].
    ///
    /// The parent group's parameters are provided via `branch_info`, which the
    /// parent exports with
    /// [`MlsGroup::branch_info`](crate::group::MlsGroup::branch_info).
    ///
    /// In addition to the regular [`StagedWelcome::build_from_welcome`]
    /// processing, this injects the parent's resumption PSK secret (which is
    /// required to derive the subgroup's key schedule from the branch PSK) and
    /// enforces the receiver-side checks the RFC mandates when joining a branched
    /// subgroup.
    ///
    /// The branch PSK carried in the `Welcome` must reference the same parent
    /// group and epoch as the supplied `branch_info`; otherwise the injected
    /// resumption PSK secret would be for the wrong epoch. This is checked here,
    /// before the secret is mixed into the key schedule, and fails with
    /// [`WelcomeError::SubgroupParentMismatch`].
    ///
    /// The remaining checks run when [`JoinBuilder::build`] is called:
    ///
    /// * the protocol version and ciphersuite match the parent group,
    /// * the subgroup is at epoch 1, and
    /// * every member of the subgroup matches a member of the parent group
    ///   (unless disabled via [`JoinBuilder::check_members`]).
    ///
    /// Matching members is left to the application by the RFC; here we use
    /// credential equality for equivalent identifiers.
    ///
    /// If the receiver does not yet know which parent epoch the branch was taken
    /// from (its own view of the parent group may have advanced), use
    /// [`StagedWelcome::process_branch_welcome`] to read the parent reference
    /// from the `Welcome` first and then pick the matching `branch_info`. That
    /// path decrypts the `Welcome` only once. This one-shot method is a
    /// convenience for callers that already know the parent epoch; it also
    /// decrypts only once, via the same carrier.
    ///
    /// [RFC 9420 §11.3]: https://www.rfc-editor.org/rfc/rfc9420.html#name-subgroup-branching
    pub fn build_from_branch<'a, Provider: OpenMlsProvider>(
        provider: &'a Provider,
        mls_group_config: &MlsGroupJoinConfig,
        welcome: Welcome,
        branch_info: BranchInfo,
    ) -> Result<JoinBuilder<'a, Provider>, WelcomeError<Provider::StorageError>> {
        Self::process_branch_welcome(provider, mls_group_config, welcome)?
            .build_from_branch(provider, branch_info)
    }

    /// Decrypt a subgroup-branch `Welcome` once so its parent reference can be
    /// inspected before selecting the matching [`BranchInfo`].
    ///
    /// The branch PSK's parent group and epoch live inside the `Welcome`'s
    /// encrypted `GroupSecrets`, so reading them requires decryption. This
    /// returns a [`PendingBranchWelcome`] holding the decrypted state: call
    /// [`PendingBranchWelcome::parent`] to read the parent `(group_id, epoch)`
    /// the branch derives from (RFC 9420 §8.4), select the `BranchInfo` for that
    /// parent epoch (e.g. from a sliding window of recent epochs), then finish
    /// with [`PendingBranchWelcome::build_from_branch`] — without decrypting the
    /// `Welcome` a second time.
    ///
    /// **Note:** like [`StagedWelcome::build_from_branch`], this path assumes a
    /// subgroup-branch `Welcome`. It consumes the matching key package from
    /// storage. If [`PendingBranchWelcome::parent`] returns `None` the `Welcome`
    /// is not a branch welcome and the carrier cannot complete a regular join
    /// (the key package is already consumed); use the normal
    /// [`ProcessedWelcome`] flow when the message may not be a branch welcome.
    pub fn process_branch_welcome<Provider: OpenMlsProvider>(
        provider: &Provider,
        mls_group_config: &MlsGroupJoinConfig,
        welcome: Welcome,
    ) -> Result<PendingBranchWelcome, WelcomeError<Provider::StorageError>> {
        let (resumption_psk_store, key_material, group_secrets) =
            decrypt_group_secrets(provider, mls_group_config, &welcome)?;

        Ok(PendingBranchWelcome {
            mls_group_config: mls_group_config.clone(),
            ciphersuite: welcome.ciphersuite(),
            welcome,
            resumption_psk_store,
            key_material,
            group_secrets,
        })
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
            .ok_or_else(|| LibraryError::custom("no leaf with given welcome sender index exists"))
    }

    /// Returns the leaf index of the client in this welcome's [`PublicGroup`].
    pub fn own_leaf_index(&self) -> LeafNodeIndex {
        self.own_leaf_index
    }

    /// Returns the leaf node of the client in this welcome's [`PublicGroup`].
    pub fn own_leaf_node(&self) -> Option<&LeafNode> {
        self.public_group.leaf(self.own_leaf_index())
    }

    /// Get the [`GroupContext`] of this welcome's [`PublicGroup`].
    pub fn group_context(&self) -> &GroupContext {
        self.public_group.group_context()
    }

    /// Get an iterator over all [`Member`]s of this welcome's [`PublicGroup`].
    pub fn members(&self) -> impl Iterator<Item = Member> + '_ {
        self.public_group.members()
    }

    /// Get the [`ApplicationExportSecret`] of this welcome.
    #[cfg(feature = "extensions-draft")]
    pub fn application_export_secret(&self) -> &ApplicationExportSecret {
        &self.application_export_secret
    }

    /// Join the group as an emulation group of a virtual client. See
    /// [`MlsGroupCreateConfigBuilder::emulation_group`] for what an emulation
    /// group is.
    ///
    /// Nothing on the wire marks a group as an emulation group, so a joiner has
    /// to set this itself. Joining an emulation group without it leaves the
    /// virtual client's secrets underived.
    ///
    /// [`MlsGroupCreateConfigBuilder::emulation_group`]: crate::group::MlsGroupCreateConfigBuilder::emulation_group
    #[cfg(feature = "virtual-clients-draft")]
    pub fn emulation_group(mut self, emulation_group: bool) -> Self {
        self.emulation_group = emulation_group;
        self
    }

    /// Consumes the [`StagedWelcome`] and returns the respective [`MlsGroup`].
    pub fn into_group<Provider: OpenMlsProvider>(
        self,
        provider: &Provider,
    ) -> Result<MlsGroup, WelcomeError<Provider::StorageError>> {
        // If we got a path secret, derive the path (which also checks if the
        // public keys match) and store the derived keys in the key store.
        let group_keypairs = if let Some(path_keypairs) = self.path_keypairs {
            let mut keypairs = vec![self.key_material.encryption_key_pair()];
            keypairs.extend_from_slice(&path_keypairs);
            keypairs
        } else {
            vec![self.key_material.encryption_key_pair()]
        };

        #[cfg(feature = "extensions-draft")]
        #[cfg_attr(not(feature = "virtual-clients-draft"), allow(unused_mut))]
        let mut application_export_tree =
            ApplicationExportTree::new(self.application_export_secret);

        // The epoch the Welcome hands us is a derivation epoch of the emulation
        // group: the commit that created it added us, so it changed membership.
        #[cfg(feature = "virtual-clients-draft")]
        if self.emulation_group {
            crate::components::vc_derivation_info::register_vc_derivation_epoch(
                provider.crypto(),
                provider.storage(),
                Some(&mut application_export_tree),
                crate::components::vc_derivation_info::VcDerivationEpochParams::for_public_group(
                    &self.public_group,
                    self.own_leaf_index,
                    self.mls_group_config
                        .vc_derivation_epoch_retention_policy()
                        .clone(),
                ),
            )?;
        }

        let past_epoch_deletion_policy = self.mls_group_config.past_epoch_deletion_policy().clone();

        let mut mls_group = MlsGroup {
            mls_group_config: self.mls_group_config,
            own_leaf_nodes: vec![],
            aad: vec![],
            #[cfg(feature = "extensions-draft")]
            safe_aad: crate::framing::SafeAad::empty(),
            group_state: MlsGroupState::Operational,
            public_group: self.public_group,
            group_epoch_secrets: self.group_epoch_secrets,
            own_leaf_index: self.own_leaf_index,
            message_secrets_store: self.message_secrets_store,
            resumption_psk_store: self.resumption_psk_store,
            #[cfg(feature = "extensions-draft")]
            application_export_tree: Some(application_export_tree),
            #[cfg(feature = "virtual-clients-draft")]
            emulation_group: self.emulation_group,
        };

        mls_group
            .store_epoch_keypairs(provider.storage(), group_keypairs.as_slice())
            .map_err(WelcomeError::StorageError)?;
        // resize the store
        mls_group.resize_message_secrets_store(&past_epoch_deletion_policy);

        // A join through a virtual client's KeyPackage binds the joined epoch
        // to the KeyPackage's derivation epoch. The binding takes over the
        // epoch reference from the retained KeyPackage material, which
        // `keys_for_welcome` left in storage for that purpose. (a bound group
        // is required for the reuse-guard MUST).
        #[cfg(feature = "virtual-clients-draft")]
        if let Some(material) = self.key_material.vc_welcome_material() {
            let max_entries = mls_group.message_secrets_store.max_epochs.saturating_add(1);
            crate::components::vc_derivation_info::write_vc_emulation_binding_with_pruning(
                provider.storage(),
                mls_group.group_id(),
                mls_group.epoch(),
                material.epoch_id.clone(),
                max_entries,
            )
            .map_err(WelcomeError::StorageError)?;
            provider
                .storage()
                .delete_retained_key_package_material(&material.key_package_ref)
                .map_err(WelcomeError::StorageError)?;
        }

        mls_group
            .store(provider.storage())
            .map_err(WelcomeError::StorageError)?;

        Ok(mls_group)
    }

    /// Exports a secret from the epoch of the group that is joined
    /// using this [`StagedWelcome`].
    /// Returns [`ExportSecretError::KeyLengthTooLong`] if the requested
    /// key length is too long.
    pub fn export_secret<CryptoProvider: OpenMlsCrypto>(
        &self,
        crypto: &CryptoProvider,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<ExportedSecret<StagedWelcomeExport>, ExportSecretError> {
        if key_length > u16::MAX as usize {
            log::error!("Got a key that is larger than u16::MAX");
            return Err(ExportSecretError::KeyLengthTooLong);
        }

        Ok(ExportedSecret::new(
            self.group_epoch_secrets
                .exporter_secret()
                .derive_exported_secret(
                    self.group_context().ciphersuite(),
                    crypto,
                    label,
                    context,
                    key_length,
                )
                .map_err(LibraryError::unexpected_crypto_error)?,
        ))
    }
}

/// A subgroup-branch `Welcome` whose `GroupSecrets` have been decrypted but not
/// yet staged.
///
/// This lets a receiver read which parent group and epoch the branch derives
/// from before committing to a [`BranchInfo`].
/// The decrypted state is carried here and reused when finishing the join.
/// Create it with [`StagedWelcome::process_branch_welcome`], read the parent
/// reference with [`Self::parent`], then finish with [`Self::build_from_branch`].
pub struct PendingBranchWelcome {
    mls_group_config: MlsGroupJoinConfig,
    ciphersuite: Ciphersuite,
    welcome: Welcome,
    resumption_psk_store: ResumptionPskStore,
    key_material: WelcomeKeyMaterial,
    group_secrets: GroupSecrets,
}

impl PendingBranchWelcome {
    /// The parent group and epoch this branch derives from, read from the branch
    /// resumption PSK carried in the `Welcome`.
    ///
    /// Use this to select the [`BranchInfo`] exported from the matching parent
    /// epoch before calling [`Self::build_from_branch`].
    ///
    /// Returns `None` if the `Welcome` carries no branch resumption PSK, i.e. it
    /// is not a subgroup-branch welcome.
    pub fn parent(&self) -> Option<(GroupId, GroupEpoch)> {
        self.group_secrets
            .psks
            .iter()
            .find_map(|id| match id.psk() {
                Psk::Resumption(r) if r.usage() == ResumptionPskUsage::Branch => {
                    Some((r.psk_group_id().clone(), r.psk_epoch()))
                }
                _ => None,
            })
    }

    /// Finish the subgroup-branch join with the selected [`BranchInfo`], reusing
    /// the already-decrypted state (no second decrypt of the `Welcome`).
    ///
    /// The branch PSK's parent reference is checked against `branch_info` (see
    /// [`StagedWelcome::build_from_branch`]); a `branch_info` from the wrong
    /// parent epoch fails with [`WelcomeError::SubgroupParentMismatch`]. The
    /// remaining receiver checks run when [`JoinBuilder::build`] is called.
    pub fn build_from_branch<'a, Provider: OpenMlsProvider>(
        self,
        provider: &'a Provider,
        branch_info: BranchInfo,
    ) -> Result<JoinBuilder<'a, Provider>, WelcomeError<Provider::StorageError>> {
        let processed_welcome = finish_processed_welcome(
            provider,
            &self.mls_group_config,
            self.ciphersuite,
            self.resumption_psk_store,
            self.key_material,
            self.group_secrets,
            &self.welcome,
            Some(&branch_info),
        )?;

        Ok(JoinBuilder::new(provider, processed_welcome).with_branch_info(branch_info))
    }
}

/// Decrypt a `Welcome`'s `GroupSecrets`.
///
/// This is the first half of welcome processing, shared between the regular
/// join and the subgroup-branch peek (see [`PendingBranchWelcome`]). It consumes
/// the matching (non-last-resort) key package from storage via
/// [`keys_for_welcome`] and decrypts the encrypted group secrets addressed to
/// it. Retained virtual-client material is read but not consumed, see
/// [`keys_for_welcome`]. The branch resumption PSK secret is not injected
/// here: injection and the parent-reference check happen in
/// [`finish_processed_welcome`], so this step is identical on both paths.
fn decrypt_group_secrets<Provider: OpenMlsProvider>(
    provider: &Provider,
    mls_group_config: &MlsGroupJoinConfig,
    welcome: &Welcome,
) -> Result<
    (ResumptionPskStore, WelcomeKeyMaterial, GroupSecrets),
    WelcomeError<<Provider as OpenMlsProvider>::StorageError>,
> {
    let ciphersuite = welcome.ciphersuite();
    // Check this before touching any stored key material: `keys_for_welcome`
    // consumes a matching (non-last-resort) key package.
    provider
        .crypto()
        .supports(ciphersuite)
        .map_err(|_| WelcomeError::UnsupportedCiphersuite(ciphersuite))?;

    let (resumption_psk_store, key_material) =
        keys_for_welcome(mls_group_config, welcome, provider)?;

    let Some(egs) =
        welcome.find_encrypted_group_secret(key_material.key_package_ref(provider.crypto())?)
    else {
        return Err(WelcomeError::JoinerSecretNotFound);
    };

    // This check seems to be superfluous from the perspective of the RFC, but still doesn't
    // seem like a bad idea. There is no local KeyPackage to compare against on the
    // virtual-client path, where the derived material is implicitly the welcome's ciphersuite.
    if let Some(key_package_bundle) = key_material.key_package_bundle() {
        if welcome.ciphersuite() != key_package_bundle.key_package().ciphersuite() {
            let e = WelcomeError::CiphersuiteMismatch;
            log::debug!("new_from_welcome {e:?}");
            return Err(e);
        }
    }

    let group_secrets = GroupSecrets::try_from_ciphertext(
        key_material.init_private_key(),
        egs.encrypted_group_secrets(),
        welcome.encrypted_group_info(),
        ciphersuite,
        provider.crypto(),
    )?;

    // Validate PSKs
    PreSharedKeyId::validate_in_welcome(&group_secrets.psks, ciphersuite)?;

    Ok((resumption_psk_store, key_material, group_secrets))
}

/// Finish processing a `Welcome` from its already-decrypted `GroupSecrets`.
///
/// This is the second half of welcome processing (the tail of
/// [`ProcessedWelcome::new_from_welcome_inner`]): it derives the key schedule,
/// decrypts the group info, and runs the capability/ciphersuite checks,
/// producing a [`ProcessedWelcome`]. It still needs the `welcome` for its
/// encrypted group info.
///
/// For subgroup branching (`branch_info` set), the parent group's resumption
/// PSK secret is injected at the sentinel epoch 0 and the branch PSK carried in
/// the `Welcome` is checked to reference the same parent group and epoch as
/// `branch_info` — both before the secret is mixed into the key schedule, so a
/// wrong-epoch secret fails cleanly with [`WelcomeError::SubgroupParentMismatch`]
/// rather than as an opaque group-info decryption failure further down.
#[allow(clippy::too_many_arguments)]
fn finish_processed_welcome<Provider: OpenMlsProvider>(
    provider: &Provider,
    mls_group_config: &MlsGroupJoinConfig,
    ciphersuite: Ciphersuite,
    mut resumption_psk_store: ResumptionPskStore,
    key_material: WelcomeKeyMaterial,
    group_secrets: GroupSecrets,
    welcome: &Welcome,
    branch_info: Option<&BranchInfo>,
) -> Result<ProcessedWelcome, WelcomeError<<Provider as OpenMlsProvider>::StorageError>> {
    // For subgroup branching, inject the parent group's resumption PSK at
    // the sentinel epoch 0 before the PSKs are loaded.
    if let Some(branch_info) = branch_info {
        resumption_psk_store.add(0.into(), branch_info.resumption_psk_secret().clone());
    }

    // When joining a subgroup branch, the branch resumption
    // PSK carried in the Welcome must reference the same parent group and
    // epoch the receiver is branching from. This must be checked here, before
    // the injected PSK secret is mixed into the key schedule: a wrong-epoch
    // secret would otherwise only surface as an opaque group-info decryption
    // failure further down.
    if let Some(branch_info) = branch_info {
        let parent_matches = group_secrets
            .psks
            .iter()
            .filter_map(|id| match id.psk() {
                Psk::Resumption(r) if r.usage() == ResumptionPskUsage::Branch => Some(r),
                _ => None,
            })
            .any(|r| {
                r.psk_group_id() == branch_info.group_id() && r.psk_epoch() == branch_info.epoch()
            });
        if !parent_matches {
            return Err(WelcomeError::SubgroupParentMismatch);
        }
    }

    let psk_secret = {
        let psks = load_psks(
            provider.storage(),
            &resumption_psk_store,
            &group_secrets.psks,
        )?;

        PskSecret::new(provider.crypto(), ciphersuite, psks)?
    };

    // prepare the key schedule
    let mut key_schedule = KeySchedule::init(
        ciphersuite,
        provider.crypto(),
        &group_secrets.joiner_secret,
        psk_secret,
    )?;

    // derive the keys for decrypting the group info
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

    let serialized_group_context = verifiable_group_info
        .group_context()
        .tls_serialize_detached()
        .map_err(LibraryError::missing_bound_check)?;

    key_schedule.add_context(provider.crypto(), &serialized_group_context)?;

    let epoch_secrets = key_schedule.epoch_secrets(provider.crypto(), ciphersuite)?;

    // On the bundle path, check the required capabilities and the
    // ciphersuite against the local KeyPackage. On the virtual-client path
    // there is no local KeyPackage: these are checked in staging against
    // the own tree leaf instead.
    if let Some(key_package_bundle) = key_material.key_package_bundle() {
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
            log::debug!("new_from_welcome {e:?}");
            return Err(e);
        }
    }

    Ok(ProcessedWelcome {
        mls_group_config: mls_group_config.clone(),
        ciphersuite,
        group_secrets,
        epoch_secrets,
        verifiable_group_info,
        resumption_psk_store,
        key_material,
    })
}

/// Read keys for decrypting the welcome message.
fn keys_for_welcome<Provider: OpenMlsProvider>(
    mls_group_config: &MlsGroupJoinConfig,
    welcome: &Welcome,
    provider: &Provider,
) -> Result<
    (ResumptionPskStore, WelcomeKeyMaterial),
    WelcomeError<<Provider as OpenMlsProvider>::StorageError>,
> {
    let resumption_psk_store = ResumptionPskStore::new(mls_group_config.number_of_resumption_psks);

    for egs in welcome.secrets() {
        let hash_ref = egs.new_member();
        if let Some(key_package_bundle) = provider
            .storage()
            .key_package(&hash_ref)
            .map_err(WelcomeError::StorageError)?
        {
            let key_package_bundle: KeyPackageBundle = key_package_bundle;
            if !key_package_bundle.key_package().last_resort() {
                provider
                    .storage()
                    .delete_key_package(
                        &key_package_bundle.key_package.hash_ref(provider.crypto())?,
                    )
                    .map_err(WelcomeError::StorageError)?;
            } else {
                log::debug!("Key package has last resort extension, not deleting");
            }
            return Ok((
                resumption_psk_store,
                WelcomeKeyMaterial::with_key_package_bundle(key_package_bundle),
            ));
        }

        #[cfg(feature = "virtual-clients-draft")]
        if let Some(material) =
            resolve_vc_welcome_material(provider, welcome.ciphersuite(), &hash_ref)?
        {
            // The retained material stays in storage for now.
            return Ok((
                resumption_psk_store,
                WelcomeKeyMaterial::with_vc_welcome_material(material),
            ));
        }
    }

    Err(WelcomeError::NoMatchingKeyPackage)
}

/// Try to derive virtual-client welcome material for `hash_ref`. Returns
/// `None` if no [`RetainedKeyPackageMaterial`] is stored for the ref, so the
/// caller can keep scanning the welcome's encrypted group secrets.
///
/// On a match this reconstructs the per-KeyPackage seed pinned in the retained
/// material at upload-processing time, and
/// derives the init and leaf-encryption keypairs from the seed under the
/// Welcome's ciphersuite. It does not touch the operation tree: the batch
/// generation was already consumed once when the upload was processed, and the
/// seed is enough to reproduce the keys.
///
/// [`RetainedKeyPackageMaterial`]: crate::components::vc_derivation_info::RetainedKeyPackageMaterial
#[cfg(feature = "virtual-clients-draft")]
pub(crate) fn resolve_vc_welcome_material<Provider: OpenMlsProvider>(
    provider: &Provider,
    ciphersuite: Ciphersuite,
    hash_ref: &crate::ciphersuite::hash_ref::KeyPackageRef,
) -> Result<
    Option<crate::components::vc_derivation_info::VcWelcomeMaterial>,
    WelcomeError<<Provider as OpenMlsProvider>::StorageError>,
> {
    use crate::components::vc_derivation_info::{RetainedKeyPackageMaterial, VcWelcomeMaterial};

    let storage = provider.storage();
    let Some(material) = storage
        .retained_key_package_material::<_, RetainedKeyPackageMaterial>(hash_ref)
        .map_err(WelcomeError::StorageError)?
    else {
        return Ok(None);
    };

    if material.key_package_ciphersuite != ciphersuite {
        return Err(WelcomeError::CiphersuiteMismatch);
    }

    // The seed is imported into the KeyPackage's ciphersuite at
    // upload-processing time. The init and leaf-encryption keys are derived
    // from it under the KeyPackage's own (the welcome's) ciphersuite.
    let crypto = provider.crypto();
    let init_key_pair = material
        .key_package_seed_secret
        .derive_init_key_secret(crypto, ciphersuite)?
        .generate_init_key_pair(crypto, ciphersuite)?;
    let encryption_keypair = material
        .key_package_seed_secret
        .derive_encryption_key_secret(crypto, ciphersuite)?
        .generate_encryption_key_pair(crypto, ciphersuite)?;

    Ok(Some(VcWelcomeMaterial {
        key_package_ref: hash_ref.clone(),
        epoch_id: material.epoch_id,
        leaf_index: material.leaf_index,
        generation: material.generation,
        key_package_index: material.key_package_index,
        init_private_key: init_key_pair.private,
        init_key: init_key_pair.public.into(),
        encryption_keypair,
    }))
}

/// Find and validate the virtual client's own leaf in the ratchet tree.
///
/// A virtual client has no signature key of its own, so the leaf is located by
/// the derivation info the VC sender embedded under [`VC_COMPONENT_ID`]: the
/// leaf whose cleartext `epoch_id` equals the material's and whose
/// `encryption_key` equals the key derived in the first welcome stage. That
/// leaf's encrypted [`DerivationInfoTbe`] is then decrypted with the derivation
/// epoch state and its `leaf_index`, `generation`, and `key_package_index`
/// must equal the material's.
///
/// [`VC_COMPONENT_ID`]: crate::components::vc_derivation_info::VC_COMPONENT_ID
/// [`DerivationInfoTbe`]: crate::components::vc_derivation_info::DerivationInfoTbe
#[cfg(feature = "virtual-clients-draft")]
fn find_and_validate_vc_own_leaf<Provider: OpenMlsProvider>(
    provider: &Provider,
    public_group: &PublicGroup,
    material: &crate::components::vc_derivation_info::VcWelcomeMaterial,
) -> Result<LeafNodeIndex, WelcomeError<<Provider as OpenMlsProvider>::StorageError>> {
    use tls_codec::{DeserializeBytes as _, Serialize as _};

    use crate::components::vc_derivation_info::{
        DerivationInfo, DerivationInfoTbe, VcDerivationEpochState, VirtualClientOperationType,
        VirtualClientsError, VC_COMPONENT_ID,
    };

    let crypto = provider.crypto();
    let derived_encryption_key = material.encryption_keypair.public_key().as_slice().to_vec();

    let own_index = public_group
        .members()
        .find(|m| m.encryption_key == derived_encryption_key)
        .map(|m| m.index)
        .ok_or(WelcomeError::PublicTreeError(
            PublicTreeError::MalformedTree,
        ))?;

    let own_leaf = public_group
        .leaf(own_index)
        .ok_or(WelcomeError::PublicTreeError(
            PublicTreeError::MalformedTree,
        ))?;

    let derivation_info_bytes = own_leaf
        .extensions()
        .app_data_dictionary()
        .and_then(|dict| dict.dictionary().get(&VC_COMPONENT_ID))
        .ok_or(VirtualClientsError::VcComponentNotListed)?;
    let derivation_info = DerivationInfo::tls_deserialize_exact_bytes(derivation_info_bytes)
        .map_err(|e| {
            log::error!("vc: welcome leaf derivation info deserialize failed: {e:?}");
            VirtualClientsError::DerivationInfoMalformed
        })?;
    if derivation_info.epoch_id() != &material.epoch_id {
        log::error!("vc: welcome leaf epoch id does not match the retained material");
        return Err(VirtualClientsError::DerivationInfoMalformed.into());
    }

    let state: VcDerivationEpochState = provider
        .storage()
        .vc_derivation_epoch_state(&material.epoch_id)
        .map_err(|e| {
            log::error!("vc: load derivation epoch state in welcome staging failed: {e:?}");
            VirtualClientsError::StorageError
        })?
        .ok_or(VirtualClientsError::MissingDerivationEpochState)?;
    let (_state_leaf_index, epoch_encryption_key, emulation_ciphersuite) = state.into_parts();

    let leaf_encryption_key = own_leaf
        .encryption_key()
        .tls_serialize_detached()
        .map_err(VirtualClientsError::from)?;
    // A KeyPackage leaf carries the `KeyPackage` variant of the tagless
    // select, so it decodes with `key_package_index` present.
    let tbe = derivation_info.decrypt(
        crypto,
        emulation_ciphersuite,
        &epoch_encryption_key,
        &leaf_encryption_key,
        VirtualClientOperationType::KeyPackage,
    )?;

    let DerivationInfoTbe::KeyPackage {
        leaf_index,
        generation,
        key_package_index,
    } = tbe
    else {
        log::error!("vc: welcome leaf derivation info is not a key-package variant");
        return Err(VirtualClientsError::DerivationInfoMalformed.into());
    };
    if leaf_index != material.leaf_index
        || generation != material.generation
        || key_package_index != material.key_package_index
    {
        log::error!("vc: welcome leaf derivation info does not match the retained material");
        return Err(VirtualClientsError::DerivationInfoMalformed.into());
    }

    Ok(own_index)
}

#[cfg(feature = "virtual-clients-draft")]
impl MlsGroup {
    /// Returns a new [`VcExternalCommitJoinBuilder`] for joining a
    /// higher-level group as a virtual client's sibling emulator client, by
    /// processing another sibling's external commit.
    pub fn vc_external_commit_join_builder() -> VcExternalCommitJoinBuilder {
        VcExternalCommitJoinBuilder::new()
    }

    /// Bootstrap a virtual client's sibling emulator client into a higher-level
    /// group the virtual client created, when this client is not yet a member.
    ///
    /// The creator emulator client built the group with
    /// [`MlsGroupBuilder::vc_emulation`], its `key_package`-sourced leaf key
    /// material derived from a `key_package` operation secret. Sharing the same
    /// derivation epoch (`epoch_id`), this client reconstructs the epoch-0 state:
    /// it verifies the GroupInfo and single-leaf ratchet tree (which may instead
    /// travel in the GroupInfo's `ratchet_tree` extension), rederives the creator
    /// leaf's key material from the shared operation secret tree, and derives the
    /// same epoch-0 `epoch_secret` from the creator's KeyPackage seed. No secret
    /// travels on the wire. On success the returned group sits at epoch 0 with
    /// this client on the shared virtual-client leaf (index 0).
    ///
    /// [`MlsGroupBuilder::vc_emulation`]: crate::group::MlsGroupBuilder::vc_emulation
    pub fn vc_join_at_creation<Provider: OpenMlsProvider>(
        provider: &Provider,
        join_config: &MlsGroupJoinConfig,
        verifiable_group_info: VerifiableGroupInfo,
        ratchet_tree: Option<RatchetTreeIn>,
        epoch_id: crate::components::vc_derivation_info::EpochId,
    ) -> Result<MlsGroup, crate::group::errors::VcGroupCreationJoinError<Provider::StorageError>>
    {
        use tls_codec::{DeserializeBytes as _, Serialize as _};

        use crate::{
            components::vc_derivation_info::{
                load_vc_epoch_state_and_tree, DerivationInfo, DerivationInfoTbe,
                VirtualClientOperationType, VirtualClientsError, VC_COMPONENT_ID,
            },
            group::errors::VcGroupCreationJoinError as Error,
            group::public_group::PublicGroup,
            schedule::EpochSecrets,
            treesync::node::leaf_node::LeafNodeSource,
        };

        // Resolve the ratchet tree (from the GroupInfo extension or the
        // argument) and verify the GroupInfo and tree.
        let ratchet_tree = match verifiable_group_info.extensions().ratchet_tree() {
            Some(extension) => extension.ratchet_tree().clone(),
            None => ratchet_tree.ok_or(Error::MissingRatchetTree)?,
        };
        let (public_group, group_info) = PublicGroup::from_ratchet_tree(
            provider.crypto(),
            ratchet_tree,
            verifiable_group_info,
            ProposalStore::new(),
            LeafNodeLifetimePolicy::default(),
        )?;
        let ciphersuite = public_group.ciphersuite();

        // The created group consists of exactly the creator's leaf at index 0.
        if public_group.members().count() != 1 {
            return Err(Error::NotASingleLeafTree);
        }
        let creator_index = LeafNodeIndex::new(0);
        let creator_leaf = public_group
            .leaf(creator_index)
            .ok_or(Error::NotASingleLeafTree)?;

        // A virtual client's group-creation leaf is key_package-sourced.
        let LeafNodeSource::KeyPackage(_) = creator_leaf.leaf_node_source() else {
            return Err(Error::CreatorLeafNotKeyPackageSourced);
        };

        // Read the creator leaf's derivation info and check the derivation epoch.
        let derivation_info_bytes = creator_leaf
            .extensions()
            .app_data_dictionary()
            .and_then(|dict| dict.dictionary().get(&VC_COMPONENT_ID))
            .ok_or(Error::MissingDerivationInfo)?;
        let derivation_info = DerivationInfo::tls_deserialize_exact_bytes(derivation_info_bytes)
            .map_err(|_| VirtualClientsError::DerivationInfoMalformed)?;
        if derivation_info.epoch_id() != &epoch_id {
            return Err(Error::EpochIdMismatch);
        }

        // Load the derivation epoch state and operation tree.
        let (state, mut operation_tree) = load_vc_epoch_state_and_tree(provider, &epoch_id)?;
        let (_leaf_index, epoch_encryption_key, emulation_ciphersuite) = state.into_parts();

        // Decrypt the derivation info (KeyPackage case) and read the batch index
        // the creator's seed was derived under.
        let leaf_encryption_key = creator_leaf
            .encryption_key()
            .tls_serialize_detached()
            .map_err(VirtualClientsError::from)?;
        let tbe = derivation_info.decrypt(
            provider.crypto(),
            emulation_ciphersuite,
            &epoch_encryption_key,
            &leaf_encryption_key,
            VirtualClientOperationType::KeyPackage,
        )?;
        let DerivationInfoTbe::KeyPackage {
            leaf_index,
            generation,
            key_package_index,
        } = tbe
        else {
            // Decrypting with the KeyPackage operation type always yields the
            // KeyPackage variant.
            return Err(LibraryError::custom("unexpected derivation info variant").into());
        };

        // Rederive the creator's KeyPackage seed positionally from the shared
        // operation tree, then the creator leaf's encryption keypair from that
        // seed. The `key_package` operation context is empty. The advanced tree
        // is persisted only after the confirmation tag verifies, so a corrupted
        // GroupInfo naming the genuine creator leaf does not burn this sibling's
        // generation.
        let operation_secret = operation_tree.derive_operation_secret(
            provider.crypto(),
            emulation_ciphersuite,
            &epoch_id,
            leaf_index,
            VirtualClientOperationType::KeyPackage,
            generation,
            b"",
        )?;
        let key_package_seed = operation_secret.derive_key_package_seed_secret(
            provider.crypto(),
            ciphersuite,
            key_package_index,
        )?;
        let leaf_keypair = key_package_seed
            .derive_encryption_key_secret(provider.crypto(), ciphersuite)?
            .generate_encryption_key_pair(provider.crypto(), ciphersuite)?;
        if leaf_keypair.public_key() != creator_leaf.encryption_key() {
            return Err(Error::LeafKeyMismatch);
        }

        // Derive epoch-0 secrets from the same KeyPackage seed and verify the
        // GroupInfo's confirmation tag against them. A mismatch means the
        // reconstruction did not reproduce the creator's epoch secrets.
        let serialized_group_context = public_group
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        let epoch_secret =
            key_package_seed.derive_group_creation_secret(provider.crypto(), ciphersuite)?;
        let epoch_secrets =
            EpochSecrets::from_epoch_secret(provider.crypto(), ciphersuite, epoch_secret)
                .map_err(LibraryError::unexpected_crypto_error)?;
        let (group_epoch_secrets, message_secrets) = epoch_secrets.split_secrets(
            serialized_group_context,
            public_group.tree_size(),
            creator_index,
        );
        let expected_confirmation_tag = message_secrets
            .confirmation_key()
            .tag(
                provider.crypto(),
                ciphersuite,
                public_group.group_context().confirmed_transcript_hash(),
            )
            .map_err(LibraryError::unexpected_crypto_error)?;
        if &expected_confirmation_tag != group_info.confirmation_tag() {
            return Err(Error::ConfirmationTagMismatch);
        }

        // The reconstruction reproduced the creator's secrets, so this is a
        // genuine sibling-created group: persist the advanced operation tree.
        provider
            .storage()
            .write_vc_operation_tree(&epoch_id, &operation_tree)
            .map_err(Error::StorageError)?;

        let message_secrets_store = MessageSecretsStore::new_with_secret(
            join_config.past_epoch_deletion_policy(),
            message_secrets,
        );
        let mut resumption_psk_store =
            ResumptionPskStore::new(join_config.number_of_resumption_psks);
        resumption_psk_store.add(
            public_group.group_context().epoch(),
            group_epoch_secrets.resumption_psk().clone(),
        );

        // Bind epoch 0 of the created group to the derivation epoch so later
        // VC operations in this group resolve the right derivation epoch state.
        // Written before the group itself, so an error between the writes
        // cannot leave a loadable group without a binding (a bound group is
        // required for the reuse-guard MUST).
        let max_entries = message_secrets_store.max_epochs.saturating_add(1);
        crate::components::vc_derivation_info::write_vc_emulation_binding_with_pruning(
            provider.storage(),
            public_group.group_id(),
            public_group.group_context().epoch(),
            epoch_id,
            max_entries,
        )
        .map_err(Error::StorageError)?;

        let mls_group = MlsGroup {
            mls_group_config: join_config.clone(),
            own_leaf_nodes: vec![],
            aad: vec![],
            #[cfg(feature = "extensions-draft")]
            safe_aad: crate::framing::SafeAad::empty(),
            group_state: MlsGroupState::Operational,
            public_group,
            group_epoch_secrets,
            own_leaf_index: creator_index,
            message_secrets_store,
            resumption_psk_store,
            #[cfg(feature = "extensions-draft")]
            application_export_tree: None,
            #[cfg(feature = "virtual-clients-draft")]
            emulation_group: false,
        };
        mls_group
            .store(provider.storage())
            .map_err(Error::StorageError)?;
        mls_group
            .store_epoch_keypairs(provider.storage(), &[leaf_keypair])
            .map_err(Error::StorageError)?;

        Ok(mls_group)
    }
}

/// Builder for bootstrapping a virtual client's sibling emulator client into
/// a higher-level group by processing another sibling's external commit,
/// when this client is not yet a member of that group.
///
/// The first emulator client joined the higher-level group via an external
/// commit. A second emulator client (this one), sharing the same emulation
/// epoch, reconstructs the resulting group state from that commit.
///
/// The join happens in two steps. [`Self::process_commit`] rebuilds the
/// prior-epoch group and verifies the commit, returning a
/// [`StagedVcExternalCommitJoin`]. The application inspects the verified
/// proposals it exposes, resolves any AppDataUpdate proposals, and completes
/// the join with [`StagedVcExternalCommitJoin::into_group`].
#[cfg(feature = "virtual-clients-draft")]
#[derive(Debug, Default)]
pub struct VcExternalCommitJoinBuilder {
    join_config: MlsGroupJoinConfig,
    ratchet_tree: Option<RatchetTreeIn>,
    lifetime_policy: LeafNodeLifetimePolicy,
}

#[cfg(feature = "virtual-clients-draft")]
impl VcExternalCommitJoinBuilder {
    /// Creates a new [`VcExternalCommitJoinBuilder`] with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Specifies the configuration to use for the joined group.
    pub fn with_config(mut self, join_config: MlsGroupJoinConfig) -> Self {
        self.join_config = join_config;
        self
    }

    /// Specifies the prior-epoch ratchet tree. This is only used if the
    /// ratchet tree is not provided in the [`VerifiableGroupInfo`]
    /// extensions. A ratchet tree must be provided, either in the
    /// [`VerifiableGroupInfo`] extensions or via this method.
    pub fn with_ratchet_tree(mut self, ratchet_tree: RatchetTreeIn) -> Self {
        self.ratchet_tree = Some(ratchet_tree);
        self
    }

    /// Skip the validation of lifetimes in leaf nodes in the ratchet tree.
    /// Note that only the leaf nodes are checked that were never updated.
    ///
    /// By default they are validated.
    pub fn skip_lifetime_validation(mut self) -> Self {
        self.lifetime_policy = LeafNodeLifetimePolicy::Skip;
        self
    }

    /// Rebuilds the higher-level group at the epoch *before* the external
    /// commit from `verifiable_group_info` (and the ratchet tree, taken from
    /// the GroupInfo's `ratchet_tree` extension or
    /// [`Self::with_ratchet_tree`]), and verifies `external_commit` against
    /// it: the GroupInfo signature and tree, the commit's signature and
    /// external-commit shape, and that the commit's derivation info
    /// references the shared emulation epoch `epoch_id`.
    ///
    /// Nothing is consumed or persisted at this point. Dropping the returned
    /// [`StagedVcExternalCommitJoin`] discards the join without advancing
    /// the shared operation secret tree.
    pub fn process_commit<Provider: OpenMlsProvider>(
        self,
        provider: &Provider,
        verifiable_group_info: VerifiableGroupInfo,
        external_commit: impl Into<crate::framing::ProtocolMessage>,
        epoch_id: crate::components::vc_derivation_info::EpochId,
    ) -> Result<
        StagedVcExternalCommitJoin,
        crate::group::errors::VcExternalCommitJoinError<Provider::StorageError>,
    > {
        use tls_codec::DeserializeBytes as _;

        use crate::{
            components::vc_derivation_info::{
                DerivationInfo, VirtualClientsError, VC_COMPONENT_ID,
            },
            framing::Sender,
            group::config::PastEpochDeletionPolicy,
            group::errors::{ProcessMessageError, VcExternalCommitJoinError as Error},
            group::mls_group::processing::committed_app_data_update_proposals,
            group::public_group::PublicGroup,
            prelude::mls_content::FramedContentBody,
            schedule::{EpochSecrets, InitSecret},
        };

        let Self {
            join_config,
            ratchet_tree,
            lifetime_policy,
        } = self;

        // Resolve the prior-epoch ratchet tree (from the GroupInfo extension
        // or the builder) and rebuild the prior-epoch public group.
        let ratchet_tree = match verifiable_group_info.extensions().ratchet_tree() {
            Some(extension) => extension.ratchet_tree().clone(),
            None => ratchet_tree.ok_or(Error::MissingRatchetTree)?,
        };
        let (public_group, _group_info) = PublicGroup::from_ratchet_tree(
            provider.crypto(),
            ratchet_tree,
            verifiable_group_info,
            ProposalStore::new(),
            lifetime_policy,
        )?;

        // Assemble a transient group at the prior epoch. Its epoch secrets are
        // never used cryptographically here: the external commit carries the
        // external init secret and the operation secret tree supplies the path,
        // so a random init-secret stub is sufficient. The own leaf index is the
        // leftmost free index, where the committing sibling installs the shared
        // virtual-client leaf.
        let ciphersuite = public_group.ciphersuite();
        let serialized_group_context = public_group
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        let own_leaf_index = public_group.leftmost_free_index(std::iter::empty())?;
        let init_secret = InitSecret::random(ciphersuite, provider.rand())
            .map_err(LibraryError::unexpected_crypto_error)?;
        let epoch_secrets =
            EpochSecrets::with_init_secret(provider.crypto(), ciphersuite, init_secret)
                .map_err(LibraryError::unexpected_crypto_error)?;
        let (group_epoch_secrets, message_secrets) = epoch_secrets.split_secrets(
            serialized_group_context,
            public_group.tree_size(),
            LeafNodeIndex::new(0u32),
        );
        // Do not retain the synthetic prior-epoch secrets used only to stage
        // this external commit.
        let message_secrets_store = MessageSecretsStore::new_with_secret(
            &PastEpochDeletionPolicy::MaxEpochs(0),
            message_secrets,
        );
        let resumption_psk_store = ResumptionPskStore::new(join_config.number_of_resumption_psks);
        let mut group = MlsGroup {
            mls_group_config: join_config,
            own_leaf_nodes: vec![],
            aad: vec![],
            #[cfg(feature = "extensions-draft")]
            safe_aad: crate::framing::SafeAad::empty(),
            group_state: MlsGroupState::Operational,
            public_group,
            group_epoch_secrets,
            own_leaf_index,
            message_secrets_store,
            resumption_psk_store,
            #[cfg(feature = "extensions-draft")]
            application_export_tree: None,
            // A virtual client joins a higher-level group here, never its own
            // emulation group.
            emulation_group: false,
        };

        // Parse and verify the external commit against the prior-epoch group.
        // A PrivateMessage claiming our own leaf cannot be an external commit.
        let processing::UnprotectedMessage::Unverified(unverified) =
            group.unprotect_message(provider, external_commit)?
        else {
            return Err(Error::NotAnExternalCommit);
        };
        let verified = unverified
            .verify(group.ciphersuite(), provider.crypto(), group.version())
            .map_err(ProcessMessageError::from)?;
        if !matches!(verified.content.sender(), Sender::NewMemberCommit) {
            return Err(Error::NotAnExternalCommit);
        }
        let content = verified.content;
        let FramedContentBody::Commit(commit) = content.content() else {
            return Err(Error::NotAnExternalCommit);
        };

        // Check the commit's derivation info without consuming an operation
        // secret generation: presence and the emulation epoch binding are
        // validated here, decryption and the consume-once secret derivation
        // happen in `StagedVcExternalCommitJoin::into_group`.
        let derivation_info_bytes = commit
            .path
            .as_ref()
            .and_then(|path| path.leaf_node().extensions().app_data_dictionary())
            .and_then(|dict| dict.dictionary().get(&VC_COMPONENT_ID))
            .ok_or(Error::MissingDerivationInfo)?;
        let derivation_info = DerivationInfo::tls_deserialize_exact_bytes(derivation_info_bytes)
            .map_err(|_| VirtualClientsError::DerivationInfoMalformed)?;
        if derivation_info.epoch_id() != &epoch_id {
            return Err(Error::EpochIdMismatch);
        }

        // The AppDataUpdate proposals covered by the commit, for the
        // application to resolve before completing the join. The transient
        // group's proposal store is empty, so only by-value proposals
        // resolve. An external commit cannot reference proposals a
        // non-member could hold.
        let app_data_update_proposals =
            committed_app_data_update_proposals(commit, group.proposal_store());

        Ok(StagedVcExternalCommitJoin {
            group,
            content,
            app_data_update_proposals,
            app_data_updates: None,
        })
    }
}

/// A verified sibling external commit, ready to be joined. Returned by
/// [`VcExternalCommitJoinBuilder::process_commit`].
///
/// The commit's signature has been verified against the prior-epoch group,
/// so the proposals exposed here are authenticated. If the commit covers
/// AppDataUpdate proposals, the application must interpret them (with the
/// help of [`Self::app_data_dictionary_updater`]) and supply the resulting
/// [`AppDataUpdates`] via [`Self::with_app_data_dictionary_updates`] before
/// calling [`Self::into_group`], exactly as it would for
/// [`MlsGroup::resolve_app_data_commit`] when processing the same commit as
/// a member.
///
/// Dropping this value discards the join. No operation secret generation is
/// consumed before [`Self::into_group`], so a discarded join can be started
/// over by processing the same commit again.
#[cfg(feature = "virtual-clients-draft")]
pub struct StagedVcExternalCommitJoin {
    /// Transient reconstruction of the group at the prior epoch.
    group: MlsGroup,
    /// The verified commit content.
    content: AuthenticatedContent,
    /// The by-value AppDataUpdate proposals covered by the commit, sorted by
    /// component id.
    app_data_update_proposals: Vec<AppDataUpdateProposal>,
    /// The application-resolved updates for the commit's AppDataUpdate
    /// proposals, if any.
    app_data_updates: Option<AppDataUpdates>,
}

#[cfg(feature = "virtual-clients-draft")]
impl StagedVcExternalCommitJoin {
    /// Returns the [`GroupContext`] of the group at the epoch *before* the
    /// external commit. The commit's changes (including any AppDataUpdate
    /// proposals) are not applied to it. The joined group's context is
    /// available on the [`MlsGroup`] returned by [`Self::into_group`].
    pub fn prior_group_context(&self) -> &GroupContext {
        self.group.context()
    }

    /// Returns an iterator over the [`Member`]s of the group at the epoch
    /// *before* the external commit. The commit's changes are not applied:
    /// the committing sibling's virtual-client leaf is absent and members
    /// the commit inline-removes are still present.
    pub fn prior_members(&self) -> impl Iterator<Item = Member> + '_ {
        self.group.members()
    }

    /// Returns the AppDataUpdate proposals covered by the commit, sorted by
    /// component id. The application interprets them to compute the
    /// [`AppDataUpdates`] that [`Self::into_group`] requires.
    pub fn app_data_update_proposals(&self) -> impl Iterator<Item = &AppDataUpdateProposal> {
        self.app_data_update_proposals.iter()
    }

    /// Returns the AppEphemeral proposals for `component_id` that the commit
    /// carries by value, in the order they appear in the commit, for example
    /// to decide how to follow the join. Unlike
    /// [`PublicMessageIn::unverified_app_ephemeral_proposals`], the returned
    /// data is authenticated: the commit's signature has been verified.
    ///
    /// [`PublicMessageIn::unverified_app_ephemeral_proposals`]:
    ///     crate::framing::PublicMessageIn::unverified_app_ephemeral_proposals
    pub fn app_ephemeral_proposals_for_component_id(
        &self,
        component_id: ComponentId,
    ) -> impl Iterator<Item = &AppEphemeralProposal> {
        use crate::{
            messages::proposals::{Proposal, ProposalOrRef},
            prelude::mls_content::FramedContentBody,
        };

        let proposals = match self.content.content() {
            FramedContentBody::Commit(commit) => commit.proposals.as_slice(),
            // `process_commit` only constructs staged joins from commits.
            _ => &[],
        };
        proposals
            .iter()
            .filter_map(move |proposal_or_ref| match proposal_or_ref {
                ProposalOrRef::Proposal(proposal) => match proposal.as_ref() {
                    Proposal::AppEphemeral(app_ephemeral)
                        if app_ephemeral.component_id() == component_id =>
                    {
                        Some(app_ephemeral.as_ref())
                    }
                    _ => None,
                },
                ProposalOrRef::Reference(_) => None,
            })
    }

    /// Returns a helper for computing the [`AppDataUpdates`], seeded with
    /// the app data dictionary of the prior-epoch group context.
    pub fn app_data_dictionary_updater(&self) -> AppDataDictionaryUpdater<'_> {
        AppDataDictionaryUpdater::new(self.group.context().app_data_dict())
    }

    /// Sets the [`AppDataUpdates`] that contain the changes made by the
    /// commit's AppDataUpdate proposals. Updates must be set exactly when
    /// the commit covers AppDataUpdate proposals.
    pub fn with_app_data_dictionary_updates(&mut self, app_data_updates: Option<AppDataUpdates>) {
        self.app_data_updates = app_data_updates;
    }

    /// Completes the join and returns the joined [`MlsGroup`]. If the commit
    /// covers AppDataUpdate proposals, the resolved updates must have been
    /// set via [`Self::with_app_data_dictionary_updates`]. Absent updates
    /// are rejected before the consume-once operation secret generation is
    /// spent, so the join can be started over. Updates that do not reproduce
    /// the committing sibling's dictionary fail with a confirmation tag
    /// mismatch after the generation is consumed, so they should be computed
    /// deterministically from the proposals rather than guessed.
    pub fn into_group<Provider: OpenMlsProvider>(
        self,
        provider: &Provider,
    ) -> Result<MlsGroup, crate::group::errors::VcExternalCommitJoinError<Provider::StorageError>>
    {
        use crate::{
            group::errors::{StageCommitError, VcExternalCommitJoinError as Error},
            group::public_group::errors::ApplyAppDataUpdateError,
            prelude::mls_content::FramedContentBody,
        };

        let Self {
            mut group,
            content,
            app_data_update_proposals,
            app_data_updates,
        } = self;

        // An application that has not resolved the commit's AppDataUpdate
        // proposals yet is rejected before the operation secret generation
        // is consumed, so it can compute the updates and process the commit
        // again. Staging repeats this check. Superfluous updates are only
        // rejected there.
        if !app_data_update_proposals.is_empty() && app_data_updates.is_none() {
            return Err(StageCommitError::ApplyAppDataUpdateError(
                ApplyAppDataUpdateError::MissingAppDataUpdates,
            )
            .into());
        }

        let FramedContentBody::Commit(commit) = content.content() else {
            // `process_commit` only constructs staged joins from commits.
            return Err(LibraryError::custom("staged join without commit content").into());
        };

        // Recover the sibling-VC commit material (operation secret + emulation
        // epoch id + carried external init secret) from the leaf's derivation
        // info, then stage and merge the commit through the sibling-VC path.
        let material = group
            .load_vc_commit_material(provider, commit)?
            .ok_or(Error::MissingDerivationInfo)?;
        let staged = group.stage_commit_with_app_data_updates(
            &content,
            vec![],
            vec![],
            app_data_updates,
            provider,
            Some(material),
        )?;
        group.merge_staged_commit(provider, staged)?;
        let deletion_policy = group.mls_group_config.past_epoch_deletion_policy().clone();
        group.resize_message_secrets_store(&deletion_policy);
        group
            .store(provider.storage())
            .map_err(Error::StorageError)?;
        Ok(group)
    }
}

/// Verify or skip the validation of leaf node lifetimes in the ratchet tree
/// when joining a group.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeafNodeLifetimePolicy {
    /// Verify the lifetime of leaf nodes in the ratchet tree.
    ///
    /// **NOTE:** Only leaf nodes that have never been updated have a lifetime.
    #[default]
    Verify,

    /// Skip the verification of the lifeimte in leaf nodes in the ratchet tree.
    Skip,
}

/// Builder for joining a group.
///
/// Create this with [`StagedWelcome::build_from_welcome`].
pub struct JoinBuilder<'a, Provider: OpenMlsProvider> {
    provider: &'a Provider,
    processed_welcome: ProcessedWelcome,
    ratchet_tree: Option<RatchetTreeIn>,
    validate_lifetimes: LeafNodeLifetimePolicy,
    replace_old_group: bool,
    /// Set when joining a subgroup branch (see [`StagedWelcome::build_from_branch`]).
    /// Triggers the receiver checks in [`Self::build`].
    branch: Option<BranchInfo>,
    /// Whether to check that every subgroup member is also a parent-group
    /// member. Only relevant when [`Self::branch`] is set. Defaults to `true`.
    check_members: bool,
}

impl<'a, Provider: OpenMlsProvider> JoinBuilder<'a, Provider> {
    /// Create a new builder for the [`JoinBuilder`].
    pub fn new(provider: &'a Provider, processed_welcome: ProcessedWelcome) -> Self {
        Self {
            provider,
            processed_welcome,
            ratchet_tree: None,
            replace_old_group: false,
            validate_lifetimes: LeafNodeLifetimePolicy::Verify,
            branch: None,
            check_members: true,
        }
    }

    /// Seed this builder with the parent group's [`BranchInfo`], turning it into
    /// a subgroup-branch join (see [`StagedWelcome::build_from_branch`]).
    fn with_branch_info(mut self, branch_info: BranchInfo) -> Self {
        self.branch = Some(branch_info);
        self
    }

    /// When joining a subgroup branch, controls whether [`Self::build`] checks
    /// that every subgroup member is also a member of the parent group receiver
    /// check (c)). Defaults to `true`.
    ///
    /// This has no effect on a regular (non-branch) join.
    pub fn check_members(mut self, check_members: bool) -> Self {
        self.check_members = check_members;
        self
    }

    /// The ratchet tree to use for the new group.
    pub fn with_ratchet_tree(mut self, ratchet_tree: RatchetTreeIn) -> Self {
        self.ratchet_tree = Some(ratchet_tree);
        self
    }

    /// Instruct the builder to replace any existing group with the same ID.
    pub fn replace_old_group(mut self) -> Self {
        self.replace_old_group = true;
        self
    }

    /// Skip the validation of lifetimes in leaf nodes in the ratchet tree.
    /// Note that only the leaf nodes are checked that were never updated.
    ///
    /// By default they are validated.
    pub fn skip_lifetime_validation(mut self) -> Self {
        self.validate_lifetimes = LeafNodeLifetimePolicy::Skip;
        self
    }

    /// Get a reference to the [`ProcessedWelcome`].
    ///
    /// Use this to inspect the [`Welcome`] message before validation.
    pub fn processed_welcome(&self) -> &ProcessedWelcome {
        &self.processed_welcome
    }

    /// Build the [`StagedWelcome`].
    pub fn build(self) -> Result<StagedWelcome, WelcomeError<Provider::StorageError>> {
        // Receiver checks (a) and (b): when joining a subgroup branch, the
        // version and ciphersuite must match the parent group, and the subgroup
        // must be at epoch 1.
        if let Some(branch_info) = &self.branch {
            let group_info = self.processed_welcome.unverified_group_info();
            if group_info.group_context().protocol_version() != branch_info.version()
                || group_info.ciphersuite() != branch_info.ciphersuite()
            {
                return Err(WelcomeError::SubgroupParameterMismatch);
            }
            if group_info.group_context().epoch().as_u64() != 1 {
                return Err(WelcomeError::SubgroupEpochInvalid);
            }
        }

        let staged_welcome = self.processed_welcome.into_staged_welcome_inner(
            self.provider,
            self.ratchet_tree,
            self.validate_lifetimes,
            self.replace_old_group,
        )?;

        // Receiver check (c): every LeafNode in the subgroup must
        // match a LeafNode in the parent group.
        if let Some(branch_info) = &self.branch {
            if self.check_members {
                for member in staged_welcome.members() {
                    if !branch_info
                        .member_credentials()
                        .contains(&member.credential)
                    {
                        return Err(WelcomeError::SubgroupLeafMismatch);
                    }
                }
            }
        }

        Ok(staged_welcome)
    }
}
