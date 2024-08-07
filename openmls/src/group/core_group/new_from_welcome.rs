use log::debug;

use crate::{
    group::{core_group::*, errors::WelcomeError},
    schedule::psk::store::ResumptionPskStore,
    storage::OpenMlsProvider,
    treesync::errors::{DerivePathError, PublicTreeError},
};

impl StagedCoreWelcome {
    /// Create a staged join from a welcome message. The purpose of this type is to be able to
    /// extract information, such as the identify of who created the welcome, before joining the
    /// group.
    /// Note: calling this function will consume the key material for decrypting the [`Welcome`]
    /// message, even if the caller does not turn the [`StagedCoreWelcome`] into a [`CoreGroup`].
    pub fn new_from_welcome<Provider: OpenMlsProvider>(
        welcome: Welcome,
        ratchet_tree: Option<RatchetTreeIn>,
        key_package_bundle: KeyPackageBundle,
        provider: &Provider,
        resumption_psk_store: ResumptionPskStore,
    ) -> Result<Self, WelcomeError<Provider::StorageError>> {
        log::debug!("CoreGroup::new_from_welcome_internal");
        let (ciphersuite, group_secrets, key_schedule, verifiable_group_info) = process_welcome(
            welcome,
            &key_package_bundle,
            provider,
            &resumption_psk_store,
        )?;

        build_staged_welcome(
            verifiable_group_info,
            ratchet_tree,
            provider,
            key_package_bundle,
            key_schedule,
            ciphersuite,
            resumption_psk_store,
            group_secrets,
        )
    }

    /// Returns the [`LeafNodeIndex`] of the group member that authored the [`Welcome`] message.
    pub fn welcome_sender_index(&self) -> LeafNodeIndex {
        self.verifiable_group_info.signer()
    }

    /// Returns the [`LeafNode`] of the group member that authored the [`Welcome`] message.
    pub fn welcome_sender(&self) -> Result<&LeafNode, LibraryError> {
        let sender_index = self.welcome_sender_index();
        self.public_group
            .leaf(sender_index)
            .ok_or(LibraryError::custom(
                "no leaf with given welcome sender index exists",
            ))
    }

    /// Consumes the [`StagedCoreWelcome`] and returns the respective [`CoreGroup`].
    pub fn into_core_group<Provider: OpenMlsProvider>(
        self,
        provider: &Provider,
    ) -> Result<CoreGroup, WelcomeError<Provider::StorageError>> {
        // If we got a path secret, derive the path (which also checks if the
        // public keys match) and store the derived keys in the key store.
        let group_keypairs = if let Some(path_keypairs) = self.path_keypairs {
            let mut keypairs = vec![self.key_package_bundle.encryption_key_pair()];
            keypairs.extend_from_slice(&path_keypairs);
            keypairs
        } else {
            vec![self.key_package_bundle.encryption_key_pair()]
        };

        let group = CoreGroup {
            public_group: self.public_group,
            group_epoch_secrets: self.group_epoch_secrets,
            own_leaf_index: self.own_leaf_index,
            use_ratchet_tree_extension: self.use_ratchet_tree_extension,
            message_secrets_store: self.message_secrets_store,
            resumption_psk_store: self.resumption_psk_store,
        };

        group
            .store(provider.storage())
            .map_err(WelcomeError::StorageError)?;
        group
            .store_epoch_keypairs(provider.storage(), group_keypairs.as_slice())
            .map_err(WelcomeError::StorageError)?;

        Ok(group)
    }
}

#[allow(clippy::too_many_arguments)]
pub(in crate::group) fn build_staged_welcome<Provider: OpenMlsProvider>(
    verifiable_group_info: VerifiableGroupInfo,
    ratchet_tree: Option<RatchetTreeIn>,
    provider: &Provider,
    key_package_bundle: KeyPackageBundle,
    mut key_schedule: KeySchedule,
    ciphersuite: Ciphersuite,
    mut resumption_psk_store: ResumptionPskStore,
    group_secrets: GroupSecrets,
) -> Result<StagedCoreWelcome, WelcomeError<Provider::StorageError>> {
    // Build the ratchet tree and group

    // Set nodes either from the extension or from the `nodes_option`.
    // If we got a ratchet tree extension in the welcome, we enable it for
    // this group. Note that this is not strictly necessary. But there's
    // currently no other mechanism to enable the extension.
    let (ratchet_tree, enable_ratchet_tree_extension) =
        match verifiable_group_info.extensions().ratchet_tree() {
            Some(extension) => (extension.ratchet_tree().clone(), true),
            None => match ratchet_tree {
                Some(ratchet_tree) => (ratchet_tree, false),
                None => return Err(WelcomeError::MissingRatchetTree),
            },
        };

    // Since there is currently only the external pub extension, there is no
    // group info extension of interest here.
    let (public_group, _group_info_extensions) = PublicGroup::from_external(
        provider,
        ratchet_tree,
        verifiable_group_info.clone(),
        ProposalStore::new(),
    )?;

    // Find our own leaf in the tree.
    let own_leaf_index = public_group
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
        ))?;

    let (group_epoch_secrets, message_secrets) = {
        let serialized_group_context = public_group
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        // TODO #751: Implement PSK
        key_schedule
            .add_context(provider.crypto(), &serialized_group_context)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;

        let epoch_secrets = key_schedule
            .epoch_secrets(provider.crypto(), ciphersuite)
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
            ciphersuite,
            public_group.group_context().confirmed_transcript_hash(),
        )
        .map_err(LibraryError::unexpected_crypto_error)?;

    // Verify confirmation tag
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
    resumption_psk_store.add(public_group.group_context().epoch(), resumption_psk.clone());

    let welcome_sender_index = verifiable_group_info.signer();
    let path_keypairs = if let Some(path_secret) = group_secrets.path_secret {
        let (path_keypairs, _commit_secret) = public_group
            .derive_path_secrets(
                provider.crypto(),
                ciphersuite,
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

    let group = StagedCoreWelcome {
        public_group,
        group_epoch_secrets,
        own_leaf_index,
        use_ratchet_tree_extension: enable_ratchet_tree_extension,
        message_secrets_store,
        resumption_psk_store,
        verifiable_group_info,
        key_package_bundle,
        path_keypairs,
    };

    Ok(group)
}

/// Process a Welcome message up to the point where the ratchet tree is required.
pub(in crate::group) fn process_welcome<Provider: OpenMlsProvider>(
    welcome: Welcome,
    key_package_bundle: &KeyPackageBundle,
    provider: &Provider,
    resumption_psk_store: &ResumptionPskStore,
) -> Result<
    (Ciphersuite, GroupSecrets, KeySchedule, VerifiableGroupInfo),
    WelcomeError<Provider::StorageError>,
> {
    let ciphersuite = welcome.ciphersuite();
    let Some(egs) = welcome.find_encrypted_group_secret(
        key_package_bundle
            .key_package()
            .hash_ref(provider.crypto())?,
    ) else {
        return Err(WelcomeError::JoinerSecretNotFound);
    };
    if ciphersuite != key_package_bundle.key_package().ciphersuite() {
        let e = WelcomeError::CiphersuiteMismatch;
        debug!("new_from_welcome {:?}", e);
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
            resumption_psk_store,
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
    if let Some(required_capabilities) = verifiable_group_info.extensions().required_capabilities()
    {
        // Also check that our key package actually supports the extensions.
        // Per spec the sender must have checked this. But you never know.
        key_package_bundle
            .key_package()
            .leaf_node()
            .capabilities()
            .supports_required_capabilities(required_capabilities)?;
    }
    Ok((
        ciphersuite,
        group_secrets,
        key_schedule,
        verifiable_group_info,
    ))
}
