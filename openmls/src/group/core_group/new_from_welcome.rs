use log::debug;
use openmls_traits::{crypto::OpenMlsCrypto, key_store::OpenMlsKeyStore};
use tls_codec::Deserialize;

use crate::{
    ciphersuite::{hash_ref::HashReference, signable::Verifiable, OpenMlsSignaturePublicKey},
    group::{core_group::*, errors::WelcomeError},
    schedule::errors::PskError,
    treesync::{
        errors::{PublicTreeError, TreeSyncFromNodesError, TreeSyncSetPathError},
        node::{encryption_keys::EncryptionKeyPair, Node},
    },
};

impl CoreGroup {
    // Join a group from a welcome message
    pub fn new_from_welcome<KeyStore: OpenMlsKeyStore>(
        welcome: Welcome,
        nodes_option: Option<Vec<Option<Node>>>,
        key_package_bundle: KeyPackageBundle,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
    ) -> Result<Self, WelcomeError<KeyStore::Error>> {
        log::debug!("CoreGroup::new_from_welcome_internal");

        // Read the encryption key pair from the key store and delete it there.
        // TODO #1207: Key store access happens as early as possible so it can
        // be pulled up later more easily.
        let leaf_keypair = EncryptionKeyPair::read_from_key_store(
            backend,
            key_package_bundle.key_package.leaf_node().encryption_key(),
        )
        .ok_or(WelcomeError::NoMatchingEncryptionKey)?;
        leaf_keypair
            .delete_from_key_store(backend)
            .map_err(|_| WelcomeError::NoMatchingEncryptionKey)?;

        let mls_version = *welcome.version();
        if mls_version != ProtocolVersion::Mls10 {
            return Err(WelcomeError::UnsupportedMlsVersion);
        }

        let ciphersuite = welcome.ciphersuite();

        // Find key_package in welcome secrets
        let egs = if let Some(egs) = Self::find_key_package_from_welcome_secrets(
            key_package_bundle
                .key_package()
                .hash_ref(backend.crypto())?,
            welcome.secrets(),
        ) {
            egs
        } else {
            return Err(WelcomeError::JoinerSecretNotFound);
        };
        if ciphersuite != key_package_bundle.key_package().ciphersuite() {
            let e = WelcomeError::CiphersuiteMismatch;
            debug!("new_from_welcome {:?}", e);
            return Err(e);
        }

        let group_secrets_bytes = backend
            .crypto()
            .hpke_open(
                ciphersuite.hpke_config(),
                egs.encrypted_group_secrets(),
                key_package_bundle.private_key.as_slice(),
                &[],
                &[],
            )
            .map_err(|_| WelcomeError::UnableToDecrypt)?;
        let group_secrets = GroupSecrets::tls_deserialize(&mut group_secrets_bytes.as_slice())
            .map_err(|_| WelcomeError::MalformedWelcomeMessage)?
            .config(ciphersuite, mls_version);
        let joiner_secret = group_secrets.joiner_secret;

        // Prepare the PskSecret
        let psk_secret =
            PskSecret::new(ciphersuite, backend, &group_secrets.psks).map_err(|e| match e {
                PskError::LibraryError(e) => e.into(),
                PskError::TooManyKeys => WelcomeError::PskTooManyKeys,
                PskError::KeyNotFound => WelcomeError::PskNotFound,
            })?;

        // Create key schedule
        let mut key_schedule = KeySchedule::init(ciphersuite, backend, joiner_secret, psk_secret)?;

        // Derive welcome key & nonce from the key schedule
        let (welcome_key, welcome_nonce) = key_schedule
            .welcome(backend)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?
            .derive_welcome_key_nonce(backend)
            .map_err(LibraryError::unexpected_crypto_error)?;

        let group_info_bytes = welcome_key
            .aead_open(backend, welcome.encrypted_group_info(), &[], &welcome_nonce)
            .map_err(|_| WelcomeError::GroupInfoDecryptionFailure)?;
        let verifiable_group_info =
            VerifiableGroupInfo::tls_deserialize(&mut group_info_bytes.as_slice())
                .map_err(|_| WelcomeError::MalformedWelcomeMessage)?;

        if ciphersuite != verifiable_group_info.ciphersuite() {
            return Err(WelcomeError::GroupInfoCiphersuiteMismatch);
        }

        // Make sure that we can support the required capabilities in the group info.
        if let Some(required_capabilities) =
            verifiable_group_info.extensions().required_capabilities()
        {
            required_capabilities
                .check_support()
                .map_err(|_| WelcomeError::UnsupportedCapability)?;
            // Also check that our key package actually supports the extensions.
            // Per spec the sender must have checked this. But you never know.
            key_package_bundle
                .key_package()
                .leaf_node()
                .validate_required_capabilities(required_capabilities)?;
        }

        let path_secret_option = group_secrets.path_secret;

        // Build the ratchet tree

        // Set nodes either from the extension or from the `nodes_option`.
        // If we got a ratchet tree extension in the welcome, we enable it for
        // this group. Note that this is not strictly necessary. But there's
        // currently no other mechanism to enable the extension.
        let (nodes, enable_ratchet_tree_extension) =
            match try_nodes_from_extensions(verifiable_group_info.extensions()) {
                Some(nodes) => (nodes, true),
                None => match nodes_option {
                    Some(n) => (n, false),
                    None => return Err(WelcomeError::MissingRatchetTree),
                },
            };

        let tree = TreeSync::from_nodes(
            backend,
            ciphersuite,
            &nodes,
            key_package_bundle
                .key_package()
                .leaf_node()
                .encryption_key(),
        )
        .map_err(|e| match e {
            TreeSyncFromNodesError::LibraryError(e) => e.into(),
            TreeSyncFromNodesError::PublicTreeError(e) => WelcomeError::PublicTreeError(e),
        })?;

        let diff = tree.empty_diff();

        // If we got a path secret, derive the path (which also checks if the
        // public keys match) and store the derived keys in the key store.
        let group_keypairs = if let Some(path_secret) = path_secret_option {
            let (path_keypairs, _commit_secret) = diff
                .derive_path_secrets(
                    backend,
                    ciphersuite,
                    path_secret,
                    verifiable_group_info.signer(),
                )
                .map_err(|e| match e {
                    TreeSyncSetPathError::LibraryError(e) => e.into(),
                    TreeSyncSetPathError::PublicKeyMismatch => {
                        WelcomeError::PublicTreeError(PublicTreeError::PublicKeyMismatch)
                    }
                })?;
            vec![leaf_keypair]
                .into_iter()
                .chain(path_keypairs.into_iter())
                .collect()
        } else {
            vec![leaf_keypair]
        };

        let group_info: GroupInfo = {
            let signature_key = tree
                .leaf(verifiable_group_info.signer())
                .ok_or(WelcomeError::UnknownSender)?
                .signature_key();
            let group_info_signer_pk = OpenMlsSignaturePublicKey::from_signature_key(
                signature_key.clone(),
                ciphersuite.signature_algorithm(),
            );

            verifiable_group_info
                .verify(backend.crypto(), &group_info_signer_pk)
                .map_err(|_| WelcomeError::InvalidGroupInfoSignature)?
        };

        // Compute state
        let group_context = GroupContext::new(
            ciphersuite,
            group_info.group_context().group_id().clone(),
            group_info.group_context().epoch(),
            tree.tree_hash().to_vec(),
            group_info
                .group_context()
                .confirmed_transcript_hash()
                .to_vec(),
            group_info.group_context().extensions().clone(),
        );

        let serialized_group_context = group_context
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        // TODO #751: Implement PSK
        key_schedule
            .add_context(backend, &serialized_group_context)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        let epoch_secrets = key_schedule
            .epoch_secrets(backend)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;

        let (group_epoch_secrets, message_secrets) = epoch_secrets.split_secrets(
            serialized_group_context,
            tree.leaf_count(),
            tree.own_leaf_index(),
        );

        let confirmation_tag = message_secrets
            .confirmation_key()
            .tag(backend, group_context.confirmed_transcript_hash())
            .map_err(LibraryError::unexpected_crypto_error)?;
        let interim_transcript_hash = update_interim_transcript_hash(
            ciphersuite,
            backend,
            &InterimTranscriptHashInput::from(&confirmation_tag),
            group_context.confirmed_transcript_hash(),
        )?;

        // Verify confirmation tag
        if &confirmation_tag != group_info.confirmation_tag() {
            log::error!("Confirmation tag mismatch");
            log_crypto!(trace, "  Got:      {:x?}", confirmation_tag);
            log_crypto!(trace, "  Expected: {:x?}", group_info.confirmation_tag());
            debug_assert!(false, "Confirmation tag mismatch");
            Err(WelcomeError::ConfirmationTagMismatch)
        } else {
            let message_secrets_store = MessageSecretsStore::new_with_secret(0, message_secrets);

            let group = CoreGroup {
                ciphersuite,
                group_context,
                group_epoch_secrets,
                tree,
                interim_transcript_hash,
                use_ratchet_tree_extension: enable_ratchet_tree_extension,
                mls_version,
                message_secrets_store,
            };
            group
                .store_epoch_keypairs(backend, group_keypairs.as_slice())
                .map_err(WelcomeError::KeyStoreError)?;

            Ok(group)
        }
    }

    // Helper functions

    pub(crate) fn find_key_package_from_welcome_secrets(
        hash_ref: HashReference,
        welcome_secrets: &[EncryptedGroupSecrets],
    ) -> Option<EncryptedGroupSecrets> {
        for egs in welcome_secrets {
            if hash_ref == egs.new_member() {
                return Some(egs.clone());
            }
        }
        None
    }
}
