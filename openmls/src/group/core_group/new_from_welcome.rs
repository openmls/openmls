use log::debug;
use openmls_traits::key_store::OpenMlsKeyStore;
use tls_codec::Deserialize;

use crate::{
    ciphersuite::{hash_ref::HashReference, hpke},
    group::{core_group::*, errors::WelcomeError},
    schedule::errors::PskError,
    treesync::{
        errors::{DerivePathError, PublicTreeError},
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

        let group_secrets_bytes = hpke::decrypt_with_label(
            key_package_bundle.private_key.as_slice(),
            "Welcome",
            welcome.encrypted_group_info(),
            egs.encrypted_group_secrets(),
            ciphersuite,
            backend.crypto(),
        )
        .map_err(|_| WelcomeError::UnableToDecrypt)?;
        let group_secrets = GroupSecrets::tls_deserialize(&mut group_secrets_bytes.as_slice())
            .map_err(|_| WelcomeError::MalformedWelcomeMessage)?
            // TODO(#1065)
            .config(ciphersuite, ProtocolVersion::Mls10);

        let joiner_secret = group_secrets.joiner_secret;

        // Prepare the PskSecret
        let psk_secret =
            PskSecret::new(ciphersuite, backend, &group_secrets.psks).map_err(|e| match e {
                PskError::LibraryError(e) => e.into(),
                PskError::TooManyKeys => WelcomeError::PskTooManyKeys,
                PskError::KeyNotFound => WelcomeError::PskNotFound,
            })?;

        // Create key schedule
        let mut key_schedule = KeySchedule::init(ciphersuite, backend, &joiner_secret, psk_secret)?;

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

        let welcome_sender_index = verifiable_group_info.signer();

        // Since there is currently only the external pub extension, there is no
        // group info extension of interest here.
        let (public_group, _group_info_extensions) =
            PublicGroup::from_external(backend, &nodes, verifiable_group_info)?;

        // Find our own leaf in the tree.
        let own_leaf_index = public_group
            .treesync()
            .find_leaf(key_package_bundle.key_package().leaf_node().signature_key())
            .ok_or(WelcomeError::PublicTreeError(
                PublicTreeError::MalformedTree,
            ))?;

        // If we got a path secret, derive the path (which also checks if the
        // public keys match) and store the derived keys in the key store.
        let group_keypairs = if let Some(path_secret) = path_secret_option {
            let (path_keypairs, _commit_secret) = public_group
                .derive_path_secrets(
                    backend,
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
            vec![leaf_keypair]
                .into_iter()
                .chain(path_keypairs.into_iter())
                .collect()
        } else {
            vec![leaf_keypair]
        };

        let serialized_group_context = public_group
            .group_context()
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
            public_group.treesync().tree_size(),
            own_leaf_index,
        );

        let confirmation_tag = message_secrets
            .confirmation_key()
            .tag(
                backend,
                public_group.group_context().confirmed_transcript_hash(),
            )
            .map_err(LibraryError::unexpected_crypto_error)?;

        // Verify confirmation tag
        if &confirmation_tag != public_group.confirmation_tag() {
            log::error!("Confirmation tag mismatch");
            log_crypto!(trace, "  Got:      {:x?}", confirmation_tag);
            log_crypto!(trace, "  Expected: {:x?}", public_group.confirmation_tag());
            debug_assert!(false, "Confirmation tag mismatch");
            Err(WelcomeError::ConfirmationTagMismatch)
        } else {
            let message_secrets_store = MessageSecretsStore::new_with_secret(0, message_secrets);

            let group = CoreGroup {
                public_group,
                group_epoch_secrets,
                own_leaf_index,
                use_ratchet_tree_extension: enable_ratchet_tree_extension,
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
