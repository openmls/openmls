use log::debug;
use openmls_traits::crypto::OpenMlsCrypto;
use tls_codec::Deserialize;

use crate::{
    ciphersuite::{hash_ref::HashReference, signable::Verifiable},
    extensions::ExtensionType,
    group::{core_group::*, errors::WelcomeError, *},
    key_packages::*,
    messages::*,
    schedule::{errors::PskError, *},
    treesync::{errors::TreeSyncFromNodesError, node::Node},
};

impl CoreGroup {
    // Join a group from a welcome message
    pub fn new_from_welcome(
        welcome: Welcome,
        nodes_option: Option<Vec<Option<Node>>>,
        key_package_bundle: KeyPackageBundle,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, WelcomeError> {
        log::debug!("CoreGroup::new_from_welcome_internal");
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
                key_package_bundle.private_key().as_slice(),
                &[],
                &[],
            )
            .map_err(|_| WelcomeError::UnableToDecrypt)?;
        let group_secrets = GroupSecrets::tls_deserialize(&mut group_secrets_bytes.as_slice())
            .map_err(|_| WelcomeError::MalformedWelcomeMessage)?
            .config(ciphersuite, mls_version);
        let joiner_secret = group_secrets.joiner_secret;

        // Prepare the PskSecret
        let psk_secret = PskSecret::new(ciphersuite, backend, group_secrets.psks.psks()).map_err(
            |e| match e {
                PskError::LibraryError(e) => e.into(),
                PskError::TooManyKeys => WelcomeError::PskTooManyKeys,
                PskError::KeyNotFound => WelcomeError::PskNotFound,
            },
        )?;

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
        let group_info = GroupInfo::tls_deserialize(&mut group_info_bytes.as_slice())
            .map_err(|_| WelcomeError::MalformedWelcomeMessage)?;

        // Make sure that we can support the required capabilities in the group info.
        let group_context_extensions = group_info.group_context_extensions();
        let required_capabilities = group_context_extensions
            .iter()
            .find(|&extension| extension.extension_type() == ExtensionType::RequiredCapabilities);
        if let Some(required_capabilities) = required_capabilities {
            let required_capabilities = required_capabilities
                .as_required_capabilities_extension()
                .map_err(|_| LibraryError::custom("Expected required capabilities extension"))?;
            required_capabilities
                .check_support()
                .map_err(|_| WelcomeError::UnsupportedCapability)?;
            // Also check that our key package actually supports the extensions.
            // Per spec the sender must have checked this. But you never know.
            key_package_bundle
                .key_package()
                .check_extension_support(required_capabilities.extensions())
                .map_err(|_| WelcomeError::UnsupportedExtensions)?
        }

        let path_secret_option = group_secrets.path_secret;

        // Build the ratchet tree

        // Set nodes either from the extension or from the `nodes_option`.
        // If we got a ratchet tree extension in the welcome, we enable it for
        // this group. Note that this is not strictly necessary. But there's
        // currently no other mechanism to enable the extension.
        let (nodes, enable_ratchet_tree_extension) =
            match try_nodes_from_extensions(group_info.other_extensions(), backend.crypto())
                .map_err(|e| match e {
                    ExtensionError::DuplicateRatchetTreeExtension => {
                        WelcomeError::DuplicateRatchetTreeExtension
                    }
                    _ => LibraryError::custom("Unexpected extension error").into(),
                })? {
                Some(nodes) => (nodes, true),
                None => match nodes_option {
                    Some(n) => (n, false),
                    None => return Err(WelcomeError::MissingRatchetTree),
                },
            };

        // Commit secret is ignored when joining a group, since we already have
        // the joiner_secret.
        let (tree, _commit_secret_option) = TreeSync::from_nodes_with_secrets(
            backend,
            ciphersuite,
            &nodes,
            group_info.signer(),
            path_secret_option,
            key_package_bundle,
        )
        .map_err(|e| match e {
            TreeSyncFromNodesError::LibraryError(e) => e.into(),
            TreeSyncFromNodesError::PublicTreeError(e) => WelcomeError::PublicTreeError(e),
        })?;

        let signer_key_package = tree
            .leaf_from_id(group_info.signer())
            .ok_or(WelcomeError::UnknownSender)?
            .key_package();

        // Verify GroupInfo signature
        group_info
            .verify_no_out(backend, signer_key_package.credential())
            .map_err(|_| WelcomeError::InvalidGroupInfoSignature)?;

        // Compute state
        let group_context = GroupContext::new(
            group_info.group_id().clone(),
            group_info.epoch(),
            tree.tree_hash().to_vec(),
            group_info.confirmed_transcript_hash().to_vec(),
            group_context_extensions,
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
            tree.leaf_count()
                .map_err(|_| LibraryError::custom("The tree was too big"))?,
            tree.own_leaf_index(),
        );

        let confirmation_tag = message_secrets
            .confirmation_key()
            .tag(backend, group_context.confirmed_transcript_hash())
            .map_err(LibraryError::unexpected_crypto_error)?;
        let interim_transcript_hash = update_interim_transcript_hash(
            ciphersuite,
            backend,
            &MlsPlaintextCommitAuthData::from(&confirmation_tag),
            group_context.confirmed_transcript_hash(),
        )?;

        // Verify confirmation tag
        if &confirmation_tag != group_info.confirmation_tag() {
            log::error!("Confirmation tag mismatch");
            log_crypto!(trace, "  Got:      {:x?}", confirmation_tag);
            log_crypto!(trace, "  Expected: {:x?}", group_info.confirmation_tag());
            Err(WelcomeError::ConfirmationTagMismatch)
        } else {
            let message_secrets_store = MessageSecretsStore::new_with_secret(0, message_secrets);

            Ok(CoreGroup {
                ciphersuite,
                group_context,
                group_epoch_secrets,
                tree,
                interim_transcript_hash,
                use_ratchet_tree_extension: enable_ratchet_tree_extension,
                mls_version,
                message_secrets_store,
            })
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
