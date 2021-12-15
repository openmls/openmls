use log::debug;
use openmls_traits::crypto::OpenMlsCrypto;
use tls_codec::Deserialize;

use crate::ciphersuite::signable::Verifiable;
use crate::extensions::ExtensionType;
use crate::group::{mls_group::*, *};
use crate::key_packages::*;
use crate::messages::*;
use crate::schedule::*;
use crate::treesync::node::Node;

impl MlsGroup {
    pub(crate) fn new_from_welcome_internal(
        welcome: Welcome,
        nodes_option: Option<Vec<Option<Node>>>,
        key_package_bundle: KeyPackageBundle,
        psk_fetcher_option: Option<PskFetcher>,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, WelcomeError> {
        log::debug!("MlsGroup::new_from_welcome_internal");
        let mls_version = *welcome.version();
        if !Config::supported_versions().contains(&mls_version) {
            return Err(WelcomeError::UnsupportedMlsVersion);
        }

        let ciphersuite_name = welcome.ciphersuite();
        let ciphersuite = Config::ciphersuite(ciphersuite_name)?;

        // Find key_package in welcome secrets
        let egs = if let Some(egs) = Self::find_key_package_from_welcome_secrets(
            key_package_bundle.key_package(),
            welcome.secrets(),
            backend,
        )? {
            egs
        } else {
            return Err(WelcomeError::JoinerSecretNotFound);
        };
        if ciphersuite_name != key_package_bundle.key_package().ciphersuite_name() {
            let e = WelcomeError::CiphersuiteMismatch;
            debug!("new_from_welcome {:?}", e);
            return Err(e);
        }

        let group_secrets_bytes = backend.crypto().hpke_open(
            ciphersuite.hpke_config(),
            &egs.encrypted_group_secrets,
            key_package_bundle.private_key().as_slice(),
            &[],
            &[],
        )?;
        let group_secrets = GroupSecrets::tls_deserialize(&mut group_secrets_bytes.as_slice())?
            .config(ciphersuite, mls_version);
        let joiner_secret = group_secrets.joiner_secret;

        // Create key schedule
        let mut key_schedule = KeySchedule::init(
            ciphersuite,
            backend,
            joiner_secret,
            psk_output(
                ciphersuite,
                backend,
                psk_fetcher_option,
                &group_secrets.psks,
            )?,
        )?;

        // Derive welcome key & nonce from the key schedule
        let (welcome_key, welcome_nonce) = key_schedule
            .welcome(backend)?
            .derive_welcome_key_nonce(backend)?;

        let group_info_bytes = welcome_key
            .aead_open(backend, welcome.encrypted_group_info(), &[], &welcome_nonce)
            .map_err(|_| WelcomeError::GroupInfoDecryptionFailure)?;
        let group_info = GroupInfo::tls_deserialize(&mut group_info_bytes.as_slice())?;

        // Make sure that we can support the required capabilities in the group info.
        let group_context_extensions = group_info.group_context_extensions();
        let required_capabilities = group_context_extensions
            .iter()
            .find(|&extension| extension.extension_type() == ExtensionType::RequiredCapabilities);
        if let Some(required_capabilities) = required_capabilities {
            let required_capabilities =
                required_capabilities.as_required_capabilities_extension()?;
            check_required_capabilities_support(required_capabilities)?;
            // Also check that our key package actually supports the extensions.
            // Per spec the sender must have checked this. But you never know.
            key_package_bundle
                .key_package()
                .check_extension_support(required_capabilities.extensions())?
        }

        let path_secret_option = group_secrets.path_secret;

        // Build the ratchet tree
        // First check the extensions to see if the tree is in there.
        let mut ratchet_tree_extension = group_info
            .other_extensions()
            .iter()
            .filter(|e| e.extension_type() == ExtensionType::RatchetTree)
            .map(|e| e.as_ratchet_tree_extension().ok())
            .collect::<Vec<Option<&RatchetTreeExtension>>>();
        if ratchet_tree_extension.len() > 1 {
            // Throw an error if there is more than one ratchet tree extension.
            // This shouldn't be the case anyway, because extensions are checked
            // for uniqueness anyway when decoding them.
            // We have to see if this makes problems later as it's not something
            // required by the spec right now.
            return Err(WelcomeError::DuplicateRatchetTreeExtension);
        }

        let ratchet_tree_extension = if ratchet_tree_extension.is_empty() {
            None
        } else {
            ratchet_tree_extension
                .pop()
                .ok_or(WelcomeError::UnknownError)?
        };

        // Set nodes either from the extension or from the `nodes_option`.
        // If we got a ratchet tree extension in the welcome, we enable it for
        // this group. Note that this is not strictly necessary. But there's
        // currently no other mechanism to enable the extension.
        let (nodes, enable_ratchet_tree_extension) = match ratchet_tree_extension {
            Some(tree) => (tree.as_slice(), true),
            None => match nodes_option.as_ref() {
                Some(n) => (n.as_slice(), false),
                None => return Err(WelcomeError::MissingRatchetTree),
            },
        };

        // Commit secret is ignored when joining a group, since we already have
        // the joiner_secret.
        let (tree, _commit_secret_option) = TreeSync::from_nodes_with_secrets(
            backend,
            ciphersuite,
            nodes,
            group_info.signer_index(),
            path_secret_option,
            key_package_bundle,
        )?;

        let group_members = tree.full_leaves()?;
        let signer_key_package = group_members
            .get(&group_info.signer_index())
            .ok_or(WelcomeError::UnknownSender)?;

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
        )?;

        let serialized_group_context = group_context.tls_serialize_detached()?;
        // TODO #141: Implement PSK
        key_schedule.add_context(backend, &serialized_group_context)?;
        let epoch_secrets = key_schedule.epoch_secrets(backend, true)?;

        let (group_epoch_secrets, message_secrets) =
            epoch_secrets.split(serialized_group_context, tree.leaf_count()?);

        let confirmation_tag = message_secrets
            .confirmation_key()
            .tag(backend, group_context.confirmed_transcript_hash.as_slice())?;
        let interim_transcript_hash = update_interim_transcript_hash(
            ciphersuite,
            backend,
            &MlsPlaintextCommitAuthData::from(&confirmation_tag),
            group_context.confirmed_transcript_hash.as_slice(),
        )?;

        // Verify confirmation tag
        if &confirmation_tag != group_info.confirmation_tag() {
            log::error!("Confirmation tag mismatch");
            log_crypto!(trace, "  Got:      {:x?}", confirmation_tag);
            log_crypto!(trace, "  Expected: {:x?}", group_info.confirmation_tag());
            Err(WelcomeError::ConfirmationTagMismatch)
        } else {
            Ok(MlsGroup {
                ciphersuite,
                group_context,
                group_epoch_secrets,
                message_secrets,
                tree,
                interim_transcript_hash,
                use_ratchet_tree_extension: enable_ratchet_tree_extension,
                mls_version,
            })
        }
    }

    // Helper functions

    pub(crate) fn find_key_package_from_welcome_secrets(
        key_package: &KeyPackage,
        welcome_secrets: &[EncryptedGroupSecrets],
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Option<EncryptedGroupSecrets>, KeyPackageError> {
        for egs in welcome_secrets {
            if key_package.hash(backend)?.as_slice() == egs.key_package_hash.as_slice() {
                return Ok(Some(egs.clone()));
            }
        }
        Ok(None)
    }
}
