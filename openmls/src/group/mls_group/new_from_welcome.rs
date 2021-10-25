use log::debug;
use tls_codec::Deserialize;

use crate::ciphersuite::signable::Verifiable;
use crate::extensions::ExtensionType;
use crate::group::{mls_group::*, *};
use crate::key_packages::*;
use crate::messages::*;
use crate::schedule::*;
use crate::tree::{index::*, node::*, treemath, *};

impl MlsGroup {
    pub(crate) fn new_from_welcome_internal(
        welcome: Welcome,
        nodes_option: Option<Vec<Option<Node>>>,
        key_package_bundle: KeyPackageBundle,
        psk_fetcher_option: Option<PskFetcher>,
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
        ) {
            egs
        } else {
            return Err(WelcomeError::JoinerSecretNotFound);
        };
        if ciphersuite_name != key_package_bundle.key_package().ciphersuite_name() {
            let e = WelcomeError::CiphersuiteMismatch;
            debug!("new_from_welcome {:?}", e);
            return Err(e);
        }

        let group_secrets_bytes = ciphersuite.hpke_open(
            &egs.encrypted_group_secrets,
            key_package_bundle.private_key(),
            &[],
            &[],
        )?;
        let group_secrets = GroupSecrets::tls_deserialize(&mut group_secrets_bytes.as_slice())?
            .config(ciphersuite, mls_version);
        let joiner_secret = group_secrets.joiner_secret;

        // Create key schedule
        let presharedkeys = PreSharedKeys {
            psks: match group_secrets.psks {
                Some(psks) => psks.psks,
                None => vec![].into(),
            },
        };

        let mut key_schedule = KeySchedule::init(
            ciphersuite,
            joiner_secret,
            psk_output(ciphersuite, psk_fetcher_option, &presharedkeys)?,
        );

        // Derive welcome key & nonce from the key schedule
        let (welcome_key, welcome_nonce) = key_schedule.welcome()?.derive_welcome_key_nonce();

        let group_info_bytes = welcome_key
            .aead_open(welcome.encrypted_group_info(), &[], &welcome_nonce)
            .map_err(|_| WelcomeError::GroupInfoDecryptionFailure)?;
        let group_info = GroupInfo::tls_deserialize(&mut group_info_bytes.as_slice())?;
        let path_secret_option = group_secrets.path_secret;

        // Build the ratchet tree
        let (mut tree, use_ratchet_tree_extension) = Self::tree_from_extension_or_nodes(
            group_info.tree_hash(),
            nodes_option,
            group_info.extensions(),
            key_package_bundle,
        )?;

        // Verify GroupInfo signature
        let signer_node = tree.nodes[group_info.signer_index()].clone();
        let signer_key_package = signer_node
            .key_package
            .ok_or(WelcomeError::MissingKeyPackage)?;
        group_info
            .verify_no_out(signer_key_package.credential())
            .map_err(|_| WelcomeError::InvalidGroupInfoSignature)?;

        // Compute path secrets
        // TODO: #36 check if path_secret has to be optional
        if let Some(path_secret) = path_secret_option {
            let common_ancestor_index = treemath::common_ancestor_index(
                tree.own_node_index().into(),
                NodeIndex::from(group_info.signer_index()),
            );
            // We can unwrap here, because, upon closer inspection,
            // `dirpath_long` will never throw an error.
            let common_path =
                treemath::parent_direct_path(common_ancestor_index, tree.leaf_count()).unwrap();

            // Update the private tree.
            let private_tree = tree.private_tree_mut();
            // Derive path secrets and generate keypairs
            let new_public_keys =
                private_tree.continue_path_secrets(ciphersuite, path_secret, &common_path);

            // Validate public keys
            if tree
                .validate_public_keys(&new_public_keys, &common_path)
                .is_err()
            {
                return Err(WelcomeError::InvalidRatchetTree(TreeError::InvalidTree));
            }
        }

        // Compute state
        let group_context = GroupContext::new(
            group_info.group_id().clone(),
            group_info.epoch(),
            group_info.tree_hash().to_vec(),
            group_info.confirmed_transcript_hash().to_vec(),
            // TODO #186: Implement extensions
            &[],
        );
        // TODO #141: Implement PSK
        key_schedule.add_context(&group_context)?;
        let epoch_secrets = key_schedule.epoch_secrets(true)?;

        let secret_tree = epoch_secrets
            .encryption_secret()
            .create_secret_tree(tree.leaf_count());

        let confirmation_tag = epoch_secrets
            .confirmation_key()
            .tag(group_context.confirmed_transcript_hash.as_slice());
        let interim_transcript_hash = update_interim_transcript_hash(
            ciphersuite,
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
                epoch_secrets,
                secret_tree: RefCell::new(secret_tree),
                tree: RefCell::new(tree),
                interim_transcript_hash,
                use_ratchet_tree_extension,
                mls_version,
            })
        }
    }

    // Helper functions

    pub(crate) fn find_key_package_from_welcome_secrets(
        key_package: &KeyPackage,
        welcome_secrets: &[EncryptedGroupSecrets],
    ) -> Option<EncryptedGroupSecrets> {
        for egs in welcome_secrets {
            if key_package.hash().as_slice() == egs.key_package_hash.as_slice() {
                return Some(egs.clone());
            }
        }
        None
    }

    /// This is a helper function that takes an `Extension` slice and optionally
    /// a vector of nodes, as well as `KeyPackageBundle` and returns a
    /// RatchetTree, as well as an boolean indicating if the ratchet tree came
    /// from an extension. This function also verifies the `tree_hash` against
    /// the given `reference_tree_hash` and verifies the parent hashes of the
    /// newly created tree. Returns a WelcomeError if there is more than one
    /// RatchetTreeExtension or if no ratchet tree can be found.
    pub(crate) fn tree_from_extension_or_nodes(
        reference_tree_hash: &[u8],
        nodes_option: Option<Vec<Option<Node>>>,
        extensions: &[Extension],
        key_package_bundle: KeyPackageBundle,
    ) -> Result<(RatchetTree, bool), WelcomeError> {
        // First check the extensions to see if the tree is in there.
        let mut ratchet_tree_extensions = extensions
            .iter()
            .filter(|e| e.extension_type() == ExtensionType::RatchetTree)
            .collect::<Vec<&Extension>>();

        let ratchet_tree_extension = if ratchet_tree_extensions.is_empty() {
            None
        } else if ratchet_tree_extensions.len() == 1 {
            let extension = ratchet_tree_extensions
                .pop()
                // Unwrappig here is safe because we know we only have one element
                .unwrap()
                .as_ratchet_tree_extension()
                // Unwrapping here is safe, because we know the extension type already
                .unwrap()
                // We clone the nodes here upon extraction, so that we don't have to clone
                // them later when we build the tree
                .clone();
            Some(extension)
        } else {
            // Throw an error if there is more than one ratchet tree extension.
            // This shouldn't be the case anyway, because extensions are checked
            // for uniqueness anyway when decoding them.
            // We have to see if this makes problems later as it's not something
            // required by the spec right now.
            return Err(WelcomeError::DuplicateRatchetTreeExtension);
        };

        // Set nodes either from the extension or from the `nodes_option`.
        // If we got a ratchet tree extension in the welcome, we enable it for
        // this group. Note that this is not strictly necessary. But there's
        // currently no other mechanism to enable the extension.
        let (nodes, enable_ratchet_tree_extension) = match ratchet_tree_extension {
            Some(tree) => (tree.into_vector(), true),
            None => {
                if let Some(nodes) = nodes_option {
                    (nodes, false)
                } else {
                    return Err(WelcomeError::MissingRatchetTree);
                }
            }
        };
        let tree = RatchetTree::new_from_nodes_and_kpb(key_package_bundle, &nodes)?;

        // Verify tree hash
        let tree_hash = tree.tree_hash();
        if tree_hash != reference_tree_hash {
            return Err(WelcomeError::TreeHashMismatch);
        }

        // Verify parent hashes
        tree.verify_parent_hashes()?;

        Ok((tree, enable_ratchet_tree_extension))
    }
}
