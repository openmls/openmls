use log::{debug, error};

use crate::ciphersuite::{signable::*, *};
use crate::codec::*;
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
    ) -> Result<Self, WelcomeError> {
        let ciphersuite = welcome.ciphersuite();

        // Find key_package in welcome secrets
        let egs = if let Some(egs) = Self::find_key_package_from_welcome_secrets(
            key_package_bundle.key_package(),
            welcome.secrets(),
        ) {
            egs
        } else {
            return Err(WelcomeError::JoinerSecretNotFound);
        };
        if ciphersuite.name() != key_package_bundle.key_package().ciphersuite_name() {
            let e = WelcomeError::CiphersuiteMismatch;
            debug!("new_from_welcome {:?}", e);
            return Err(e);
        }

        // Compute keys to decrypt GroupInfo
        let (mut group_info, intermediate_secret, path_secret_option) = Self::decrypt_group_info(
            &ciphersuite,
            &egs,
            key_package_bundle.private_key(),
            welcome.encrypted_group_info(),
        )?;

        // Build the ratchet tree
        // First check the extensions to see if the tree is in there.
        let ratchet_tree_ext_index = group_info
            .extensions()
            .iter()
            .position(|e| e.extension_type() == ExtensionType::RatchetTree);
        let ratchet_tree_extension = if let Some(i) = ratchet_tree_ext_index {
            let extension = group_info.extensions_mut().remove(i);
            // Throw an error if we there is another ratchet tree extension.
            // We have to see if this makes problems later as it's not something
            // required by the spec right now.
            if group_info
                .extensions()
                .iter()
                .any(|e| e.extension_type() == ExtensionType::RatchetTree)
            {
                return Err(WelcomeError::DuplicateRatchetTreeExtension);
            }
            match extension.as_ratchet_tree_extension() {
                Ok(e) => {
                    let ext = Some(e.clone());
                    // Put the extension back into the GroupInfo, so the
                    // signature verifies.
                    group_info.extensions_mut().insert(i, extension);
                    ext
                }
                Err(e) => {
                    error!("Library error retrieving ratchet tree extension ({:?}", e);
                    None
                }
            }
        } else {
            None
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

        let mut tree = RatchetTree::new_from_nodes(ciphersuite, key_package_bundle, &nodes)?;

        // Verify tree hash
        let tree_hash = tree.tree_hash();
        if tree_hash != group_info.tree_hash() {
            return Err(WelcomeError::TreeHashMismatch);
        }

        // Verify parent hashes
        if !tree.verify_parent_hashes() {
            return Err(WelcomeError::InvalidRatchetTree(TreeError::InvalidTree));
        }

        // Verify GroupInfo signature
        let signer_node = tree.nodes[group_info.signer_index()].clone();
        let signer_key_package = signer_node.key_package.unwrap();
        let payload = group_info.unsigned_payload().unwrap();
        if !signer_key_package
            .credential()
            .verify(&payload, group_info.signature())
        {
            return Err(WelcomeError::InvalidGroupInfoSignature);
        }

        // Compute path secrets
        // TODO: #36 check if path_secret has to be optional
        if let Some(path_secret) = path_secret_option {
            let common_ancestor_index = treemath::common_ancestor_index(
                tree.own_node_index().into(),
                NodeIndex::from(group_info.signer_index()),
            );
            let common_path = treemath::direct_path_root(common_ancestor_index, tree.leaf_count())
                .expect("new_from_welcome_internal: TreeMath error when computing direct path.");

            // Update the private tree.
            let private_tree = tree.private_tree_mut();
            // Derive path secrets and generate keypairs
            let new_public_keys = private_tree.continue_path_secrets(
                &ciphersuite,
                path_secret.path_secret,
                &common_path,
            );

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
            tree_hash,
            group_info.confirmed_transcript_hash().to_vec(),
        )?;
        // TODO #141: Implement PSK
        let epoch_secret = EpochSecret::new(ciphersuite, intermediate_secret, &group_context);
        let (epoch_secrets, init_secret, encryption_secret) =
            EpochSecrets::derive_epoch_secrets(&ciphersuite, epoch_secret);
        let secret_tree = encryption_secret.create_secret_tree(tree.leaf_count());

        let confirmation_tag = ConfirmationTag::new(
            &ciphersuite,
            &epoch_secrets.confirmation_key(),
            &group_context.confirmed_transcript_hash,
        );
        let interim_transcript_hash = update_interim_transcript_hash(
            &ciphersuite,
            &MLSPlaintextCommitAuthData::from(&confirmation_tag),
            &group_context.confirmed_transcript_hash,
        )?;

        // Verify confirmation tag
        if confirmation_tag != group_info.confirmation_tag() {
            Err(WelcomeError::ConfirmationTagMismatch)
        } else {
            Ok(MlsGroup {
                ciphersuite,
                group_context,
                epoch_secrets,
                init_secret,
                secret_tree: RefCell::new(secret_tree),
                tree: RefCell::new(tree),
                interim_transcript_hash,
                add_ratchet_tree_extension: enable_ratchet_tree_extension,
            })
        }
    }

    // Helper functions

    fn find_key_package_from_welcome_secrets(
        key_package: &KeyPackage,
        welcome_secrets: &[EncryptedGroupSecrets],
    ) -> Option<EncryptedGroupSecrets> {
        for egs in welcome_secrets {
            if key_package.hash() == egs.key_package_hash {
                return Some(egs.clone());
            }
        }
        None
    }

    fn decrypt_group_info(
        ciphersuite: &Ciphersuite,
        encrypted_group_secrets: &EncryptedGroupSecrets,
        private_key: &HPKEPrivateKey,
        encrypted_group_info: &[u8],
    ) -> Result<(GroupInfo, IntermediateSecret, Option<PathSecret>), WelcomeError> {
        let group_secrets_bytes = ciphersuite.hpke_open(
            &encrypted_group_secrets.encrypted_group_secrets,
            &private_key,
            &[],
            &[],
        )?;
        let group_secrets = GroupSecrets::decode_detached(&group_secrets_bytes)?;
        let joiner_secret = group_secrets.joiner_secret;
        // TODO #141: Implement PSK
        let intermediate_secret = IntermediateSecret::new(ciphersuite, joiner_secret, None);
        let welcome_secret = WelcomeSecret::new(ciphersuite, &intermediate_secret);
        let (welcome_key, welcome_nonce) = welcome_secret.derive_welcome_key_nonce(ciphersuite);
        let group_info_bytes =
            match welcome_key.aead_open(encrypted_group_info, &[], &welcome_nonce) {
                Ok(bytes) => bytes,
                Err(_) => return Err(WelcomeError::GroupInfoDecryptionFailure),
            };
        Ok((
            GroupInfo::decode_detached(&group_info_bytes)?,
            intermediate_secret,
            group_secrets.path_secret,
        ))
    }
}
