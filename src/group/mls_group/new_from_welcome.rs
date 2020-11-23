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
            key_package_bundle.get_key_package(),
            welcome.get_secrets_ref(),
        ) {
            egs
        } else {
            return Err(WelcomeError::JoinerSecretNotFound);
        };
        if ciphersuite.name() != key_package_bundle.get_key_package().cipher_suite().name() {
            let e = WelcomeError::CiphersuiteMismatch;
            debug!("new_from_welcome {:?}", e);
            return Err(e);
        }

        // Compute keys to decrypt GroupInfo
        let (mut group_info, group_secrets) = Self::decrypt_group_info(
            &ciphersuite,
            &egs,
            key_package_bundle.get_private_key_ref(),
            welcome.get_encrypted_group_info_ref(),
        )?;

        // Build the ratchet tree
        // First check the extensions to see if the tree is in there.
        let ratchet_tree_ext_index = group_info
            .extensions()
            .iter()
            .position(|e| e.get_type() == ExtensionType::RatchetTree);
        let ratchet_tree_extension = if let Some(i) = ratchet_tree_ext_index {
            let extension = group_info.extensions_mut().remove(i);
            // Throw an error if we there is another ratchet tree extension.
            // We have to see if this makes problems later as it's not something
            // required by the spec right now.
            if group_info
                .extensions()
                .iter()
                .any(|e| e.get_type() == ExtensionType::RatchetTree)
            {
                return Err(WelcomeError::DuplicateRatchetTreeExtension);
            }
            match extension.to_ratchet_tree_extension_ref() {
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
        let nodes = match ratchet_tree_extension {
            Some(tree) => tree.into_vector(),
            None => {
                if let Some(nodes) = nodes_option {
                    nodes
                } else {
                    return Err(WelcomeError::MissingRatchetTree);
                }
            }
        };

        let mut tree = RatchetTree::new_from_nodes(ciphersuite, key_package_bundle, &nodes)?;

        // Verify tree hash
        if tree.compute_tree_hash() != group_info.tree_hash() {
            return Err(WelcomeError::TreeHashMismatch);
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

        // Verify ratchet tree
        // TODO: #35 Why does this get the nodes? Shouldn't `new_from_nodes` consume the
        // nodes?
        if !RatchetTree::verify_integrity(&ciphersuite, &nodes) {
            return Err(WelcomeError::InvalidRatchetTree);
        }

        // Compute path secrets
        // TODO: #36 check if path_secret has to be optional
        if let Some(path_secret) = group_secrets.path_secret {
            let common_ancestor_index = treemath::common_ancestor_index(
                tree.get_own_node_index(),
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
                return Err(WelcomeError::InvalidRatchetTree);
            }
        }

        // Compute state
        let group_context = GroupContext {
            group_id: group_info.group_id().clone(),
            epoch: group_info.epoch(),
            tree_hash: tree.compute_tree_hash(),
            confirmed_transcript_hash: group_info.confirmed_transcript_hash().to_vec(),
        };
        let mut epoch_secrets = EpochSecrets::derive_epoch_secrets(
            &ciphersuite,
            &group_secrets.joiner_secret,
            Secret::new_empty_secret(),
        );
        let secret_tree = epoch_secrets.create_secret_tree(tree.leaf_count()).unwrap();

        let confirmation_tag = ConfirmationTag::new(
            &ciphersuite,
            &epoch_secrets.confirmation_key(),
            &group_context.confirmed_transcript_hash,
        );
        let interim_transcript_hash = update_interim_transcript_hash(
            &ciphersuite,
            &MLSPlaintextCommitAuthData::from(&confirmation_tag),
            &group_context.confirmed_transcript_hash,
        );

        // Verify confirmation tag
        if confirmation_tag.0 != group_info.confirmation_tag() {
            Err(WelcomeError::ConfirmationTagMismatch)
        } else {
            Ok(MlsGroup {
                ciphersuite,
                group_context,
                epoch_secrets,
                secret_tree: RefCell::new(secret_tree),
                tree: RefCell::new(tree),
                interim_transcript_hash,
                add_ratchet_tree_extension: false,
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
    ) -> Result<(GroupInfo, GroupSecrets), WelcomeError> {
        let group_secrets_bytes = ciphersuite.hpke_open(
            &encrypted_group_secrets.encrypted_group_secrets,
            &private_key,
            &[],
            &[],
        );
        let group_secrets = GroupSecrets::decode(&mut Cursor::new(&group_secrets_bytes)).unwrap();
        let (welcome_key, welcome_nonce) =
            compute_welcome_key_nonce(ciphersuite, &group_secrets.joiner_secret);
        let group_info_bytes =
            match welcome_key.aead_open(encrypted_group_info, &[], &welcome_nonce) {
                Ok(bytes) => bytes,
                Err(_) => return Err(WelcomeError::GroupInfoDecryptionFailure),
            };
        Ok((
            GroupInfo::from_bytes(&group_info_bytes).unwrap(),
            group_secrets,
        ))
    }
}
