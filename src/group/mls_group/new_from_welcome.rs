// maelstrom
// Copyright (C) 2020 Raphael Robert
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crate::ciphersuite::{signable::*, *};
use crate::codec::*;
use crate::group::{mls_group::*, *};
use crate::key_packages::*;
use crate::messages::*;
use crate::schedule::*;
use crate::tree::astree::*;
use crate::tree::treemath;
use crate::tree::{node::*, *};

pub fn new_from_welcome(
    welcome: Welcome,
    nodes_option: Option<Vec<Option<Node>>>,
    key_package_bundle: (HPKEPrivateKey, KeyPackage),
) -> Result<MlsGroup, WelcomeError> {
    let ciphersuite = welcome.cipher_suite;
    let (private_key, key_package) = key_package_bundle;

    // Find key_package in welcome secrets
    let egs =
        if let Some(egs) = find_key_package_from_welcome_secrets(&key_package, &welcome.secrets) {
            egs
        } else {
            return Err(WelcomeError::JoinerSecretNotFound);
        };
    if &ciphersuite != key_package.get_cipher_suite() {
        return Err(WelcomeError::CiphersuiteMismatch);
    }

    // Compute keys to decrypt GroupInfo
    let (group_info, group_secrets) = decrypt_group_info(
        &ciphersuite,
        &egs,
        &private_key,
        &welcome.encrypted_group_info,
    )?;

    // Build the ratchet tree
    // TODO: check the extensions to see if the tree is in there
    let nodes = if let Some(nodes) = nodes_option {
        nodes
    } else {
        return Err(WelcomeError::MissingRatchetTree);
    };

    let mut tree = if let Some(tree) = RatchetTree::new_from_nodes(
        ciphersuite,
        KeyPackageBundle::from_values(key_package, private_key),
        &nodes,
    ) {
        tree
    } else {
        return Err(WelcomeError::JoinerNotInTree);
    };

    // Verify tree hash
    if tree.compute_tree_hash() != &group_info.tree_hash[..] {
        return Err(WelcomeError::TreeHashMismatch);
    }

    // Verify GroupInfo signature
    let signer_node = tree.nodes[NodeIndex::from(group_info.signer_index).as_usize()].clone();
    let signer_key_package = signer_node.key_package.unwrap();
    let payload = group_info.unsigned_payload().unwrap();
    if !signer_key_package
        .get_credential()
        .verify(&payload, &group_info.signature)
    {
        return Err(WelcomeError::InvalidGroupInfoSignature);
    }

    // Verify ratchet tree
    if !RatchetTree::verify_integrity(&ciphersuite, &nodes) {
        return Err(WelcomeError::InvalidRatchetTree);
    }

    // Compute path secrets
    // TODO: check if path_secret has to be optional
    if let Some(path_secret) = group_secrets.path_secret {
        let common_ancestor = treemath::common_ancestor(
            tree.get_own_index(),
            NodeIndex::from(group_info.signer_index),
        );
        let common_path = treemath::dirpath_root(common_ancestor, tree.leaf_count());
        let (path_secrets, _commit_secret) = OwnLeaf::continue_path_secrets(
            &ciphersuite,
            &path_secret.path_secret,
            common_path.len(),
        );
        let keypairs = OwnLeaf::generate_path_keypairs(&ciphersuite, &path_secrets);
        tree.merge_keypairs(&keypairs, &common_path);

        let mut path_keypairs = PathKeypairs::new();
        path_keypairs.add(&keypairs, &common_path);
        tree.own_leaf.path_keypairs = path_keypairs;
    }

    // Compute state
    let group_context = GroupContext {
        group_id: group_info.group_id,
        epoch: group_info.epoch,
        tree_hash: tree.compute_tree_hash(),
        confirmed_transcript_hash: group_info.confirmed_transcript_hash,
    };
    let epoch_secrets =
        EpochSecrets::derive_epoch_secrets(&ciphersuite, &group_secrets.joiner_secret, vec![]);
    let astree = ASTree::new(
        ciphersuite,
        &epoch_secrets.application_secret,
        tree.leaf_count(),
    );

    // Verify confirmation tag
    if ConfirmationTag::new(
        &ciphersuite,
        &epoch_secrets.confirmation_key,
        &group_context.confirmed_transcript_hash,
    ) != ConfirmationTag(group_info.confirmation_tag)
    {
        Err(WelcomeError::ConfirmationTagMismatch)
    } else {
        Ok(MlsGroup {
            ciphersuite: welcome.cipher_suite,
            group_context,
            generation: 0,
            epoch_secrets,
            astree,
            tree,
            interim_transcript_hash: group_info.interim_transcript_hash,
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
        match ciphersuite.aead_open(encrypted_group_info, &[], &welcome_key, &welcome_nonce) {
            Ok(bytes) => bytes,
            Err(_) => return Err(WelcomeError::GroupInfoDecryptionFailure),
        };
    Ok((
        GroupInfo::decode_detached(&group_info_bytes).unwrap(),
        group_secrets,
    ))
}
