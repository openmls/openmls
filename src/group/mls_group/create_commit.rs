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
use crate::extensions::*;
use crate::framing::*;
use crate::group::mls_group::*;
use crate::group::*;
use crate::messages::*;
use crate::tree::treemath;
use crate::utils::*;
use rayon::prelude::*;

impl MlsGroup {
    pub(crate) fn create_commit_internal(
        &self,
        aad: &[u8],
        signature_key: &SignaturePrivateKey,
        proposals: Vec<MLSPlaintext>,
        force_self_update: bool,
    ) -> CreateCommitResult {
        let ciphersuite = self.get_ciphersuite();
        let mut contains_own_updates = false;
        // Organize proposals
        let mut proposal_queue = ProposalQueue::new();
        for mls_plaintext in proposals {
            let queued_proposal = QueuedProposal::new(mls_plaintext, None);
            if queued_proposal.sender.as_leaf_index() == self.get_sender_index()
                && queued_proposal.proposal.is_update()
            {
                contains_own_updates = true;
            } else {
                proposal_queue.add(queued_proposal, &ciphersuite);
            }
        }

        // TODO Dedup proposals
        let proposal_id_list = proposal_queue.get_commit_lists(&ciphersuite);

        let sender_index = self.get_sender_index();
        let mut provisional_tree = self.tree.borrow_mut();

        // Apply proposals to tree
        let (membership_changes, invited_members, group_removed) =
            provisional_tree.apply_proposals(&proposal_id_list, proposal_queue, &[]);
        if group_removed {
            return Err(CreateCommitError::CannotRemoveSelf);
        }
        // Determine if Commit needs path field
        let path_required =
            membership_changes.path_required() || contains_own_updates || force_self_update;

        let (commit_secret, path, path_secrets_option) = if path_required {
            // If path is needed, compute path values
            let (commit_secret, path_option, path_secrets) =
                provisional_tree.refresh_own_leaf(signature_key, &self.group_context.serialize());
            (commit_secret, path_option, path_secrets)
        } else {
            // If path is not needed, return empty commit secret
            let commit_secret = CommitSecret(zero(self.get_ciphersuite().hash_length()));
            (commit_secret, None, None)
        };
        // Create commit message
        let commit = Commit {
            updates: proposal_id_list.updates,
            removes: proposal_id_list.removes,
            adds: proposal_id_list.adds,
            path,
        };
        // Create provisional group state
        let mut provisional_epoch = self.group_context.epoch;
        provisional_epoch.increment();
        let confirmed_transcript_hash = update_confirmed_transcript_hash(
            self.get_ciphersuite(),
            &MLSPlaintextCommitContent::new(&self.group_context, sender_index, commit.clone()),
            &self.interim_transcript_hash,
        );
        let provisional_group_context = GroupContext {
            group_id: self.group_context.group_id.clone(),
            epoch: provisional_epoch,
            tree_hash: provisional_tree.compute_tree_hash(),
            confirmed_transcript_hash: confirmed_transcript_hash.clone(),
        };
        let mut provisional_epoch_secrets = self.epoch_secrets.clone();
        let epoch_secret = provisional_epoch_secrets.get_new_epoch_secrets(
            &ciphersuite,
            commit_secret,
            None,
            &provisional_group_context,
        );
        // Compute confirmation tag
        let confirmation_tag = ConfirmationTag::new(
            &ciphersuite,
            &provisional_epoch_secrets.confirmation_key,
            &confirmed_transcript_hash,
        );
        // Create MLSPlaintext
        let content = MLSPlaintextContentType::Commit((commit, confirmation_tag.clone()));
        let mls_plaintext = MLSPlaintext::new(
            ciphersuite,
            sender_index,
            aad,
            content,
            signature_key,
            &self.get_context(),
        );
        // Check if new members were added an create welcome message
        // TODO: Add support for extensions
        if !membership_changes.adds.is_empty() {
            let public_tree = RatchetTreeExtension::new(provisional_tree.public_key_tree());
            let ratchet_tree_extension = public_tree.to_extension();
            let tree_hash = ciphersuite.hash(&ratchet_tree_extension.extension_data);
            // Create GroupInfo object
            let interim_transcript_hash = update_interim_transcript_hash(
                &ciphersuite,
                &mls_plaintext,
                &confirmed_transcript_hash,
            );
            let mut group_info = GroupInfo {
                group_id: provisional_group_context.group_id.clone(),
                epoch: provisional_group_context.epoch,
                tree_hash,
                confirmed_transcript_hash,
                interim_transcript_hash,
                extensions: vec![],
                confirmation_tag: confirmation_tag.as_slice(),
                signer_index: sender_index,
                signature: Signature::new_empty(),
            };
            group_info.signature = group_info.sign(ciphersuite, signature_key);
            // Encrypt GroupInfo object
            let (welcome_key, welcome_nonce) =
                compute_welcome_key_nonce(ciphersuite, &epoch_secret);
            let encrypted_group_info = ciphersuite
                .aead_seal(
                    &group_info.encode_detached().unwrap(),
                    &[],
                    &welcome_key,
                    &welcome_nonce,
                )
                .unwrap();
            // Create group secrets
            let mut plaintext_secrets = vec![];
            for (index, add_proposal) in invited_members.clone() {
                let key_package = add_proposal.key_package;
                let key_package_hash = ciphersuite.hash(&key_package.encode_detached().unwrap());
                let path_secret = if path_required {
                    let common_ancestor_index = treemath::common_ancestor_index(
                        index,
                        provisional_tree.get_own_node_index(),
                    );
                    let dirpath = treemath::direct_path_root(
                        provisional_tree.get_own_node_index(),
                        provisional_tree.leaf_count(),
                    );
                    let position = dirpath
                        .iter()
                        .position(|&x| x == common_ancestor_index)
                        .unwrap();
                    let path_secrets = path_secrets_option.clone().unwrap();
                    let path_secret = path_secrets[position].clone();
                    Some(PathSecret { path_secret })
                } else {
                    None
                };
                let group_secrets = GroupSecrets {
                    joiner_secret: epoch_secret.clone(),
                    path_secret,
                };
                let group_secrets_bytes = group_secrets.encode_detached().unwrap();
                plaintext_secrets.push((
                    key_package.get_hpke_init_key().clone(),
                    group_secrets_bytes,
                    key_package_hash,
                ));
            }
            // Encrypt group secrets
            let secrets = plaintext_secrets
                .par_iter()
                .map(|(init_key, bytes, key_package_hash)| {
                    let encrypted_group_secrets = ciphersuite.hpke_seal(init_key, &[], &[], bytes);
                    EncryptedGroupSecrets {
                        key_package_hash: key_package_hash.clone(),
                        encrypted_group_secrets,
                    }
                })
                .collect();
            // Create welcome message
            let welcome = Welcome {
                version: ProtocolVersion::Mls10,
                cipher_suite: self.ciphersuite,
                secrets,
                encrypted_group_info,
            };
            Ok((mls_plaintext, Some(welcome)))
        } else {
            Ok((mls_plaintext, None))
        }
    }
}
