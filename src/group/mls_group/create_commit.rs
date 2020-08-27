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
use crate::key_packages::*;
use crate::messages::*;
use crate::tree::treemath;
use crate::utils::*;
use rayon::prelude::*;

pub fn create_commit(
    group: &MlsGroup,
    aad: &[u8],
    signature_key: &SignaturePrivateKey,
    key_package_bundle: KeyPackageBundle,
    proposals: Vec<(Sender, Proposal)>,
    own_key_packages: Vec<(HPKEPrivateKey, KeyPackage)>,
    force_group_update: bool,
) -> (MLSPlaintext, Option<Welcome>, Option<KeyPackageBundle>) {
    let ciphersuite = group.get_ciphersuite();

    // Create KeyPackageBundles
    let mut pending_kpbs = vec![];
    for (pk, kp) in own_key_packages {
        pending_kpbs.push(KeyPackageBundle::from_key_package(kp, pk));
    }

    // Organize proposals
    let mut proposal_queue = ProposalQueue::new();
    for (sender, proposal) in proposals {
        let queued_proposal = QueuedProposal::new(proposal, sender.as_leaf_index(), None);
        proposal_queue.add(queued_proposal, &ciphersuite);
    }

    // TODO Dedup proposals

    let proposal_id_list = proposal_queue.get_commit_lists(&ciphersuite);
    let mut provisional_tree = group.tree.clone();

    let (membership_changes, invited_members, _group_removed) =
        provisional_tree.apply_proposals(proposal_id_list.clone(), proposal_queue, pending_kpbs);

    let path_required = membership_changes.path_required() || force_group_update;

    let (path, path_secrets_option, kpb_option, commit_secret) = if path_required {
        let (commit_secret, kpb, path, path_secrets) = provisional_tree.update_own_leaf(
            Some(signature_key),
            key_package_bundle,
            &group.group_context.serialize(),
            true,
        );
        (path, path_secrets, Some(kpb), commit_secret)
    } else {
        let commit_secret = CommitSecret(zero(group.get_ciphersuite().hash_length()));
        (None, None, None, commit_secret)
    };

    let commit = Commit {
        updates: proposal_id_list.updates,
        removes: proposal_id_list.removes,
        adds: proposal_id_list.adds,
        path,
    };

    let mut provisional_epoch = group.group_context.epoch;
    provisional_epoch.increment();

    let confirmed_transcript_hash = update_confirmed_transcript_hash(
        group.get_ciphersuite(),
        &MLSPlaintextCommitContent::new(
            &group.group_context,
            group.get_sender_index(),
            commit.clone(),
        ),
        &group.interim_transcript_hash,
    );

    let provisional_group_context = GroupContext {
        group_id: group.group_context.group_id.clone(),
        epoch: provisional_epoch,
        tree_hash: provisional_tree.compute_tree_hash(),
        confirmed_transcript_hash: confirmed_transcript_hash.clone(),
    };

    let mut provisional_epoch_secrets = group.epoch_secrets.clone();
    let epoch_secret = provisional_epoch_secrets.get_new_epoch_secrets(
        &ciphersuite,
        commit_secret,
        None,
        &provisional_group_context,
    );

    let confirmation_tag = ConfirmationTag::new(
        &ciphersuite,
        &provisional_epoch_secrets.confirmation_key,
        &confirmed_transcript_hash,
    );

    let content = MLSPlaintextContentType::Commit((commit, confirmation_tag.clone()));
    let mls_plaintext = MLSPlaintext::new(
        ciphersuite,
        group.get_sender_index(),
        aad,
        content,
        signature_key,
        &group.get_context(),
    );

    let interim_transcript_hash =
        update_interim_transcript_hash(&ciphersuite, &mls_plaintext, &confirmed_transcript_hash);

    if !membership_changes.adds.is_empty() {
        let public_tree = RatchetTreeExtension::new(provisional_tree.public_key_tree());
        let ratchet_tree_extension = public_tree.to_extension();
        let tree_hash = ciphersuite.hash(&ratchet_tree_extension.extension_data);

        let mut group_info = GroupInfo {
            group_id: provisional_group_context.group_id.clone(),
            epoch: provisional_group_context.epoch,
            tree_hash,
            confirmed_transcript_hash,
            interim_transcript_hash,
            extensions: vec![],
            confirmation: confirmation_tag.0,
            signer_index: group.get_sender_index(),
            signature: Signature::new_empty(),
        };
        group_info.signature = group_info.sign(ciphersuite, signature_key);

        let (welcome_key, welcome_nonce) = compute_welcome_key_nonce(ciphersuite, &epoch_secret);

        let encrypted_group_info = ciphersuite
            .aead_seal(
                &group_info.encode_detached().unwrap(),
                &[],
                &welcome_key,
                &welcome_nonce,
            )
            .unwrap();

        let mut plaintext_secrets = vec![];
        for (index, add_proposal) in invited_members.clone() {
            let key_package = add_proposal.key_package;
            let key_package_hash = ciphersuite.hash(&key_package.encode_detached().unwrap());
            let path_secret = if path_required {
                let common_ancestor = treemath::common_ancestor(index, group.tree.get_own_index());
                let dirpath = treemath::dirpath_root(
                    group.tree.get_own_index(),
                    provisional_tree.leaf_count(),
                );
                let position = dirpath.iter().position(|&x| x == common_ancestor).unwrap();
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
        let welcome = Welcome {
            version: ProtocolVersion::Mls10,
            cipher_suite: group.ciphersuite,
            secrets,
            encrypted_group_info,
        };
        (mls_plaintext, Some(welcome), kpb_option)
    } else {
        (mls_plaintext, None, kpb_option)
    }
}
