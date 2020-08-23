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

use crate::ciphersuite::*;
use crate::extensions::*;
use crate::framing::*;
use crate::group::mls_group::*;
use crate::group::*;
use crate::key_packages::*;
use crate::messages::*;
use crate::tree::astree::*;
use crate::utils::*;

pub fn apply_commit(
    group: &mut MlsGroup,
    mls_plaintext: MLSPlaintext,
    proposals: Vec<(Sender, Proposal)>,
    own_key_packages: Vec<(HPKEPrivateKey, KeyPackage)>,
) {
    let ciphersuite = group.get_ciphersuite();
    let mut public_queue = ProposalQueue::new();
    for (sender, proposal) in proposals {
        let queued_proposal = QueuedProposal::new(proposal, sender.as_leaf_index(), None);
        public_queue.add(queued_proposal, &ciphersuite);
    }
    //let proposal_id_list = public_queue.get_commit_lists(&ciphersuite);
    //let mut new_tree = group.tree.clone();

    let mut pending_kpbs = vec![];
    for (pk, kp) in own_key_packages {
        pending_kpbs.push(KeyPackageBundle::from_key_package(kp, pk));
    }

    let sender = mls_plaintext.sender.sender;
    let is_own_commit = mls_plaintext.sender.as_node_index() == group.tree.get_own_index();
    // TODO return an error in case of failure
    debug_assert_eq!(mls_plaintext.epoch, group.group_context.epoch);
    let (commit, confirmation) = match mls_plaintext.content.clone() {
        MLSPlaintextContentType::Commit((commit, confirmation)) => (commit, confirmation),
        _ => panic!("No Commit in MLSPlaintext"),
    };

    let mut new_tree = group.tree.clone();

    let proposal_id_list = ProposalIDList {
        updates: commit.updates.clone(),
        removes: commit.removes.clone(),
        adds: commit.adds.clone(),
    };

    let (membership_changes, _invited_members, group_removed) =
        new_tree.apply_proposals(proposal_id_list, public_queue, pending_kpbs.clone());

    // TODO save this state in the group to prevent future operations
    if group_removed {
        return;
    }

    let commit_secret = if let Some(path) = commit.path.clone() {
        let kp = path.leaf_key_package.clone();
        // TODO return an error in case of failure
        debug_assert!(kp.verify());
        debug_assert!(mls_plaintext.verify(&group.group_context, kp.get_credential()));
        if is_own_commit {
            let own_kpb = pending_kpbs
                .iter()
                .find(|&kpb| kpb.get_key_package() == &kp)
                .unwrap();
            let (commit_secret, _, _, _) = new_tree.update_own_leaf(
                group.get_identity(),
                None,
                Some(own_kpb.clone()),
                &group.group_context.serialize(),
                false,
            );
            commit_secret
        } else {
            new_tree.update_direct_path(
                sender,
                path.clone(),
                path.leaf_key_package,
                &group.group_context.serialize(),
            )
        }
    } else {
        let path_required = membership_changes.path_required();
        debug_assert!(!path_required); // TODO: error handling
        CommitSecret(zero(group.get_ciphersuite().hash_length()))
    };

    let mut new_epoch = group.group_context.epoch;
    new_epoch.increment();

    let confirmed_transcript_hash = update_confirmed_transcript_hash(
        group.get_ciphersuite(),
        &MLSPlaintextCommitContent::new(
            &group.group_context,
            mls_plaintext.sender.sender,
            commit.clone(),
        ),
        &group.interim_transcript_hash,
    );

    let new_group_context = GroupContext {
        group_id: group.group_context.group_id.clone(),
        epoch: new_epoch,
        tree_hash: new_tree.compute_tree_hash(),
        confirmed_transcript_hash: confirmed_transcript_hash.clone(),
    };

    let mut new_epoch_secrets = group.epoch_secrets.clone();
    new_epoch_secrets.get_new_epoch_secrets(
        &ciphersuite,
        commit_secret,
        None,
        &new_group_context.serialize(),
    );

    let interim_transcript_hash =
        update_interim_transcript_hash(&ciphersuite, &mls_plaintext, &confirmed_transcript_hash);

    debug_assert_eq!(
        ConfirmationTag::new(
            &ciphersuite,
            &new_epoch_secrets.confirmation_key,
            &confirmed_transcript_hash
        ),
        confirmation
    );

    if let Some(path) = commit.path {
        if !is_own_commit {
            let parent_hash = new_tree.compute_parent_hash(NodeIndex::from(sender));

            if let Some(received_parent_hash) = path
                .leaf_key_package
                .get_extension(ExtensionType::ParentHash)
            {
                if let ExtensionPayload::ParentHash(parent_hash_inner) = received_parent_hash {
                    debug_assert_eq!(parent_hash, parent_hash_inner.parent_hash);
                } else {
                    panic!("Wrong extension type: expected ParentHashExtension");
                };
            } else {
                panic!("Commit didn't contain a ParentHash extension");
            }
        }
    }

    group.tree = new_tree;
    group.group_context = new_group_context;
    group.epoch_secrets = new_epoch_secrets;
    group.interim_transcript_hash = interim_transcript_hash;
    group.astree = ASTree::new(
        *group.get_ciphersuite(),
        &group.epoch_secrets.application_secret,
        group.tree.leaf_count(),
    );
}
