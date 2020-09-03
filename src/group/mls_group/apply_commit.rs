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
) -> Result<(), ApplyCommitError> {
    let ciphersuite = group.get_ciphersuite();

    // Verify epoch
    if mls_plaintext.epoch != group.group_context.epoch {
        return Err(ApplyCommitError::EpochMismatch);
    }

    // Create KeyPackageBundles
    let mut pending_kpbs = vec![];
    for (pk, kp) in own_key_packages {
        pending_kpbs.push(KeyPackageBundle::from_values(kp, pk));
    }

    // Extract Commit from MLSPlaintext
    let (commit, confirmation_tag) = match mls_plaintext.content.clone() {
        MLSPlaintextContentType::Commit((commit, confirmation)) => (commit, confirmation),
        _ => return Err(ApplyCommitError::WrongPlaintextContentType),
    };

    // Organize proposals
    let proposal_id_list = ProposalIDList {
        updates: commit.updates.clone(),
        removes: commit.removes.clone(),
        adds: commit.adds.clone(),
    };
    let mut proposal_queue = ProposalQueue::new();
    for (sender, proposal) in proposals {
        let queued_proposal = QueuedProposal::new(proposal, sender.as_leaf_index(), None);
        proposal_queue.add(queued_proposal, &ciphersuite);
    }

    // Create provisional tree and apply proposals
    let mut provisional_tree = group.tree.clone();
    let (membership_changes, _invited_members, group_removed) =
        provisional_tree.apply_proposals(&proposal_id_list, proposal_queue, pending_kpbs.clone());

    // Check if we were removed from the group
    if group_removed {
        return Err(ApplyCommitError::SelfRemoved);
    }

    // Determine if Commit is own Commit
    let sender = mls_plaintext.sender.sender;
    let is_own_commit = mls_plaintext.sender.as_node_index() == group.tree.get_own_index();

    // Determine if Commit has a path
    let commit_secret = if let Some(path) = commit.path.clone() {
        // Verify KeyPackage and MLSPlaintext signature
        let kp = &path.leaf_key_package;
        if !kp.verify() {
            return Err(ApplyCommitError::PathKeyPackageVerificationFailure);
        }
        if !mls_plaintext.verify(&group.group_context, kp.get_credential()) {
            return Err(ApplyCommitError::PlaintextSignatureFailure);
        }
        if is_own_commit {
            // Find the right KeyPackageBundle among the pending bundles
            let own_kpb = pending_kpbs
                .iter()
                .find(|&kpb| kpb.get_key_package() == kp)
                .unwrap();
            let (commit_secret, _, _, _) = provisional_tree.update_own_leaf(
                None,
                own_kpb.clone(),
                &group.group_context.serialize(),
                false,
            );
            commit_secret
        } else {
            provisional_tree.update_direct_path(sender, &path, &group.group_context.serialize())
        }
    } else {
        if membership_changes.path_required() {
            return Err(ApplyCommitError::RequiredPathNotFound);
        }
        CommitSecret(zero(ciphersuite.hash_length()))
    };

    // Create provisional group state
    let mut provisional_epoch = group.group_context.epoch;
    provisional_epoch.increment();

    let confirmed_transcript_hash = update_confirmed_transcript_hash(
        ciphersuite,
        &MLSPlaintextCommitContent::new(&group.group_context, sender, commit.clone()),
        &group.interim_transcript_hash,
    );

    let provisional_group_context = GroupContext {
        group_id: group.group_context.group_id.clone(),
        epoch: provisional_epoch,
        tree_hash: provisional_tree.compute_tree_hash(),
        confirmed_transcript_hash: confirmed_transcript_hash.clone(),
    };

    let mut provisional_epoch_secrets = group.epoch_secrets.clone();
    provisional_epoch_secrets.get_new_epoch_secrets(
        &ciphersuite,
        commit_secret,
        None,
        &provisional_group_context,
    );

    let interim_transcript_hash =
        update_interim_transcript_hash(&ciphersuite, &mls_plaintext, &confirmed_transcript_hash);

    // Verify confirmation tag
    if ConfirmationTag::new(
        &ciphersuite,
        &provisional_epoch_secrets.confirmation_key,
        &confirmed_transcript_hash,
    ) != confirmation_tag
    {
        return Err(ApplyCommitError::ConfirmationTagMismatch);
    }

    // Verify KeyPackage extensions
    if let Some(path) = commit.path {
        if !is_own_commit {
            let parent_hash = provisional_tree.compute_parent_hash(NodeIndex::from(sender));
            if let Some(received_parent_hash) = path
                .leaf_key_package
                .get_extension(ExtensionType::ParentHash)
            {
                if let ExtensionPayload::ParentHash(parent_hash_inner) = received_parent_hash {
                    if parent_hash != parent_hash_inner.parent_hash {
                        return Err(ApplyCommitError::ParentHashMismatch);
                    }
                }
            } else {
                return Err(ApplyCommitError::NoParentHashExtension);
            }
        }
    }

    // Apply provisional tree and state to group
    group.tree = provisional_tree;
    group.group_context = provisional_group_context;
    group.epoch_secrets = provisional_epoch_secrets;
    group.interim_transcript_hash = interim_transcript_hash;
    group.astree = ASTree::new(
        *group.get_ciphersuite(),
        &group.epoch_secrets.application_secret,
        group.tree.leaf_count(),
    );
    Ok(())
}
