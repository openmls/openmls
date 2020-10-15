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

use crate::extensions::*;
use crate::framing::*;
use crate::group::mls_group::*;
use crate::group::*;
use crate::key_packages::*;
use crate::messages::*;
use crate::utils::*;

impl MlsGroup {
    pub(crate) fn apply_commit_internal(
        &mut self,
        mls_plaintext: MLSPlaintext,
        proposals: Vec<MLSPlaintext>,
        own_key_packages: Vec<KeyPackageBundle>,
    ) -> Result<(), ApplyCommitError> {
        let ciphersuite = self.get_ciphersuite();

        // Verify epoch
        if mls_plaintext.epoch != self.group_context.epoch {
            return Err(ApplyCommitError::EpochMismatch);
        }

        // Create KeyPackageBundles
        let mut pending_kpbs = vec![];
        for kpb in own_key_packages {
            let (pk, kp) = (kpb.private_key, kpb.key_package);
            pending_kpbs.push(KeyPackageBundle::from_values(kp, pk));
        }

        // Extract Commit from MLSPlaintext
        let (commit, confirmation_tag) = match &mls_plaintext.content {
            MLSPlaintextContentType::Commit((commit, confirmation_tag)) => {
                (commit, confirmation_tag)
            }
            _ => return Err(ApplyCommitError::WrongPlaintextContentType),
        };

        // Organize proposals
        let proposal_id_list = ProposalIDList {
            updates: commit.updates.clone(),
            removes: commit.removes.clone(),
            adds: commit.adds.clone(),
        };
        let mut proposal_queue = ProposalQueue::new();
        for mls_plaintext in proposals {
            let queued_proposal = QueuedProposal::new(mls_plaintext, None);
            proposal_queue.add(queued_proposal, &ciphersuite);
        }

        // Create provisional tree and apply proposals
        let mut provisional_tree = self.tree.borrow_mut();
        let (membership_changes, _invited_members, group_removed) =
            provisional_tree.apply_proposals(&proposal_id_list, proposal_queue, &pending_kpbs);

        // Check if we were removed from the group
        if group_removed {
            return Err(ApplyCommitError::SelfRemoved);
        }

        // Determine if Commit is own Commit
        let sender = mls_plaintext.sender.sender;
        let is_own_commit =
            mls_plaintext.sender.as_node_index() == provisional_tree.get_own_node_index(); // XXX: correct?

        // Determine if Commit has a path
        let commit_secret = if let Some(path) = commit.path.clone() {
            // Verify KeyPackage and MLSPlaintext signature
            let kp = &path.leaf_key_package;
            if !kp.verify() {
                return Err(ApplyCommitError::PathKeyPackageVerificationFailure);
            }
            let serialized_context = self.group_context.encode_detached().unwrap();
            if !mls_plaintext.verify(Some(serialized_context), kp.get_credential()) {
                return Err(ApplyCommitError::PlaintextSignatureFailure);
            }
            if is_own_commit {
                // Find the right KeyPackageBundle among the pending bundles
                let own_kpb = pending_kpbs
                    .iter()
                    .find(|&kpb| kpb.get_key_package() == kp)
                    .unwrap()
                    .clone();
                provisional_tree
                    .replace_private_tree(own_kpb, &self.group_context.serialize())
                    .unwrap()
            } else {
                provisional_tree
                    .update_path(sender, &path, &self.group_context.serialize())
                    .unwrap()
            }
        } else {
            if membership_changes.path_required() {
                return Err(ApplyCommitError::RequiredPathNotFound);
            }
            CommitSecret(zero(ciphersuite.hash_length()))
        };

        // Create provisional group state
        let mut provisional_epoch = self.group_context.epoch;
        provisional_epoch.increment();

        let confirmed_transcript_hash = update_confirmed_transcript_hash(
            ciphersuite,
            &MLSPlaintextCommitContent::new(&self.group_context, sender, commit.clone()),
            &self.interim_transcript_hash,
        );

        let provisional_group_context = GroupContext {
            group_id: self.group_context.group_id.clone(),
            epoch: provisional_epoch,
            tree_hash: provisional_tree.compute_tree_hash(),
            confirmed_transcript_hash: confirmed_transcript_hash.clone(),
        };

        let mut provisional_epoch_secrets = self.epoch_secrets.clone();
        provisional_epoch_secrets.get_new_epoch_secrets(
            &ciphersuite,
            commit_secret,
            None,
            &provisional_group_context,
        );

        let interim_transcript_hash = update_interim_transcript_hash(
            &ciphersuite,
            &mls_plaintext,
            &confirmed_transcript_hash,
        );

        // Verify confirmation tag
        if &ConfirmationTag::new(
            &ciphersuite,
            &provisional_epoch_secrets.confirmation_key,
            &confirmed_transcript_hash,
        ) != confirmation_tag
        {
            return Err(ApplyCommitError::ConfirmationTagMismatch);
        }

        // Verify KeyPackage extensions
        if let Some(path) = &commit.path {
            if !is_own_commit {
                let parent_hash = provisional_tree.compute_parent_hash(NodeIndex::from(sender));
                if let Some(received_parent_hash) = path
                    .leaf_key_package
                    .get_extension(ExtensionType::ParentHash)
                {
                    let parent_hash_extension =
                        received_parent_hash.to_parent_hash_extension_ref()?;
                    if parent_hash != parent_hash_extension.get_parent_hash_ref() {
                        return Err(ApplyCommitError::ParentHashMismatch);
                    }
                } else {
                    return Err(ApplyCommitError::NoParentHashExtension);
                }
            }
        }

        // Apply provisional tree and state to group
        self.group_context = provisional_group_context;
        self.epoch_secrets = provisional_epoch_secrets;
        self.interim_transcript_hash = interim_transcript_hash;
        self.secret_tree = RefCell::new(SecretTree::new(
            &self.epoch_secrets.encryption_secret,
            provisional_tree.leaf_count(),
        ));
        Ok(())
    }
}
