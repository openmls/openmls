use crate::extensions::*;
use crate::framing::*;
use crate::group::mls_group::*;
use crate::group::*;
use crate::key_packages::*;
use crate::messages::*;
use crate::tree::private_tree::CommitSecret;

impl MlsGroup {
    pub(crate) fn apply_commit_internal(
        &mut self,
        mls_plaintext: &MLSPlaintext,
        proposals_by_reference: &[&MLSPlaintext],
        own_key_packages: &[KeyPackageBundle],
    ) -> Result<(), ApplyCommitError> {
        let ciphersuite = self.ciphersuite();

        // Verify epoch
        if mls_plaintext.epoch() != &self.group_context.epoch {
            return Err(ApplyCommitError::EpochMismatch);
        }

        // Extract Commit from MLSPlaintext
        let (commit, received_confirmation_tag) = match &mls_plaintext.content {
            MLSPlaintextContentType::Commit((commit, confirmation_tag)) => {
                (commit, confirmation_tag)
            }
            _ => return Err(ApplyCommitError::WrongPlaintextContentType),
        };

        // Convert proposals by reference into a queue
        let proposals_by_ref_queue =
            ProposalQueue::from_proposals_by_reference(ciphersuite, proposals_by_reference);

        // Build a queue with all proposals from the Commit and check that we have all
        // of the proposals by reference locally
        let proposal_queue = match ProposalQueue::from_committed_proposals(
            ciphersuite,
            &commit.proposals,
            &proposals_by_ref_queue,
            mls_plaintext.sender,
        ) {
            Ok(proposal_queue) => proposal_queue,
            Err(_) => return Err(ApplyCommitError::MissingProposal),
        };

        // Create provisional tree and apply proposals
        let mut provisional_tree = self.tree.borrow_mut();
        let apply_proposals_values =
            match provisional_tree.apply_proposals(proposal_queue, own_key_packages) {
                Ok(res) => res,
                Err(_) => return Err(ApplyCommitError::OwnKeyNotFound),
            };

        // Check if we were removed from the group
        if apply_proposals_values.self_removed {
            return Err(ApplyCommitError::SelfRemoved);
        }

        // Determine if Commit is own Commit
        let sender = mls_plaintext.sender.sender;
        let is_own_commit =
            mls_plaintext.sender.to_node_index() == provisional_tree.own_node_index(); // XXX: correct?

        let zero_commit_secret = CommitSecret::zero_secret(ciphersuite);
        // Determine if Commit has a path
        let commit_secret = if let Some(path) = commit.path.clone() {
            // Verify KeyPackage and MLSPlaintext signature
            let kp = &path.leaf_key_package;
            if kp.verify().is_err() {
                return Err(ApplyCommitError::PathKeyPackageVerificationFailure);
            }
            let serialized_context = self.group_context.encode_detached().unwrap();
            if !mls_plaintext.verify(Some(serialized_context.clone()), kp.credential()) {
                return Err(ApplyCommitError::PlaintextSignatureFailure);
            }
            if is_own_commit {
                // Find the right KeyPackageBundle among the pending bundles and
                // clone out the one that we need.
                let own_kpb = match own_key_packages.iter().find(|kpb| kpb.key_package() == kp) {
                    Some(kpb) => kpb,
                    None => return Err(ApplyCommitError::MissingOwnKeyPackage),
                };
                provisional_tree.replace_private_tree(own_kpb, &serialized_context)
            } else {
                // Collect the new leaves' indexes so we can filter them out in the resolution
                // later.
                provisional_tree
                    .update_path(
                        sender,
                        &path,
                        &serialized_context,
                        apply_proposals_values.exclusion_list(),
                    )
                    .unwrap()
            }
        } else {
            if apply_proposals_values.path_required {
                return Err(ApplyCommitError::RequiredPathNotFound);
            }
            &zero_commit_secret
        };

        // Create provisional group state
        let mut provisional_epoch = self.group_context.epoch;
        provisional_epoch.increment();

        let confirmed_transcript_hash = update_confirmed_transcript_hash(
            ciphersuite,
            &MLSPlaintextCommitContent::new(&self.group_context, sender, commit.clone()),
            &self.interim_transcript_hash,
        );

        let joiner_secret = JoinerSecret::from_commit_and_epoch_secret(
            ciphersuite,
            Some(commit_secret),
            self.init_secret.clone(),
        );
        let member_secret =
            MemberSecret::from_joiner_secret_and_psk(ciphersuite, joiner_secret, None);

        let provisional_group_context = GroupContext {
            group_id: self.group_context.group_id.clone(),
            epoch: provisional_epoch,
            tree_hash: provisional_tree.compute_tree_hash(),
            confirmed_transcript_hash: confirmed_transcript_hash.clone(),
        };
        let (provisional_epoch_secrets, provisional_init_secret, encryption_secret) =
            EpochSecrets::derive_epoch_secrets(
                ciphersuite,
                member_secret,
                &provisional_group_context,
            );

        let interim_transcript_hash = update_interim_transcript_hash(
            &ciphersuite,
            &MLSPlaintextCommitAuthData::from(mls_plaintext),
            &confirmed_transcript_hash,
        );

        // Verify confirmation tag
        let own_confirmation_tag = ConfirmationTag::new(
            &ciphersuite,
            &provisional_epoch_secrets.confirmation_key(),
            &confirmed_transcript_hash,
        );
        if &own_confirmation_tag != received_confirmation_tag {
            return Err(ApplyCommitError::ConfirmationTagMismatch);
        }

        // Verify KeyPackage extensions
        if let Some(path) = &commit.path {
            if !is_own_commit {
                let parent_hash = provisional_tree.compute_parent_hash(NodeIndex::from(sender));
                if let Some(received_parent_hash) = path
                    .leaf_key_package
                    .extension_with_type(ExtensionType::ParentHash)
                {
                    let parent_hash_extension =
                        match received_parent_hash.to_parent_hash_extension() {
                            Ok(phe) => phe,
                            Err(_) => return Err(ApplyCommitError::NoParentHashExtension),
                        };
                    if parent_hash != parent_hash_extension.parent_hash() {
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
        self.init_secret = provisional_init_secret;
        // Create a secret_tree, consuming the `encryption_secret` in the
        // process.
        self.secret_tree =
            RefCell::new(encryption_secret.create_secret_tree(provisional_tree.leaf_count()));
        Ok(())
    }
}
