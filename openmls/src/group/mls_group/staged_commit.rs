use mls_group::proposals::StagedProposal;

use super::super::errors::*;
use super::proposals::{
    ProposalStore, StagedAddProposal, StagedProposalQueue, StagedPskProposal, StagedRemoveProposal,
    StagedUpdateProposal,
};
use super::*;
use core::fmt::Debug;

impl MlsGroup {
    /// Stages a commit message.
    /// This function does the following:
    ///  - Applies the proposals covered by the commit to the tree
    ///  - Applies the (optional) update path to the tree
    ///  - Calculates the path secrets
    ///  - Initializes the key schedule for epoch rollover
    ///  - Verifies the confirmation tag/membership tag
    /// Returns a [StagedCommit] that can be inspected and later merged
    /// into the group state with [MlsGroup::merge_commit()]
    /// This function does the following checks:
    ///  - ValSem100
    ///  - ValSem101
    ///  - ValSem102
    ///  - ValSem103
    ///  - ValSem104
    ///  - ValSem105
    ///  - ValSem106
    ///  - ValSem107
    ///  - ValSem108
    ///  - ValSem109
    ///  - ValSem110
    ///  - ValSem201
    ///  - ValSem205
    pub fn stage_commit(
        &mut self,
        mls_plaintext: &MlsPlaintext,
        proposal_store: &ProposalStore,
        own_key_packages: &[KeyPackageBundle],
        psk_fetcher_option: Option<PskFetcher>,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<StagedCommit, MlsGroupError> {
        let ciphersuite = self.ciphersuite();

        // Extract the sender of the Commit message
        let sender = *mls_plaintext.sender();

        // Verify epoch
        if mls_plaintext.epoch() != self.group_context.epoch {
            log::error!(
                "Epoch mismatch. Got {:?}, expected {:?}",
                mls_plaintext.epoch(),
                self.group_context.epoch
            );
            return Err(StageCommitError::EpochMismatch.into());
        }

        // Extract Commit & Confirmation Tag from MlsPlaintext
        let commit = match mls_plaintext.content() {
            MlsPlaintextContentType::Commit(commit) => commit,
            _ => return Err(StageCommitError::WrongPlaintextContentType.into()),
        };

        let received_confirmation_tag = mls_plaintext
            .confirmation_tag()
            .ok_or(StageCommitError::ConfirmationTagMissing)?;

        // Build a queue with all proposals from the Commit and check that we have all
        // of the proposals by reference locally
        let mut proposal_queue = StagedProposalQueue::from_committed_proposals(
            ciphersuite,
            backend,
            commit.proposals.as_slice().to_vec(),
            proposal_store,
            sender,
        )
        .map_err(|_| StageCommitError::MissingProposal)?;

        // TODO #424: This won't be necessary anymore, we can just apply the proposals first
        // and add a new fake Update proposal to the queue after that
        let path_key_package = commit
            .path()
            .as_ref()
            .map(|update_path| update_path.leaf_key_package.clone());

        let sender_key_package_tuple = path_key_package
            .as_ref()
            .map(|key_package| (sender.to_leaf_index(), key_package));

        // Validate the staged proposals by doing the following checks:

        // ValSem100
        // ValSem101
        // ValSem102
        // ValSem103
        // ValSem104
        // ValSem105
        // ValSem106
        self.validate_add_proposals(&proposal_queue)?;
        // ValSem107
        // ValSem108
        self.validate_remove_proposals(&proposal_queue)?;
        // ValSem109
        // ValSem110
        self.validate_update_proposals(&proposal_queue, sender_key_package_tuple)?;

        // Create provisional tree and apply proposals
        let mut provisional_tree = self.tree.borrow_mut();
        // FIXME: #424 this is a copy of the nodes in the tree to reset the original state.
        let original_nodes = provisional_tree.nodes.clone();
        let apply_proposals_values = provisional_tree
            .apply_staged_proposals(backend, &proposal_queue, own_key_packages)
            .map_err(|_| StageCommitError::OwnKeyNotFound)?;

        // Check if we were removed from the group
        if apply_proposals_values.self_removed {
            return Ok(StagedCommit {
                staged_proposal_queue: proposal_queue,
                state: None,
            });
        }

        // Determine if Commit is own Commit
        let sender_index = sender.to_leaf_index();
        let is_own_commit = sender_index == provisional_tree.own_node_index();

        let zero_commit_secret = CommitSecret::zero_secret(ciphersuite, self.mls_version);
        // Determine if Commit has a path
        let commit_secret = if let Some(path) = commit.path.clone() {
            // Verify KeyPackage and MlsPlaintext membership tag
            // Note that the signature must have been verified already.
            // TODO #106: Support external members
            let kp = &path.leaf_key_package;
            if kp.verify(backend).is_err() {
                return Err(StageCommitError::PathKeyPackageVerificationFailure.into());
            }
            let serialized_context = self.group_context.tls_serialize_detached()?;

            if is_own_commit {
                // Find the right KeyPackageBundle among the pending bundles and
                // clone out the one that we need.
                let own_kpb = own_key_packages
                    .iter()
                    .find(|kpb| kpb.key_package() == kp)
                    .ok_or(StageCommitError::MissingOwnKeyPackage)?;

                if let Some(commit_secret) =
                    provisional_tree.replace_private_tree(backend, own_kpb, &serialized_context)
                {
                    commit_secret
                } else {
                    // We can return a library error here, because we know there was a path and thus
                    // a new commit secret must have been set.
                    return Err(MlsGroupError::LibraryError);
                }
            } else {
                // Collect the new leaves' indexes so we can filter them out in the resolution
                // later.
                provisional_tree
                    .update_path(
                        backend,
                        sender_index,
                        &path,
                        &serialized_context,
                        apply_proposals_values.exclusion_list(),
                    )
                    .map_err(|e| {
                        MlsGroupError::StageCommitError(StageCommitError::DecryptionFailure(e))
                    })?
            }
        } else {
            if apply_proposals_values.path_required {
                // ValSem201
                return Err(StageCommitError::RequiredPathNotFound.into());
            }
            &zero_commit_secret
        };

        let joiner_secret = JoinerSecret::new(
            backend,
            commit_secret,
            self.epoch_secrets
                .init_secret()
                .ok_or(StageCommitError::InitSecretNotFound)?,
        )?;

        // Create provisional group state
        let mut provisional_epoch = self.group_context.epoch;
        provisional_epoch.increment();

        let confirmed_transcript_hash = update_confirmed_transcript_hash(
            ciphersuite,
            backend,
            // It is ok to use return a library error here, because we know the MlsPlaintext contains a Commit
            &MlsPlaintextCommitContent::try_from(mls_plaintext)
                .map_err(|_| MlsGroupError::LibraryError)?,
            &self.interim_transcript_hash,
        )?;

        let provisional_group_context = GroupContext::new(
            self.group_context.group_id.clone(),
            provisional_epoch,
            provisional_tree.tree_hash(backend)?,
            confirmed_transcript_hash.clone(),
            self.group_context.extensions(),
        )?;

        // Create key schedule
        let mut key_schedule = KeySchedule::init(
            ciphersuite,
            backend,
            joiner_secret,
            psk_output(
                ciphersuite,
                backend,
                psk_fetcher_option,
                &apply_proposals_values.presharedkeys,
            )?,
        )?;

        let serialized_provisional_group_context =
            provisional_group_context.tls_serialize_detached()?;

        key_schedule.add_context(backend, &serialized_provisional_group_context)?;
        let provisional_epoch_secrets = key_schedule.epoch_secrets(backend, true)?;

        let mls_plaintext_commit_auth_data = MlsPlaintextCommitAuthData::try_from(mls_plaintext)
            .map_err(|_| {
                log::error!("Confirmation tag is missing in commit. This should be unreachable because we verified the tag before.");
                StageCommitError::ConfirmationTagMissing
            })?;

        let interim_transcript_hash = update_interim_transcript_hash(
            ciphersuite,
            backend,
            &mls_plaintext_commit_auth_data,
            &confirmed_transcript_hash,
        )?;

        // Verify confirmation tag
        // ValSem205
        let own_confirmation_tag = provisional_epoch_secrets
            .confirmation_key()
            .tag(backend, &confirmed_transcript_hash)?;
        if &own_confirmation_tag != received_confirmation_tag {
            // FIXME: reset nodes. This should get fixed with the tree rewrite.
            provisional_tree.nodes = original_nodes;
            log::error!("Confirmation tag mismatch");
            log_crypto!(trace, "  Got:      {:x?}", received_confirmation_tag);
            log_crypto!(trace, "  Expected: {:x?}", own_confirmation_tag);
            return Err(StageCommitError::ConfirmationTagMismatch.into());
        }

        // Verify KeyPackage extensions
        if let Some(path) = &commit.path {
            if !is_own_commit {
                let parent_hash = provisional_tree.set_parent_hashes(backend, sender_index)?;
                if let Some(received_parent_hash) = path
                    .leaf_key_package
                    .extension_with_type(ExtensionType::ParentHash)
                {
                    let parent_hash_extension =
                        match received_parent_hash.as_parent_hash_extension() {
                            Ok(phe) => phe,
                            Err(_) => return Err(StageCommitError::NoParentHashExtension.into()),
                        };
                    if parent_hash != parent_hash_extension.parent_hash() {
                        return Err(StageCommitError::ParentHashMismatch.into());
                    }
                } else {
                    return Err(StageCommitError::NoParentHashExtension.into());
                }
            }
        }

        // If there is a key package from the Commit's update path, add it to the proposal queue
        // TODO #424: This won't be necessary anymore, we can just apply the proposals first
        // and add a new fake Update proposal to the queue after that
        if let Some(key_package) = path_key_package {
            let proposal = Proposal::Update(UpdateProposal { key_package });
            let staged_proposal =
                StagedProposal::from_proposal_and_sender(ciphersuite, backend, proposal, sender)
                    .map_err(|_| MlsGroupError::LibraryError)?;
            proposal_queue.add(staged_proposal);
        }

        // Create a secret_tree, consuming the `encryption_secret` in the
        // process.
        let secret_tree = provisional_epoch_secrets
            .encryption_secret()
            .create_secret_tree(provisional_tree.leaf_count());

        Ok(StagedCommit {
            staged_proposal_queue: proposal_queue,
            state: Some(StagedCommitState {
                group_context: provisional_group_context,
                epoch_secrets: provisional_epoch_secrets,
                interim_transcript_hash,
                secret_tree: RefCell::new(secret_tree),
                original_nodes,
            }),
        })
    }

    /// Merges a [StagedCommit] into the group state.
    pub fn merge_commit(&mut self, staged_commit: StagedCommit) {
        if let Some(state) = staged_commit.state {
            self.group_context = state.group_context;
            self.epoch_secrets = state.epoch_secrets;
            self.interim_transcript_hash = state.interim_transcript_hash;
            self.secret_tree = state.secret_tree;
        }
    }

    /// This is temporary and will disappear when #424 is addressed.
    /// This is just here for completeness but won't be used anywhere.
    /// Rolls back the public tree nodes in case a Commit contained undesired proposals.
    pub fn cancel_commit(&mut self, staged_commit: StagedCommit) {
        let mut tree = self.tree.borrow_mut();
        if let Some(state) = staged_commit.state {
            tree.nodes = state.original_nodes;
        }
    }
}

/// Contains the changes from a commit to the group state.
#[derive(Debug)]
pub struct StagedCommit {
    staged_proposal_queue: StagedProposalQueue,
    state: Option<StagedCommitState>,
}

impl StagedCommit {
    /// Returns the Add proposals that are covered by the Commit message as in iterator over [StagedAddProposal].
    pub fn add_proposals(&self) -> impl Iterator<Item = StagedAddProposal> {
        self.staged_proposal_queue.add_proposals()
    }

    /// Returns the Remove proposals that are covered by the Commit message as in iterator over [StagedRemoveProposal].
    pub fn remove_proposals(&self) -> impl Iterator<Item = StagedRemoveProposal> {
        self.staged_proposal_queue.remove_proposals()
    }

    /// Returns the Update proposals that are covered by the Commit message as in iterator over [StagedUpdateProposal].
    pub fn update_proposals(&self) -> impl Iterator<Item = StagedUpdateProposal> {
        self.staged_proposal_queue.update_proposals()
    }

    /// Returns the PresharedKey proposals that are covered by the Commit message as in iterator over [StagedPskProposal].
    pub fn psk_proposals(&self) -> impl Iterator<Item = StagedPskProposal> {
        self.staged_proposal_queue.psk_proposals()
    }

    /// Returns `true` if the member was removed through a proposal covered by this Commit message
    /// and `false` otherwise.
    pub fn self_removed(&self) -> bool {
        self.state.is_none()
    }
}

/// This struct is used internally by [StagedCommit] to encapsulate all the modified group state.
#[derive(Debug)]
pub(crate) struct StagedCommitState {
    group_context: GroupContext,
    epoch_secrets: EpochSecrets,
    interim_transcript_hash: Vec<u8>,
    secret_tree: RefCell<SecretTree>,
    original_nodes: Vec<Node>,
}
