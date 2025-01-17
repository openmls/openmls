use super::{super::errors::*, *};
use crate::{
    framing::{mls_auth_content::AuthenticatedContent, mls_content::FramedContentBody, Sender},
    group::{
        mls_group::staged_commit::StagedCommitState, proposal_store::ProposalQueue, StagedCommit,
    },
    messages::{proposals::ProposalOrRef, Commit},
};

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
pub struct PublicStagedCommitState {
    pub(super) staged_diff: StagedPublicGroupDiff,
    pub(super) update_path_leaf_node: Option<LeafNode>,
}

impl PublicStagedCommitState {
    pub fn new(
        staged_diff: StagedPublicGroupDiff,
        update_path_leaf_node: Option<LeafNode>,
    ) -> Self {
        Self {
            staged_diff,
            update_path_leaf_node,
        }
    }

    pub(crate) fn into_staged_diff(self) -> StagedPublicGroupDiff {
        self.staged_diff
    }

    pub fn update_path_leaf_node(&self) -> Option<&LeafNode> {
        self.update_path_leaf_node.as_ref()
    }

    pub fn staged_diff(&self) -> &StagedPublicGroupDiff {
        &self.staged_diff
    }
}

impl PublicGroup {
    pub(crate) fn validate_commit<'a>(
        &self,
        mls_content: &'a AuthenticatedContent,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<(&'a Commit, ProposalQueue, LeafNodeIndex), StageCommitError> {
        let ciphersuite = self.ciphersuite();

        // Verify epoch
        // https://validation.openmls.tech/#valn1201
        if mls_content.epoch() != self.group_context().epoch() {
            log::error!(
                "Epoch mismatch. Got {:?}, expected {:?}",
                mls_content.epoch(),
                self.group_context().epoch()
            );
            return Err(StageCommitError::EpochMismatch);
        }

        // Extract Commit & Confirmation Tag from PublicMessage
        let commit = match mls_content.content() {
            FramedContentBody::Commit(commit) => commit,
            _ => return Err(StageCommitError::WrongPlaintextContentType),
        };

        let sender = mls_content.sender();

        if sender == &Sender::NewMemberCommit {
            // External commit, there MUST be a path
            // https://validation.openmls.tech/#valn0405
            if commit.path.is_none() {
                return Err(ExternalCommitValidationError::NoPath.into());
            }

            // ValSem244: External Commit, There MUST NOT be any referenced proposals.
            // https://validation.openmls.tech/#valn0406
            if commit
                .proposals
                .iter()
                .any(|proposal| matches!(proposal, ProposalOrRef::Reference(_)))
            {
                return Err(ExternalCommitValidationError::ReferencedProposal.into());
            }

            let number_of_remove_proposals = commit
                .proposals
                .iter()
                .filter(|prop| matches!(prop, ProposalOrRef::Proposal(Proposal::Remove(_))))
                .count();

            // https://validation.openmls.tech/#valn0402
            if number_of_remove_proposals > 1 {
                return Err(ExternalCommitValidationError::MultipleExternalInitProposals.into());
            }
        }

        // Build a queue with all proposals from the Commit and check that we have all
        // of the proposals by reference locally
        // ValSem240: Commit must not cover inline self Remove proposal
        let proposal_queue = ProposalQueue::from_committed_proposals(
            ciphersuite,
            crypto,
            commit.proposals.as_slice().to_vec(),
            self.proposal_store(),
            sender,
        )
        .map_err(|e| {
            log::error!("Error building the proposal queue for the commit ({e:?})");
            match e {
                FromCommittedProposalsError::LibraryError(e) => StageCommitError::LibraryError(e),
                FromCommittedProposalsError::ProposalNotFound => StageCommitError::MissingProposal,
                FromCommittedProposalsError::SelfRemoval => StageCommitError::AttemptedSelfRemoval,
            }
        })?;

        // https://validation.openmls.tech/#valn1207
        if let Some(update_path) = &commit.path {
            self.validate_leaf_node(update_path.leaf_node())?;
        }

        // Validate the staged proposals. This implements https://validation.openmls.tech/#valn1204.
        // This is done by doing the following checks:

        // ValSem101
        // ValSem102
        // ValSem103
        // ValSem104
        self.validate_key_uniqueness(&proposal_queue, Some(commit))?;
        // ValSem105
        self.validate_add_proposals(&proposal_queue)?;
        // ValSem106
        // ValSem109
        self.validate_capabilities(&proposal_queue)?;
        // ValSem107
        // ValSem108
        self.validate_remove_proposals(&proposal_queue)?;
        // ValSem113: All Proposals: The proposal type must be supported by all
        // members of the group
        self.validate_proposal_type_support(&proposal_queue)?;
        // ValSem208
        // ValSem209
        self.validate_group_context_extensions_proposal(&proposal_queue)?;
        // ValSem401
        // ValSem402
        // ValSem403
        self.validate_pre_shared_key_proposals(&proposal_queue)?;

        match sender {
            Sender::Member(leaf_index) => {
                // ValSem110
                // ValSem111
                // ValSem112
                self.validate_update_proposals(&proposal_queue, *leaf_index)?;

                self.validate_no_external_init_proposals(&proposal_queue)?;
            }
            Sender::External(_) => {
                // A commit cannot be issued by a pre-configured sender.
                return Err(StageCommitError::SenderTypeExternal);
            }
            Sender::NewMemberProposal => {
                // A commit cannot be issued by a `NewMemberProposal` sender.
                return Err(StageCommitError::SenderTypeNewMemberProposal);
            }
            Sender::NewMemberCommit => {
                // ValSem240: External Commit, inline Proposals: There MUST be at least one ExternalInit proposal.
                // ValSem241: External Commit, inline Proposals: There MUST be at most one ExternalInit proposal.
                // ValSem242: External Commit must only cover inline proposal in allowlist (ExternalInit, Remove, PreSharedKey)
                self.validate_external_commit(&proposal_queue)?;
            }
        }

        // Now we can actually look at the public keys as they might have changed.
        let sender_index = match sender {
            Sender::Member(leaf_index) => *leaf_index,
            Sender::NewMemberCommit => {
                let inline_proposals = commit.proposals.iter().filter_map(|p| {
                    if let ProposalOrRef::Proposal(inline_proposal) = p {
                        Some(Some(inline_proposal))
                    } else {
                        None
                    }
                });
                self.leftmost_free_index(inline_proposals)?
            }
            _ => {
                return Err(StageCommitError::SenderTypeExternal);
            }
        };

        Ok((commit, proposal_queue, sender_index))
    }

    // Check that no external init proposal occurs. Needed only for regular commits.
    // [valn0310](https://validation.openmls.tech/#valn0310)
    fn validate_no_external_init_proposals(
        &self,
        proposal_queue: &ProposalQueue,
    ) -> Result<(), ProposalValidationError> {
        for proposal in proposal_queue.queued_proposals() {
            if matches!(
                proposal.proposal().proposal_type(),
                ProposalType::ExternalInit
            ) {
                return Err(ProposalValidationError::ExternalInitProposalInRegularCommit);
            }
        }

        Ok(())
    }

    /// Stages a commit message that was sent by another group member.
    /// This function does the following:
    ///  - Applies the proposals covered by the commit to the tree
    ///  - Applies the (optional) update path to the tree
    ///  - Updates the [`GroupContext`]
    ///  - Decrypts and derives the path secrets
    ///  - Initializes the key schedule for epoch rollover
    ///  - Verifies the confirmation tag
    ///
    /// Returns a [`StagedCommit`] that can be inspected and later merged into
    /// the group state either with [`MlsGroup::merge_commit()`] or
    /// [`PublicGroup::merge_diff()`] This function does the following checks:
    ///  - ValSem101
    ///  - ValSem102
    ///  - ValSem104
    ///  - ValSem105
    ///  - ValSem106
    ///  - ValSem107
    ///  - ValSem108
    ///  - ValSem110
    ///  - ValSem111
    ///  - ValSem112
    ///  - ValSem200
    ///  - ValSem201
    ///  - ValSem202: Path must be the right length
    ///  - ValSem203: Path secrets must decrypt correctly
    ///  - ValSem204: Public keys from Path must be verified and match the
    ///               private keys from the direct path
    ///  - ValSem205
    ///  - ValSem240
    ///  - ValSem241
    ///  - ValSem242
    ///  - ValSem244
    ///
    /// Returns an error if the given commit was sent by the owner of this
    /// group.
    pub(crate) fn stage_commit(
        &self,
        mls_content: &AuthenticatedContent,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<StagedCommit, StageCommitError> {
        let (commit, proposal_queue, sender_index) = self.validate_commit(mls_content, crypto)?;

        let staged_diff = self.stage_diff(mls_content, &proposal_queue, sender_index, crypto)?;
        let staged_state = PublicStagedCommitState {
            staged_diff,
            update_path_leaf_node: commit.path.as_ref().map(|p| p.leaf_node().clone()),
        };

        let staged_commit_state = StagedCommitState::PublicState(Box::new(staged_state));

        Ok(StagedCommit::new(proposal_queue, staged_commit_state))
    }

    fn stage_diff(
        &self,
        mls_content: &AuthenticatedContent,
        proposal_queue: &ProposalQueue,
        sender_index: LeafNodeIndex,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<StagedPublicGroupDiff, StageCommitError> {
        let ciphersuite = self.ciphersuite();
        let mut diff = self.empty_diff();

        let apply_proposals_values = diff.apply_proposals(proposal_queue, None)?;

        let commit = match mls_content.content() {
            FramedContentBody::Commit(commit) => commit,
            _ => return Err(StageCommitError::WrongPlaintextContentType),
        };

        // Determine if Commit has a path
        if let Some(update_path) = &commit.path {
            // Update the public group
            // ValSem202: Path must be the right length
            diff.apply_received_update_path(crypto, ciphersuite, sender_index, update_path)?;
        } else if apply_proposals_values.path_required {
            // ValSem201
            // https://validation.openmls.tech/#valn1206
            return Err(StageCommitError::RequiredPathNotFound);
        };

        // Update group context
        diff.update_group_context(crypto, apply_proposals_values.extensions.clone())?;

        // Update the confirmed transcript hash before we compute the confirmation tag.
        diff.update_confirmed_transcript_hash(crypto, mls_content)?;

        let received_confirmation_tag = mls_content
            .confirmation_tag()
            .ok_or(StageCommitError::ConfirmationTagMissing)?;

        // If we have private key material, derive the secrets for the next
        // epoch and check the confirmation tag.
        diff.update_interim_transcript_hash(
            ciphersuite,
            crypto,
            received_confirmation_tag.clone(),
        )?;

        let staged_diff = diff.into_staged_diff(crypto, ciphersuite)?;

        Ok(staged_diff)
    }

    /// Merges a [StagedCommit] into the public group state.
    pub fn merge_commit<Storage: PublicStorageProvider>(
        &mut self,
        storage: &Storage,
        staged_commit: StagedCommit,
    ) -> Result<(), MergeCommitError<Storage::Error>> {
        match staged_commit.into_state() {
            StagedCommitState::PublicState(staged_state) => {
                self.merge_diff(staged_state.staged_diff);
            }
            StagedCommitState::GroupMember(_) => (),
        }

        self.proposal_store.empty();
        storage
            .clear_proposal_queue::<GroupId, ProposalRef>(self.group_id())
            .map_err(MergeCommitError::StorageError)?;
        self.store(storage).map_err(MergeCommitError::StorageError)
    }
}
