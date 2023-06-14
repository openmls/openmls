use super::{super::errors::*, *};
use crate::{
    framing::{mls_auth_content::AuthenticatedContent, mls_content::FramedContentBody, Sender},
    group::{
        core_group::{
            proposals::{ProposalQueue, ProposalStore},
            staged_commit::StagedCommitState,
        },
        StagedCommit,
    },
    messages::{proposals::ProposalOrRef, Commit},
};

impl PublicGroup {
    pub(crate) fn validate_commit<'a>(
        &self,
        mls_content: &'a AuthenticatedContent,
        proposal_store: &ProposalStore,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<(&'a Commit, ProposalQueue, LeafNodeIndex), StageCommitError> {
        let ciphersuite = self.ciphersuite();

        // Verify epoch
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
        // ValSem244: External Commit, There MUST NOT be any referenced proposals.
        if sender == &Sender::NewMemberCommit
            && commit
                .proposals
                .iter()
                .any(|proposal| matches!(proposal, ProposalOrRef::Reference(_)))
        {
            return Err(StageCommitError::ExternalCommitValidation(
                ExternalCommitValidationError::ReferencedProposal,
            ));
        }

        // Build a queue with all proposals from the Commit and check that we have all
        // of the proposals by reference locally
        // ValSem240: Commit must not cover inline self Remove proposal
        let proposal_queue = ProposalQueue::from_committed_proposals(
            ciphersuite,
            crypto,
            commit.proposals.as_slice().to_vec(),
            proposal_store,
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

        let commit_update_leaf_node = commit
            .path()
            .as_ref()
            .map(|update_path| update_path.leaf_node().clone());

        // Validate the staged proposals by doing the following checks:
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
                // ValSem243: External Commit, inline Remove Proposal: The identity and the endpoint_id of the removed
                //            leaf are identical to the ones in the path KeyPackage.
                self.validate_external_commit(&proposal_queue, commit_update_leaf_node.as_ref())?;
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

    /// Stages a commit message that was sent by another group member.
    /// This function does the following:
    ///  - Applies the proposals covered by the commit to the tree
    ///  - Applies the (optional) update path to the tree
    ///  - Updates the [`GroupContext`]
    ///
    /// A similar function to this exists in [`CoreGroup`], which in addition
    /// does the following:
    ///  - Decrypts and derives the path secrets
    ///  - Initializes the key schedule for epoch rollover
    ///  - Verifies the confirmation tag
    ///
    /// Returns a [`StagedCommit`] that can be inspected and later merged into
    /// the group state either with [`CoreGroup::merge_commit()`] or
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
    ///  - ValSem243
    ///  - ValSem244
    /// Returns an error if the given commit was sent by the owner of this
    /// group.
    /// TODO #1255: This will be used by the `process_message` function of the
    /// `PublicGroup` later on.
    #[allow(unused)]
    pub(crate) fn stage_commit(
        &self,
        mls_content: &AuthenticatedContent,
        proposal_store: &ProposalStore,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<StagedCommit, StageCommitError> {
        let ciphersuite = self.ciphersuite();

        let (commit, proposal_queue, sender_index) =
            self.validate_commit(mls_content, proposal_store, crypto)?;

        let staged_diff = self.stage_diff(mls_content, &proposal_queue, sender_index, crypto)?;

        let staged_commit_state = StagedCommitState::PublicState(Box::new(staged_diff));

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
            return Err(StageCommitError::RequiredPathNotFound);
        };

        // Update group context
        diff.update_group_context(crypto)?;

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
    ///
    /// This function should not fail and only returns a [`Result`], because it
    /// might throw a `LibraryError`.
    pub fn merge_commit(&mut self, staged_commit: StagedCommit) {
        match staged_commit.into_state() {
            StagedCommitState::PublicState(staged_diff) => self.merge_diff(*staged_diff),
            StagedCommitState::GroupMember(_) => (),
        }
        self.proposal_store.empty()
    }
}
