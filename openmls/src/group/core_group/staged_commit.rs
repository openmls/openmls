use crate::treesync::errors::TreeSyncAddLeaf;
use crate::treesync::{diff::StagedTreeSyncDiff, treekem::DecryptPathParams};

use super::proposals::{
    ProposalQueue, ProposalStore, QueuedAddProposal, QueuedPskProposal, QueuedRemoveProposal,
    QueuedUpdateProposal,
};

use super::super::errors::*;
use super::*;
use core::fmt::Debug;
use std::collections::HashSet;
use std::mem;

impl CoreGroup {
    /// Stages a commit message that was sent by another group member.
    /// This function does the following:
    ///  - Applies the proposals covered by the commit to the tree
    ///  - Applies the (optional) update path to the tree
    ///  - Calculates the path secrets
    ///  - Initializes the key schedule for epoch rollover
    ///  - Verifies the confirmation tag/membership tag
    /// Returns a [StagedCommit] that can be inspected and later merged
    /// into the group state with [CoreGroup::merge_commit()]
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
    ///  - ValSem245
    /// Returns an error if the given commit was sent by the owner of this
    /// group.
    pub(crate) fn stage_commit(
        &mut self,
        mls_plaintext: &MlsPlaintext,
        proposal_store: &ProposalStore,
        own_key_packages: &[KeyPackageBundle],
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<StagedCommit, StageCommitError> {
        // Extract the sender of the Commit message
        let ciphersuite = self.ciphersuite();

        // Verify epoch
        if mls_plaintext.epoch() != self.group_context.epoch() {
            log::error!(
                "Epoch mismatch. Got {:?}, expected {:?}",
                mls_plaintext.epoch(),
                self.group_context.epoch()
            );
            return Err(StageCommitError::EpochMismatch);
        }

        // Check that the sender is another member of the group
        let sender = mls_plaintext.sender();

        if let Sender::Member(member) = sender {
            if member
                == self
                    .key_package_ref()
                    .ok_or_else(|| LibraryError::custom("Expected own key package reference"))?
            {
                return Err(StageCommitError::OwnCommit);
            }
        }

        // Extract Commit & Confirmation Tag from MlsPlaintext
        let commit = match mls_plaintext.content() {
            MlsPlaintextContentType::Commit(commit) => commit,
            _ => return Err(StageCommitError::WrongPlaintextContentType),
        };

        let received_confirmation_tag = mls_plaintext
            .confirmation_tag()
            .ok_or(StageCommitError::ConfirmationTagMissing)?;

        // Build a queue with all proposals from the Commit and check that we have all
        // of the proposals by reference locally
        let proposal_queue = ProposalQueue::from_committed_proposals(
            ciphersuite,
            backend,
            commit.proposals.as_slice().to_vec(),
            proposal_store,
            sender,
        )
        .map_err(|e| match e {
            FromCommittedProposalsError::LibraryError(e) => StageCommitError::LibraryError(e),
            FromCommittedProposalsError::ProposalNotFound => StageCommitError::MissingProposal,
            FromCommittedProposalsError::SelfRemoval => StageCommitError::AttemptedSelfRemoval,
        })?;

        let commit_update_key_package = commit
            .path()
            .as_ref()
            .map(|update_path| update_path.leaf_key_package().clone());

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

        let public_key_set = match sender {
            Sender::Member(hash_ref) => {
                // ValSem109
                // ValSem110
                // ValSem111
                // ValSem112
                self.validate_update_proposals(&proposal_queue, hash_ref)?
            }
            Sender::Preconfigured(_) => {
                // A commit cannot be issued by a pre-configured sender.
                return Err(StageCommitError::SenderTypePreconfigured);
            }
            Sender::NewMember => {
                // ValSem240: External Commit, inline Proposals: There MUST be at least one ExternalInit proposal.
                // ValSem241: External Commit, inline Proposals: There MUST be at most one ExternalInit proposal.
                // ValSem242: External Commit, inline Proposals: There MUST NOT be any Add proposals.
                // ValSem243: External Commit, inline Proposals: There MUST NOT be any Update proposals.
                // ValSem244: External Commit, inline Remove Proposal: The identity and the endpoint_id of the removed
                //            leaf are identical to the ones in the path KeyPackage.
                // ValSem245: External Commit, referenced Proposals: There MUST NOT be any ExternalInit proposals.
                self.validate_external_commit(&proposal_queue, commit_update_key_package.as_ref())?;
                // Since there are no update proposals in an External Commit we have no public keys to return
                HashSet::new()
            }
        };

        // Create provisional tree and apply proposals
        let mut diff = self.treesync().empty_diff()?;

        let apply_proposals_values = self
            .apply_proposals(&mut diff, backend, &proposal_queue, own_key_packages)
            .map_err(|_| StageCommitError::OwnKeyNotFound)?;

        // Now we can actually look at the public keys as they might have changed.
        let sender_index = match sender {
            Sender::Member(hash_ref) => {
                // Own commits have to be merged directly instead of staging them.
                // We can't check for this explicitly. But if it's an own commit
                // we won't be able to get the sender index because the kpr is our
                // own new one that's only in the staged commit.
                self.sender_index(hash_ref)
                    .map_err(|_| StageCommitError::InconsistentSenderIndex)?
            }
            Sender::NewMember => diff.free_leaf_index()?,
            _ => {
                return Err(StageCommitError::SenderTypePreconfigured);
            }
        };

        // Check if we were removed from the group
        if apply_proposals_values.self_removed {
            let staged_diff = diff.into_staged_diff(backend, ciphersuite)?;
            return Ok(StagedCommit::new(
                proposal_queue,
                StagedCommitState::SelfRemoved(Box::new(staged_diff)),
                commit_update_key_package,
            ));
        }

        // Determine if Commit has a path
        let commit_secret = if let Some(path) = commit.path.clone() {
            // Verify KeyPackage and MlsPlaintext membership tag
            // Note that the signature must have been verified already.
            // TODO #106: Support external members
            let kp = path.leaf_key_package();
            if kp.verify(backend).is_err() {
                return Err(StageCommitError::PathKeyPackageVerificationFailure);
            }
            let serialized_context = self
                .group_context
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?;

            let (key_package, update_path_nodes) = path.into_parts();

            // Make sure that the new path key package is valid
            self.validate_path_key_package(sender_index, &key_package, public_key_set, sender)?;

            // If the committer is a `NewMember`, we have to add the leaf to
            // the tree before we can apply or even decrypt an update path.
            // While `apply_received_update_path` will happily update a
            // blank leaf, we still have to call `add_leaf` here in case
            // there are no blanks and the new member extended the tree to
            // fit in.
            if apply_proposals_values.external_init_secret_option.is_some() {
                let sender_leaf_index = diff
                    .add_leaf(key_package.clone(), backend.crypto())
                    .map_err(|e| match e {
                        TreeSyncAddLeaf::LibraryError(e) => e.into(),
                        TreeSyncAddLeaf::TreeFull => StageCommitError::TooManyNewMembers,
                    })?;
                // The new member should have the same index as the claimed sender index.
                if sender_leaf_index != sender_index {
                    return Err(StageCommitError::InconsistentSenderIndex);
                }
            }

            // Decrypt the UpdatePath
            let decrypt_path_params = DecryptPathParams {
                version: self.mls_version,
                update_path: update_path_nodes,
                sender_leaf_index: sender_index,
                exclusion_list: &apply_proposals_values.exclusion_list(),
                group_context: &serialized_context,
            };
            // ValSem202: Path must be the right length
            // ValSem203: Path secrets must decrypt correctly
            // ValSem204: Public keys from Path must be verified and match the private keys from the direct path
            let (plain_path, commit_secret) =
                diff.decrypt_path(backend, ciphersuite, decrypt_path_params)?;
            diff.apply_received_update_path(
                backend,
                ciphersuite,
                sender_index,
                key_package,
                plain_path,
            )?;
            commit_secret
        } else {
            if apply_proposals_values.path_required {
                // ValSem201
                return Err(StageCommitError::RequiredPathNotFound);
            }
            CommitSecret::zero_secret(ciphersuite, self.mls_version)
        };

        // Check if we need to include the init secret from an external commit
        // we applied earlier or if we use the one from the previous epoch.
        let init_secret =
            if let Some(ref init_secret) = apply_proposals_values.external_init_secret_option {
                init_secret
            } else {
                self.group_epoch_secrets.init_secret()
            };

        let joiner_secret = JoinerSecret::new(backend, commit_secret, init_secret)
            .map_err(LibraryError::unexpected_crypto_error)?;

        // Create provisional group state
        let mut provisional_epoch = self.group_context.epoch();
        provisional_epoch.increment();

        let confirmed_transcript_hash = update_confirmed_transcript_hash(
            ciphersuite,
            backend,
            // It is ok to use return a library error here, because we know the MlsPlaintext contains a Commit
            &MlsPlaintextCommitContent::try_from(mls_plaintext)
                .map_err(|_| LibraryError::custom("Could not convert commit content"))?,
            &self.interim_transcript_hash,
        )?;

        let provisional_group_context = GroupContext::new(
            self.group_context.group_id().clone(),
            provisional_epoch,
            diff.compute_tree_hashes(backend, ciphersuite)?,
            confirmed_transcript_hash.clone(),
            self.group_context.extensions(),
        );

        // Prepare the PskSecret
        let psk_secret = PskSecret::new(
            ciphersuite,
            backend,
            apply_proposals_values.presharedkeys.psks(),
        )?;

        // Create key schedule
        let mut key_schedule = KeySchedule::init(ciphersuite, backend, joiner_secret, psk_secret)?;

        let serialized_provisional_group_context = provisional_group_context
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        key_schedule
            .add_context(backend, &serialized_provisional_group_context)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        let provisional_epoch_secrets = key_schedule
            .epoch_secrets(backend)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;

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
            .tag(backend, &confirmed_transcript_hash)
            .map_err(LibraryError::unexpected_crypto_error)?;
        if &own_confirmation_tag != received_confirmation_tag {
            log::error!("Confirmation tag mismatch");
            log_crypto!(trace, "  Got:      {:x?}", received_confirmation_tag);
            log_crypto!(trace, "  Expected: {:x?}", own_confirmation_tag);
            return Err(StageCommitError::ConfirmationTagMismatch);
        }

        let (provisional_group_epoch_secrets, provisional_message_secrets) =
            provisional_epoch_secrets.split_secrets(
                serialized_provisional_group_context,
                diff.leaf_count(),
                // The index should be the same on TreeSync and Diff.
                diff.own_leaf_index(),
            );

        // Make the diff a staged diff. This finalizes the diff and no more changes can be applied to it.
        let staged_diff = diff.into_staged_diff(backend, ciphersuite)?;

        let staged_commit_state =
            StagedCommitState::GroupMember(Box::new(MemberStagedCommitState {
                group_context: provisional_group_context,
                group_epoch_secrets: provisional_group_epoch_secrets,
                message_secrets: provisional_message_secrets,
                interim_transcript_hash,
                staged_diff,
            }));

        Ok(StagedCommit::new(
            proposal_queue,
            staged_commit_state,
            commit_update_key_package,
        ))
    }

    /// Merges a [StagedCommit] into the group state and optionally return a [`SecretTree`]
    /// from the previous epoch. The secret tree is returned if the Commit does not contain a self removal.
    ///
    /// This function should not fail and only returns a [`Result`], because it
    /// might throw a `LibraryError`.
    pub(crate) fn merge_commit(
        &mut self,
        staged_commit: StagedCommit,
    ) -> Result<Option<MessageSecrets>, LibraryError> {
        match staged_commit.state {
            StagedCommitState::SelfRemoved(staged_diff) => {
                self.tree.merge_diff(*staged_diff)?;
                Ok(None)
            }
            StagedCommitState::GroupMember(state) => {
                self.group_context = state.group_context;
                self.group_epoch_secrets = state.group_epoch_secrets;

                // Replace the previous message secrets with the new ones and return the previous message secrets
                let mut message_secrets = state.message_secrets;
                mem::swap(
                    &mut message_secrets,
                    self.message_secrets_store.message_secrets_mut(),
                );

                self.interim_transcript_hash = state.interim_transcript_hash;

                self.tree.merge_diff(state.staged_diff)?;
                Ok(Some(message_secrets))
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum StagedCommitState {
    SelfRemoved(Box<StagedTreeSyncDiff>),
    GroupMember(Box<MemberStagedCommitState>),
}

/// Contains the changes from a commit to the group state.
#[derive(Debug, Serialize, Deserialize)]
pub struct StagedCommit {
    staged_proposal_queue: ProposalQueue,
    state: StagedCommitState,
    commit_update_key_package: Option<KeyPackage>,
}

impl StagedCommit {
    /// Create a new [`StagedCommit`] from the provisional group state created
    /// during the commit process.
    pub(crate) fn new(
        staged_proposal_queue: ProposalQueue,
        state: StagedCommitState,
        commit_update_key_package: Option<KeyPackage>,
    ) -> Self {
        StagedCommit {
            staged_proposal_queue,
            state,
            commit_update_key_package,
        }
    }

    /// Returns the Add proposals that are covered by the Commit message as in iterator over [QueuedAddProposal].
    pub fn add_proposals(&self) -> impl Iterator<Item = QueuedAddProposal> {
        self.staged_proposal_queue.add_proposals()
    }

    /// Returns the Remove proposals that are covered by the Commit message as in iterator over [QueuedRemoveProposal].
    pub fn remove_proposals(&self) -> impl Iterator<Item = QueuedRemoveProposal> {
        self.staged_proposal_queue.remove_proposals()
    }

    /// Returns the Update proposals that are covered by the Commit message as in iterator over [QueuedUpdateProposal].
    pub fn update_proposals(&self) -> impl Iterator<Item = QueuedUpdateProposal> {
        self.staged_proposal_queue.update_proposals()
    }

    /// Returns the PresharedKey proposals that are covered by the Commit message as in iterator over [QueuedPskProposal].
    pub fn psk_proposals(&self) -> impl Iterator<Item = QueuedPskProposal> {
        self.staged_proposal_queue.psk_proposals()
    }

    /// Returns an optional key package from the Commit's update path.
    /// A key package is returned for full and empty Commits, but not for partial Commits.
    pub fn commit_update_key_package(&self) -> Option<&KeyPackage> {
        self.commit_update_key_package.as_ref()
    }

    /// Returns `true` if the member was removed through a proposal covered by this Commit message
    /// and `false` otherwise.
    pub fn self_removed(&self) -> bool {
        matches!(self.state, StagedCommitState::SelfRemoved(_))
    }
}

/// This struct is used internally by [StagedCommit] to encapsulate all the modified group state.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MemberStagedCommitState {
    group_context: GroupContext,
    group_epoch_secrets: GroupEpochSecrets,
    message_secrets: MessageSecrets,
    interim_transcript_hash: Vec<u8>,
    staged_diff: StagedTreeSyncDiff,
}

impl MemberStagedCommitState {
    pub(super) fn new(
        group_context: GroupContext,
        group_epoch_secrets: GroupEpochSecrets,
        message_secrets: MessageSecrets,
        interim_transcript_hash: Vec<u8>,
        staged_diff: StagedTreeSyncDiff,
    ) -> Self {
        Self {
            group_context,
            group_epoch_secrets,
            message_secrets,
            interim_transcript_hash,
            staged_diff,
        }
    }
}
