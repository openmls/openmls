//! Processing functions of an [`MlsGroup`] for incoming messages.

use std::mem;

use core_group::staged_commit::StagedCommit;
use openmls_traits::{signatures::Signer, storage::StorageProvider as _};

use crate::storage::OpenMlsProvider;
use crate::{
    group::core_group::create_commit_params::CreateCommitParams, messages::group_info::GroupInfo,
};

use crate::group::errors::MergeCommitError;

use super::{errors::ProcessMessageError, *};

impl MlsGroup {
    /// Parses incoming messages from the DS. Checks for syntactic errors and
    /// makes some semantic checks as well. If the input is an encrypted
    /// message, it will be decrypted. This processing function does syntactic
    /// and semantic validation of the message. It returns a [ProcessedMessage]
    /// enum.
    ///
    /// # Errors:
    /// Returns an [`ProcessMessageError`] when the validation checks fail
    /// with the exact reason of the failure.
    pub fn process_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        message: impl Into<ProtocolMessage>,
    ) -> Result<ProcessedMessage, ProcessMessageError<Provider::StorageError>> {
        // Make sure we are still a member of the group
        if !self.is_active() {
            return Err(ProcessMessageError::GroupStateError(
                MlsGroupStateError::UseAfterEviction,
            ));
        }
        let message = message.into();

        // Check that handshake messages are compatible with the incoming wire format policy
        if !message.is_external()
            && message.is_handshake_message()
            && !self
                .configuration()
                .wire_format_policy()
                .incoming()
                .is_compatible_with(message.wire_format())
        {
            return Err(ProcessMessageError::IncompatibleWireFormat);
        }

        // Parse the message
        let sender_ratchet_configuration =
            self.configuration().sender_ratchet_configuration().clone();
        self.group.process_message(
            provider,
            message,
            &sender_ratchet_configuration,
            &self.own_leaf_nodes,
        )
    }

    /// Stores a standalone proposal in the internal [ProposalStore]
    pub fn store_pending_proposal<Storage: StorageProvider>(
        &mut self,
        storage: &Storage,
        proposal: QueuedProposal,
    ) -> Result<(), Storage::Error> {
        storage.queue_proposal(self.group_id(), &proposal.proposal_reference(), &proposal)?;
        // Store the proposal in in the internal ProposalStore
        self.proposal_store_mut().add(proposal);

        Ok(())
    }

    /// Creates a Commit message that covers the pending proposals that are
    /// currently stored in the group's [ProposalStore]. The Commit message is
    /// created even if there are no valid pending proposals.
    ///
    /// Returns an error if there is a pending commit. Otherwise it returns a
    /// tuple of `Commit, Option<Welcome>, Option<GroupInfo>`, where `Commit`
    /// and [`Welcome`] are MlsMessages of the type [`MlsMessageOut`].
    ///
    /// [`Welcome`]: crate::messages::Welcome
    // FIXME: #1217
    #[allow(clippy::type_complexity)]
    pub fn commit_to_pending_proposals<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
    ) -> Result<
        (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>),
        CommitToPendingProposalsError<Provider::StorageError>,
    > {
        self.is_operational()?;

        // Create Commit over all pending proposals
        // TODO #751
        let params = CreateCommitParams::builder()
            .framing_parameters(self.framing_parameters())
            .build();
        let create_commit_result = self.group.create_commit(params, provider, signer)?;

        // Convert PublicMessage messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_message = self.content_to_mls_message(create_commit_result.commit, provider)?;

        // Set the current group state to [`MlsGroupState::PendingCommit`],
        // storing the current [`StagedCommit`] from the commit results
        self.group_state = MlsGroupState::PendingCommit(Box::new(PendingCommitState::Member(
            create_commit_result.staged_commit,
        )));
        provider
            .storage()
            .write_group_state(self.group_id(), &self.group_state)
            .map_err(CommitToPendingProposalsError::StorageError)?;

        self.reset_aad();
        Ok((
            mls_message,
            create_commit_result
                .welcome_option
                .map(|w| MlsMessageOut::from_welcome(w, self.group.version())),
            create_commit_result.group_info,
        ))
    }

    /// Merge a [StagedCommit] into the group after inspection. As this advances
    /// the epoch of the group, it also clears any pending commits.
    pub fn merge_staged_commit<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        staged_commit: StagedCommit,
    ) -> Result<(), MergeCommitError<Provider::StorageError>> {
        // Check if we were removed from the group
        if staged_commit.self_removed() {
            self.group_state = MlsGroupState::Inactive;
        }
        provider
            .storage()
            .write_group_state(self.group_id(), &self.group_state)
            .map_err(MergeCommitError::StorageError)?;

        // Merge staged commit
        self.group.merge_staged_commit(provider, staged_commit)?;

        // Extract and store the resumption psk for the current epoch
        let resumption_psk = self.group.group_epoch_secrets().resumption_psk();
        self.group
            .resumption_psk_store
            .add(self.group.context().epoch(), resumption_psk.clone());
        provider
            .storage()
            .write_resumption_psk_store(self.group_id(), &self.group.resumption_psk_store)
            .map_err(MergeCommitError::StorageError)?;

        // Delete own KeyPackageBundles
        self.own_leaf_nodes.clear();
        provider
            .storage()
            .delete_own_leaf_nodes(self.group_id())
            .map_err(MergeCommitError::StorageError)?;

        // Delete a potential pending commit
        self.clear_pending_commit(provider.storage())
            .map_err(MergeCommitError::StorageError)?;

        Ok(())
    }

    /// Merges the pending [`StagedCommit`] if there is one, and
    /// clears the field by setting it to `None`.
    pub fn merge_pending_commit<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
    ) -> Result<(), MergePendingCommitError<Provider::StorageError>> {
        match &self.group_state {
            MlsGroupState::PendingCommit(_) => {
                let old_state = mem::replace(&mut self.group_state, MlsGroupState::Operational);
                if let MlsGroupState::PendingCommit(pending_commit_state) = old_state {
                    self.merge_staged_commit(provider, (*pending_commit_state).into())?;
                }
                Ok(())
            }
            MlsGroupState::Inactive => Err(MlsGroupStateError::UseAfterEviction)?,
            MlsGroupState::Operational => Ok(()),
        }
    }
}
