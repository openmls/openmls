//! Processing functions of an [`MlsGroup`] for incoming messages.

use std::mem;

use core_group::{create_commit_params::CreateCommitParams, staged_commit::StagedCommit};
use tls_codec::Serialize;

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
    pub fn process_message(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        message: MlsMessageIn,
    ) -> Result<ProcessedMessage, ProcessMessageError> {
        // Make sure we are still a member of the group
        if !self.is_active() {
            return Err(ProcessMessageError::GroupStateError(
                MlsGroupStateError::UseAfterEviction,
            ));
        }

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

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        // Parse the message
        let sender_ratchet_configuration =
            self.configuration().sender_ratchet_configuration().clone();
        self.group.process_message(
            backend,
            message,
            &sender_ratchet_configuration,
            &self.proposal_store,
            &self.own_kpbs,
        )
    }

    /// Stores a standalone proposal in the internal [ProposalStore]
    pub fn store_pending_proposal(&mut self, proposal: QueuedProposal) {
        // Store the proposal in in the internal ProposalStore
        self.proposal_store.add(proposal);

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();
    }

    /// Creates a Commit message that covers the pending proposals that are
    /// currently stored in the group's [ProposalStore].
    ///
    /// Returns an error if there is a pending commit.
    pub fn commit_to_pending_proposals(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<(MlsMessageOut, Option<Welcome>), CommitToPendingProposalsError> {
        self.is_operational()?;

        let credential = self.credential()?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(
                &credential
                    .signature_key()
                    .tls_serialize_detached()
                    .map_err(LibraryError::missing_bound_check)?,
            )
            .ok_or(CommitToPendingProposalsError::NoMatchingCredentialBundle)?;

        // Create Commit over all pending proposals
        // TODO #751
        let params = CreateCommitParams::builder()
            .framing_parameters(self.framing_parameters())
            .credential_bundle(&credential_bundle)
            .proposal_store(&self.proposal_store)
            .build();
        let create_commit_result = self.group.create_commit(params, backend)?;

        // Convert MlsPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_message = self.plaintext_to_mls_message(create_commit_result.commit, backend)?;

        // Set the current group state to [`MlsGroupState::PendingCommit`],
        // storing the current [`StagedCommit`] from the commit results
        self.group_state = MlsGroupState::PendingCommit(Box::new(PendingCommitState::Member(
            create_commit_result.staged_commit,
        )));

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((mls_message, create_commit_result.welcome_option))
    }

    /// Merge a [StagedCommit] into the group after inspection. As this advances
    /// the epoch of the group, it also clears any pending commits.
    pub fn merge_staged_commit(&mut self, staged_commit: StagedCommit) -> Result<(), LibraryError> {
        // Check if we were removed from the group
        if staged_commit.self_removed() {
            self.group_state = MlsGroupState::Inactive;
        }

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        // Merge staged commit
        self.group
            .merge_staged_commit(staged_commit, &mut self.proposal_store)?;

        // Extract and store the resumption psk for the current epoch
        let resumption_psk = self.group.group_epoch_secrets().resumption_psk();
        self.resumption_psk_store
            .add(self.group.context().epoch(), resumption_psk.clone());

        // Delete own KeyPackageBundles
        self.own_kpbs.clear();

        // Delete a potential pending commit
        self.clear_pending_commit();

        Ok(())
    }

    /// Merges the pending [`StagedCommit`] if there is one, and
    /// clears the field by setting it to `None`.
    pub fn merge_pending_commit(&mut self) -> Result<(), MlsGroupStateError> {
        match &self.group_state {
            MlsGroupState::PendingCommit(_) => {
                let old_state = mem::replace(&mut self.group_state, MlsGroupState::Operational);
                if let MlsGroupState::PendingCommit(pending_commit_state) = old_state {
                    if let Err(e) = self.merge_staged_commit((*pending_commit_state).into()) {
                        log::debug!("Error when merging own commit: {:?}", e);
                    }
                }
                Ok(())
            }
            MlsGroupState::Inactive => Err(MlsGroupStateError::UseAfterEviction),
            MlsGroupState::Operational => Ok(()),
        }
    }
}
