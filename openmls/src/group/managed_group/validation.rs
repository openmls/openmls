use mls_group::{proposals::StagedProposal, staged_commit::StagedCommit};

use super::*;

impl ManagedGroup {
    /// This function is used to parse messages from the DS.
    /// It checks for syntactic errors and makes some semantic checks as well.
    /// If the input is a [MlsCiphertext] message, it will be decrypted.
    /// Returns an [UnverifiedMessage] that can be inspected and later processed in
    /// [self::process_unverified_message()].
    pub fn parse_message(
        &mut self,
        message: MlsMessageIn,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<UnverifiedMessage, ManagedGroupError> {
        // Make sure we are still a member of the group
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        self.group
            .parse_message(message, backend)
            .map_err(|e| e.into())
    }

    /// This processing function does most of the semantic verifications.
    /// It returns a [ProcessedMessage] enum.
    pub fn process_unverified_message(
        &mut self,
        unverified_message: UnverifiedMessage,
        signature_key: Option<&SignaturePublicKey>,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<ProcessedMessage, ManagedGroupError> {
        self.group
            .process_unverified_message(
                unverified_message,
                signature_key,
                &self.proposal_store,
                &self.own_kpbs,
                backend,
            )
            .map_err(|e| e.into())
    }

    /// Stores a standalone proposal in the internal [ProposalStore]
    pub fn store_pending_proposal(&mut self, proposal: StagedProposal) {
        // Store the proposal in in the internal ProposalStore
        self.proposal_store.add(proposal);
    }

    /// Merge a [StagedCommit] into the group after inspection
    pub fn merge_staged_commit(
        &mut self,
        staged_commit: StagedCommit,
    ) -> Result<(), ManagedGroupError> {
        self.group
            .merge_staged_commit(staged_commit, &mut self.proposal_store)
            .map_err(|e| e.into())
    }
}
