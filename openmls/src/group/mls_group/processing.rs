use core_group::{
    create_commit_params::CreateCommitParams, proposals::StagedProposal,
    staged_commit::StagedCommit,
};

use super::*;

impl MlsGroup {
    /// This function is used to parse messages from the DS.
    /// It checks for syntactic errors and makes some semantic checks as well.
    /// If the input is a [MlsCiphertext] message, it will be decrypted.
    /// Returns an [UnverifiedMessage] that can be inspected and later processed in
    /// [self::process_unverified_message()].
    pub fn parse_message(
        &mut self,
        message: MlsMessageIn,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<UnverifiedMessage, MlsGroupError> {
        // Make sure we are still a member of the group
        if !self.active {
            return Err(MlsGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        // Parse the message
        let sender_ratchet_configuration =
            self.configuration().sender_ratchet_configuration().clone();
        self.group
            .parse_message(
                message,
                &mut self.message_secrets_store,
                &sender_ratchet_configuration,
                backend,
            )
            .map_err(MlsGroupError::Group)
    }

    /// This processing function does most of the semantic verifications.
    /// It returns a [ProcessedMessage] enum.
    pub fn process_unverified_message(
        &mut self,
        unverified_message: UnverifiedMessage,
        signature_key: Option<&SignaturePublicKey>,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<ProcessedMessage, MlsGroupError> {
        self.group
            .process_unverified_message(
                unverified_message,
                signature_key,
                &self.proposal_store,
                &mut self.message_secrets_store,
                &self.own_kpbs,
                backend,
            )
            .map_err(|e| e.into())
    }

    /// Stores a standalone proposal in the internal [ProposalStore]
    pub fn store_pending_proposal(&mut self, proposal: StagedProposal) {
        // Store the proposal in in the internal ProposalStore
        self.proposal_store.add(proposal);

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();
    }

    /// Create a Commit message that covers the pending proposals that are
    /// currently stored inthe group's [ProposalStore].
    pub fn commit_to_pending_proposals(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<(MlsMessageOut, Option<Welcome>), MlsGroupError> {
        if !self.active {
            return Err(MlsGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        let credential = self.credential()?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(credential.signature_key())
            .ok_or(MlsGroupError::NoMatchingCredentialBundle)?;

        // Create Commit over all pending proposals
        // TODO #141
        let params = CreateCommitParams::builder()
            .framing_parameters(self.framing_parameters())
            .credential_bundle(&credential_bundle)
            .proposal_store(&self.proposal_store)
            .build();
        let (commit, welcome_option, kpb_option) = self.group.create_commit(params, backend)?;

        // If it was a full Commit, we have to save the KeyPackageBundle for later
        if let Some(kpb) = kpb_option {
            self.own_kpbs.push(kpb);
        }

        // Convert MlsPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_message = self.plaintext_to_mls_message(commit, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((mls_message, welcome_option))
    }

    /// Merge a [StagedCommit] into the group after inspection
    pub fn merge_staged_commit(
        &mut self,
        staged_commit: StagedCommit,
    ) -> Result<(), MlsGroupError> {
        // Check if we were removed from the group
        if staged_commit.self_removed() {
            self.active = false;
        }

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        // Merge staged commit
        self.group
            .merge_staged_commit(
                staged_commit,
                &mut self.proposal_store,
                &mut self.message_secrets_store,
            )
            .map_err(MlsGroupError::Group)?;

        // Extract and store the resumption secret for the current epoch
        let resumption_secret = self.group.group_epoch_secrets().resumption_secret();
        self.resumption_secret_store
            .add(self.group.context().epoch(), resumption_secret.clone());

        // Delete own KeyPackageBundles
        self.own_kpbs.clear();

        Ok(())
    }
}
