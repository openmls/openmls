use super::*;

impl ManagedGroup {
    // === Application messages ===

    /// Creates an application message.
    /// Returns `ManagedGroupError::UseAfterEviction(UseAfterEviction::Error)`
    /// if the member is no longer part of the group.
    /// Returns `ManagedGroupError::PendingProposalsExist` if pending proposals
    /// exist. In that case `.process_pending_proposals()` must be called first
    /// and incoming messages from the DS must be processed afterwards.
    pub fn create_message(
        &mut self,
        key_store: &KeyStore,
        message: &[u8],
    ) -> Result<MlsMessageOut, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }
        if !self.pending_proposals.is_empty() {
            return Err(ManagedGroupError::PendingProposalsExist(
                PendingProposalsError::Exists,
            ));
        }

        let credential = self.credential()?;
        let credential_bundle = key_store
            .get_credential_bundle(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        let ciphertext = self.group.create_application_message(
            &self.aad,
            message,
            &credential_bundle,
            self.configuration().padding_size(),
        )?;

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok(MlsMessageOut::Ciphertext(ciphertext))
    }

    /// Process pending proposals
    pub fn process_pending_proposals(
        &mut self,
        key_store: &KeyStore,
    ) -> Result<(MlsMessageOut, Option<Welcome>), ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }
        // Include pending proposals into Commit
        let messages_to_commit: Vec<&MlsPlaintext> = self.pending_proposals.iter().collect();

        let credential = self.credential()?;
        let credential_bundle = key_store
            .get_credential_bundle(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        // Create Commit over all pending proposals
        // TODO #141
        let (commit, welcome_option, kpb_option) = self.group.create_commit(
            &self.aad,
            &credential_bundle,
            &messages_to_commit,
            &[],
            true,
            None,
        )?;

        // If it was a full Commit, we have to save the KeyPackageBundle for later
        if let Some(kpb) = kpb_option {
            self.own_kpbs.push(kpb);
        }

        // Convert MlsPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_message = self.plaintext_to_mls_message(commit)?;

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok((mls_message, welcome_option))
    }
}
