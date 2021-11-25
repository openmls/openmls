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
        backend: &impl OpenMlsCryptoProvider,
        message: &[u8],
    ) -> Result<MlsMessageOut, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }
        if !self.proposal_store.is_empty() {
            return Err(ManagedGroupError::PendingProposalsExist(
                PendingProposalsError::Exists,
            ));
        }

        let credential = self.credential()?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        let ciphertext = self.group.create_application_message(
            &self.aad,
            message,
            &credential_bundle,
            self.configuration().padding_size(),
            backend,
        )?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok(MlsMessageOut::Ciphertext(ciphertext))
    }
}
