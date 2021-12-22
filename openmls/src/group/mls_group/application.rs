use super::*;

impl MlsGroup {
    // === Application messages ===

    /// Creates an application message.
    /// Returns `MlsGroupError::UseAfterEviction(UseAfterEviction::Error)`
    /// if the member is no longer part of the group.
    /// Returns `MlsGroupError::PendingProposalsExist` if pending proposals
    /// exist. In that case `.process_pending_proposals()` must be called first
    /// and incoming messages from the DS must be processed afterwards.
    pub fn create_message(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        message: &[u8],
    ) -> Result<MlsMessageOut, MlsGroupError> {
        if !self.active {
            return Err(MlsGroupError::UseAfterEviction(UseAfterEviction::Error));
        }
        if !self.proposal_store.is_empty() {
            return Err(MlsGroupError::PendingProposalsExist(
                PendingProposalsError::Exists,
            ));
        }

        let credential = self.credential()?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(credential.signature_key())
            .ok_or(MlsGroupError::NoMatchingCredentialBundle)?;

        let ciphertext = self.group.create_application_message(
            &self.aad,
            message,
            &credential_bundle,
            self.configuration().padding_size(),
            backend,
        )?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok(MlsMessageOut::Ciphertext(Box::new(ciphertext)))
    }
}
