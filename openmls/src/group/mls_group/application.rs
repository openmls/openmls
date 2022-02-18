use tls_codec::Serialize;

use super::{errors::CreateMessageError, *};

impl MlsGroup {
    // === Application messages ===

    /// Creates an application message.
    /// Returns `CreateMessageError::MlsGroupStateError::UseAfterEviction`
    /// if the member is no longer part of the group.
    /// Returns `CreateMessageError::MlsGroupStateError::PendingProposal` if pending proposals
    /// exist. In that case `.process_pending_proposals()` must be called first
    /// and incoming messages from the DS must be processed afterwards.
    pub fn create_message(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        message: &[u8],
    ) -> Result<MlsMessageOut, CreateMessageError> {
        if !self.is_active() {
            return Err(CreateMessageError::GroupStateError(
                MlsGroupStateError::UseAfterEviction,
            ));
        }
        if !self.proposal_store.is_empty() {
            return Err(CreateMessageError::GroupStateError(
                MlsGroupStateError::PendingProposal,
            ));
        }

        let credential = self
            .credential()
            // We checked we are in the right group state before
            .map_err(|_| LibraryError::custom("Wrong group state"))?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(
                &credential
                    .signature_key()
                    .tls_serialize_detached()
                    .map_err(LibraryError::missing_bound_check)?,
            )
            .ok_or(CreateMessageError::NoMatchingCredentialBundle)?;

        let ciphertext = self
            .group
            .create_application_message(
                &self.aad,
                message,
                &credential_bundle,
                self.configuration().padding_size(),
                backend,
            )
            // We know the application message is wellformed and we have the key material of the current epoch
            .map_err(|_| LibraryError::custom("Malformed plaintext"))?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok(MlsMessageOut::from(ciphertext))
    }
}
