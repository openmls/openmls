use openmls_traits::signatures::Signer;

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
        provider: &impl OpenMlsProvider,
        signer: &impl Signer,
        message: &[u8],
    ) -> Result<MlsMessageOut, CreateMessageError> {
        if !self.is_active() {
            return Err(CreateMessageError::GroupStateError(
                MlsGroupStateError::UseAfterEviction,
            ));
        }
        // TODO: unwrap
        if provider.storage().queued_proposal_count().unwrap() > 0 {
            return Err(CreateMessageError::GroupStateError(
                MlsGroupStateError::PendingProposal,
            ));
        }

        let ciphertext = self
            .group
            .create_application_message(
                &self.aad,
                message,
                self.configuration().padding_size(),
                provider,
                signer,
            )
            // We know the application message is wellformed and we have the key material of the current epoch
            .map_err(|_| LibraryError::custom("Malformed plaintext"))?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok(MlsMessageOut::from_private_message(
            ciphertext,
            self.group.version(),
        ))
    }
}
