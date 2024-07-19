use openmls_traits::signatures::Signer;

use crate::storage::OpenMlsProvider;

use super::{errors::CreateMessageError, *};

impl MlsGroup {
    // === Application messages ===

    /// Creates an application message.
    /// Returns `CreateMessageError::MlsGroupStateError::UseAfterEviction`
    /// if the member is no longer part of the group.
    /// Returns `CreateMessageError::MlsGroupStateError::PendingProposal` if pending proposals
    /// exist. In that case `.process_pending_proposals()` must be called first
    /// and incoming messages from the DS must be processed afterwards.
    pub fn create_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        message: &[u8],
    ) -> Result<MlsMessageOut, CreateMessageError<Provider::StorageError>> {
        if !self.is_active() {
            return Err(CreateMessageError::GroupStateError(
                MlsGroupStateError::UseAfterEviction,
            ));
        }
        if !self.proposal_store().is_empty() {
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

        self.reset_aad();
        Ok(MlsMessageOut::from_private_message(
            ciphertext,
            self.group.version(),
        ))
    }
}
