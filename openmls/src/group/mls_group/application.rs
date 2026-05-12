use openmls_traits::signatures::Signer;

use crate::storage::OpenMlsProvider;

#[cfg(feature = "virtual-clients-draft")]
use crate::tree::secret_tree::SecretType;

#[cfg(feature = "virtual-clients-draft")]
use super::errors::ConfirmMessageError;
use super::{errors::CreateMessageError, *};

impl MlsGroup {
    // === Application messages ===

    /// Creates an application message. Returns
    /// `CreateMessageError::MlsGroupStateError::UseAfterEviction` if the member
    /// is no longer part of the group. Returns
    /// `CreateMessageError::MlsGroupStateError::PendingProposal` if pending
    /// proposals exist. In that case `.process_pending_proposals()` must be
    /// called first and incoming messages from the DS must be processed
    /// afterwards.
    #[cfg(not(feature = "virtual-clients-draft"))]
    pub fn create_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        message: &[u8],
    ) -> Result<MlsMessageOut, CreateMessageError> {
        let (_, output) =
            self.create_message_internal::<_, CreateMessageError>(provider, signer, message)?;
        Ok(output)
    }

    /// Creates an application message. Returns
    /// `CreateMessageError::MlsGroupStateError::UseAfterEviction` if the member
    /// is no longer part of the group. Returns
    /// `CreateMessageError::MlsGroupStateError::PendingProposal` if pending
    /// proposals exist. In that case `.process_pending_proposals()` must be
    /// called first and incoming messages from the DS must be processed
    /// afterwards.
    #[cfg(feature = "virtual-clients-draft")]
    pub fn create_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        message: &[u8],
    ) -> Result<MlsMessageOut, CreateMessageError<Provider::StorageError>> {
        let (generation, output) = self
            .create_message_internal::<_, CreateMessageError<Provider::StorageError>>(
                provider, signer, message,
            )?;
        self.confirm_message(provider.storage(), generation)?;
        Ok(output)
    }

    fn create_message_internal<Provider: OpenMlsProvider, E>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        message: &[u8],
    ) -> Result<(u32, MlsMessageOut), E>
    where
        E: From<LibraryError> + From<MlsGroupStateError>,
    {
        if !self.is_active() {
            return Err(MlsGroupStateError::UseAfterEviction.into());
        }
        if !self.proposal_store().is_empty() {
            return Err(MlsGroupStateError::PendingProposal.into());
        }

        let authenticated_content = AuthenticatedContent::new_application(
            self.own_leaf_index(),
            &self.aad,
            message,
            self.context(),
            signer,
        )?;
        let EncryptionOutput {
            generation,
            private_message,
        } = self
            .encrypt(authenticated_content, provider)
            // We know the application message is wellformed and we have the key material of the current epoch
            .map_err(|_| LibraryError::custom("Malformed plaintext"))?;

        let output = MlsMessageOut::from_private_message(private_message, self.version());
        self.reset_aad();
        Ok((generation, output))
    }

    /// Creates an application message. Encryption secrets are only deleted
    /// after the message has been confirmed via `confirm_message()`.
    ///
    /// Returns `CreateMessageError::MlsGroupStateError::UseAfterEviction` if
    /// the member is no longer part of the group. Returns
    /// `CreateMessageError::MlsGroupStateError::PendingProposal` if pending
    /// proposals exist. In that case `.process_pending_proposals()` must be
    /// called first and incoming messages from the DS must be processed
    /// afterwards.
    #[cfg(feature = "virtual-clients-draft")]
    pub fn create_unconfirmed_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        message: &[u8],
    ) -> Result<(u32, MlsMessageOut), CreateMessageError<Provider::StorageError>> {
        self.create_message_internal(provider, signer, message)
    }

    /// Confirms that a message has been successfully sent without a generation
    /// collision. This deletes the encryption secrets for the given generation.
    #[cfg(feature = "virtual-clients-draft")]
    pub fn confirm_message<Storage: StorageProvider>(
        &mut self,
        storage: &Storage,
        generation: u32,
    ) -> Result<(), ConfirmMessageError<Storage::Error>> {
        // For now we only support application secrets.
        let secret_type = SecretType::ApplicationSecret;
        self.message_secrets_store
            .message_secrets_mut()
            .secret_tree_mut()
            .delete_own_secret_for_generation(secret_type, generation)?;
        storage
            .write_message_secrets(self.group_id(), &self.message_secrets_store)
            .map_err(ConfirmMessageError::StorageError)?;
        Ok(())
    }
}
