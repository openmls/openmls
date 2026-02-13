use openmls_traits::signatures::Signer;

use crate::storage::OpenMlsProvider;

#[cfg(feature = "virtual-clients-draft")]
use crate::tree::secret_tree::SecretType;

use super::{errors::CreateMessageError, *};

#[cfg(feature = "virtual-clients-draft")]
type CreateMessageReturn = (u32, MlsMessageOut);
#[cfg(not(feature = "virtual-clients-draft"))]
type CreateMessageReturn = MlsMessageOut;

impl MlsGroup {
    // === Application messages ===

    /// Creates an application message. Returns
    /// `CreateMessageError::MlsGroupStateError::UseAfterEviction` if the member
    /// is no longer part of the group. Returns
    /// `CreateMessageError::MlsGroupStateError::PendingProposal` if pending
    /// proposals exist. In that case `.process_pending_proposals()` must be
    /// called first and incoming messages from the DS must be processed
    /// afterwards.
    pub fn create_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        message: &[u8],
    ) -> Result<MlsMessageOut, CreateMessageError<Provider::StorageError>> {
        let output = self.create_message_internal(
            provider,
            signer,
            message,
            #[cfg(feature = "virtual-clients-draft")]
            true,
        )?;
        #[cfg(feature = "virtual-clients-draft")]
        let output = output.1;
        Ok(output)
    }

    fn create_message_internal<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        message: &[u8],
        #[cfg(feature = "virtual-clients-draft")] confirm: bool,
    ) -> Result<CreateMessageReturn, CreateMessageError<Provider::StorageError>> {
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

        let authenticated_content = AuthenticatedContent::new_application(
            self.own_leaf_index(),
            &self.aad,
            message,
            self.context(),
            signer,
        )?;
        let ciphertext = self
            .encrypt(authenticated_content, provider)
            // We know the application message is wellformed and we have the key material of the current epoch
            .map_err(|_| LibraryError::custom("Malformed plaintext"))?;

        #[cfg(feature = "virtual-clients-draft")]
        let (generation, ciphertext) = {
            if confirm {
                self.confirm_message(provider.storage(), ciphertext.0)?;
            }
            (ciphertext.0, ciphertext.1)
        };

        let output = MlsMessageOut::from_private_message(ciphertext, self.version());

        #[cfg(feature = "virtual-clients-draft")]
        let output = (generation, output);

        self.reset_aad();

        Ok(output)
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
        self.create_message_internal(provider, signer, message, false)
    }

    /// Confirms that a message has been successfully sent without a generation
    /// collision. This deletes the encryption secrets for the given generation.
    #[cfg(feature = "virtual-clients-draft")]
    pub fn confirm_message<Storage: StorageProvider>(
        &mut self,
        storage: &Storage,
        generation: u32,
    ) -> Result<(), CreateMessageError<Storage::Error>> {
        // For now we only support application secrets.
        let secret_type = SecretType::ApplicationSecret;
        self.message_secrets_store
            .message_secrets_mut()
            .secret_tree_mut()
            .delete_own_secret_for_generation(secret_type, generation)
            .map_err(MessageEncryptionError::SecretTreeError)?;
        storage
            .write_message_secrets(self.group_id(), &self.message_secrets_store)
            .map_err(CreateMessageError::StorageError)?;
        Ok(())
    }
}
