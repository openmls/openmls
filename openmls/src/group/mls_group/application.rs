use openmls_traits::signatures::Signer;

use crate::storage::OpenMlsProvider;

#[cfg(feature = "virtual-clients-draft")]
use crate::tree::secret_tree::SecretType;

#[cfg(feature = "virtual-clients-draft")]
use super::errors::ConfirmMessageError;
use super::{errors::CreateMessageError, *};

/// The result of [`MlsGroup::create_unconfirmed_message`]: the encrypted
/// message together with the bookkeeping a virtual client needs to coordinate
/// the send with the DS.
#[cfg(feature = "virtual-clients-draft")]
#[derive(Debug, Clone)]
pub struct UnconfirmedMessage {
    /// The encrypted application message to fan out.
    pub message: MlsMessageOut,
    /// The epoch the message was encrypted in. Pass it together with
    /// `generation` to [`MlsGroup::confirm_message`] once the DS has accepted
    /// the message, to delete the retained encryption secret.
    pub epoch: GroupEpoch,
    /// The ratchet generation used for encryption. Pass it together with
    /// `epoch` to [`MlsGroup::confirm_message`] once the DS has accepted the
    /// message, to delete the retained encryption secret.
    pub generation: u32,
    /// The [`GenerationId`] to attach to the fanned-out message, present when
    /// the group is bound to an emulation epoch and `None` otherwise. A
    /// strongly-consistent DS compares it across siblings to detect generation
    /// collisions.
    ///
    /// [`GenerationId`]: crate::components::vc_derivation_info::GenerationId
    pub generation_id: Option<crate::components::vc_derivation_info::GenerationId>,
}

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
    #[cfg(all(feature = "virtual-clients-draft", any(feature = "test-utils", test)))]
    pub fn create_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        message: &[u8],
    ) -> Result<MlsMessageOut, CreateMessageError<Provider::StorageError>> {
        let (generation, _generation_id, output) =
            self.create_message_internal(provider, signer, message)?;
        self.confirm_message(provider.storage(), self.epoch(), generation)?;
        Ok(output)
    }

    #[cfg(not(feature = "virtual-clients-draft"))]
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

        let aad = self.outgoing_authenticated_data()?;
        let authenticated_content = AuthenticatedContent::new_application(
            self.own_leaf_index(),
            &aad,
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

    #[cfg(feature = "virtual-clients-draft")]
    fn create_message_internal<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        message: &[u8],
    ) -> Result<
        (
            u32,
            Option<crate::components::vc_derivation_info::GenerationId>,
            MlsMessageOut,
        ),
        CreateMessageError<Provider::StorageError>,
    > {
        if !self.is_active() {
            return Err(MlsGroupStateError::UseAfterEviction.into());
        }
        if !self.proposal_store().is_empty() {
            return Err(MlsGroupStateError::PendingProposal.into());
        }

        let aad = self.outgoing_authenticated_data()?;
        let authenticated_content = AuthenticatedContent::new_application(
            self.own_leaf_index(),
            &aad,
            message,
            self.context(),
            signer,
        )?;
        let EncryptionOutput {
            generation,
            private_message,
            generation_id,
        } = self.encrypt(authenticated_content, provider)?;

        let output = MlsMessageOut::from_private_message(private_message, self.version());
        self.reset_aad();
        Ok((generation, generation_id, output))
    }

    /// Creates an application message. Encryption secrets are only deleted
    /// after the message has been confirmed via `confirm_message()`.
    ///
    /// Returns the ratchet `generation` used for encryption, an optional
    /// [`GenerationId`], and the encrypted message. The `generation` is passed
    /// back to `confirm_message` to delete the retained encryption secret once
    /// the DS has accepted the message. The [`GenerationId`] is present when
    /// the group is bound to an emulation epoch and `None` otherwise. When
    /// present, the application attaches it to the fanned-out message so a
    /// strongly-consistent DS can detect generation collisions between
    /// siblings.
    ///
    /// Returns `CreateMessageError::MlsGroupStateError::UseAfterEviction` if
    /// the member is no longer part of the group. Returns
    /// `CreateMessageError::MlsGroupStateError::PendingProposal` if pending
    /// proposals exist. In that case `.process_pending_proposals()` must be
    /// called first and incoming messages from the DS must be processed
    /// afterwards.
    ///
    /// [`GenerationId`]: crate::components::vc_derivation_info::GenerationId
    #[cfg(feature = "virtual-clients-draft")]
    pub fn create_unconfirmed_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        message: &[u8],
    ) -> Result<UnconfirmedMessage, CreateMessageError<Provider::StorageError>> {
        let (generation, generation_id, message) =
            self.create_message_internal(provider, signer, message)?;
        Ok(UnconfirmedMessage {
            message,
            epoch: self.epoch(),
            generation,
            generation_id,
        })
    }

    /// Deletes the retained own secret of the given `secret_type` created at
    /// (`epoch`, `generation`). A confirm call deletes exactly the secret its
    /// corresponding create call retained, or nothing.
    #[cfg(feature = "virtual-clients-draft")]
    fn confirm_own_secret<Storage: StorageProvider>(
        &mut self,
        storage: &Storage,
        epoch: GroupEpoch,
        generation: u32,
        secret_type: SecretType,
    ) -> Result<(), ConfirmMessageError<Storage::Error>> {
        // Dispatch on the creation epoch directly rather than through
        // `message_secrets_for_epoch_mut`, which maps future epochs to the
        // current tree and would delete a different message's secret.
        let message_secrets = if epoch > self.context().epoch() {
            return Err(ConfirmMessageError::FutureEpoch);
        } else if epoch == self.context().epoch() {
            self.message_secrets_store.message_secrets_mut()
        } else {
            // The retained secret is already gone once its epoch has aged out
            // of the store, so there is nothing left to delete.
            let Some(message_secrets) = self.message_secrets_store.secrets_for_epoch_mut(epoch)
            else {
                return Ok(());
            };
            message_secrets
        };
        message_secrets
            .secret_tree_mut()
            .delete_own_secret_for_generation(secret_type, generation)?;
        storage
            .write_message_secrets(self.group_id(), &self.message_secrets_store)
            .map_err(ConfirmMessageError::StorageError)?;
        Ok(())
    }

    /// Deletes the retained encryption secret of the application message created
    /// at (`epoch`, `generation`). A confirm call deletes exactly the secret its
    /// corresponding [`MlsGroup::create_unconfirmed_message`] call retained, or
    /// nothing.
    ///
    /// This is a no-op success when the epoch has aged out of the message
    /// secrets store, or when the generation's secret is already gone (already
    /// confirmed, or consumed by processing the message's own echo).
    ///
    /// Returns [`ConfirmMessageError::FutureEpoch`] when `epoch` is newer than
    /// the group's current epoch.
    ///
    /// Only confirm once the DS has accepted exactly this message. After a lost
    /// race against a sibling (the DS rejected the send because of a generation
    /// collision), the secret must not be confirmed, since it is what decrypts
    /// the sibling's winning message at the same generation.
    #[cfg(feature = "virtual-clients-draft")]
    pub fn confirm_message<Storage: StorageProvider>(
        &mut self,
        storage: &Storage,
        epoch: GroupEpoch,
        generation: u32,
    ) -> Result<(), ConfirmMessageError<Storage::Error>> {
        self.confirm_own_secret(storage, epoch, generation, SecretType::ApplicationSecret)
    }

    /// Deletes the retained encryption secret of the handshake message (proposal
    /// or commit) created at (`epoch`, `generation`). A confirm call deletes
    /// exactly the secret its corresponding create call retained, or nothing.
    ///
    /// Proposals and commits draw generations from the same per-epoch handshake
    /// ratchet, so this single endpoint covers both.
    ///
    /// This is a no-op success when the epoch has aged out of the message
    /// secrets store, or when the generation's secret is already gone (already
    /// confirmed, or consumed by processing the message's own echo).
    ///
    /// Returns [`ConfirmMessageError::FutureEpoch`] when `epoch` is newer than
    /// the group's current epoch.
    ///
    /// Only confirm once the DS has accepted exactly this message. After a lost
    /// race against a sibling (the DS rejected the send because of a generation
    /// collision), the secret must not be confirmed, since it is what decrypts
    /// the sibling's winning message at the same generation.
    #[cfg(feature = "virtual-clients-draft")]
    pub fn confirm_handshake_message<Storage: StorageProvider>(
        &mut self,
        storage: &Storage,
        epoch: GroupEpoch,
        generation: u32,
    ) -> Result<(), ConfirmMessageError<Storage::Error>> {
        self.confirm_own_secret(storage, epoch, generation, SecretType::HandshakeSecret)
    }
}
