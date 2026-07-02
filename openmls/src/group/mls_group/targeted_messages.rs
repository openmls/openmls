use openmls_traits::signatures::Signer;

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    framing::MlsMessageOut,
    storage::OpenMlsProvider,
    targeted_messages::{
        self, CreateTargetedMessageError, ProcessTargetedMessageError, ProcessedTargetedMessage,
        TargetedMessageGroupContext, TargetedMessageIn,
    },
};

use super::*;

impl MlsGroup {
    /// Creates a targeted message for a specific group member. The
    /// `application_data` payload is encrypted to the recipient's leaf
    /// encryption key. The sender is authenticated via signature.
    /// `padding_length` is the number of zero bytes appended to the plaintext
    /// before encryption to obscure the application data length. Pass `0` for
    /// no padding.
    pub fn create_targeted_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        recipient_leaf_index: LeafNodeIndex,
        application_data: &[u8],
        padding_length: usize,
    ) -> Result<MlsMessageOut, CreateTargetedMessageError> {
        if !self.is_active() {
            return Err(CreateTargetedMessageError::GroupNotActive);
        }

        let targeted_msg = {
            let recipient_leaf = self
                .public_group()
                .leaf(recipient_leaf_index)
                .ok_or(CreateTargetedMessageError::RecipientNotFound)?;
            let recipient_encryption_key = recipient_leaf.encryption_key();

            let ctx = TargetedMessageGroupContext {
                ciphersuite: self.ciphersuite(),
                group_id: self.group_id(),
                epoch: self.context().epoch(),
                exporter_secret: self.group_epoch_secrets().exporter_secret(),
            };

            targeted_messages::create_targeted_message(
                provider.crypto(),
                signer,
                &ctx,
                self.own_leaf_index(),
                recipient_leaf_index,
                recipient_encryption_key,
                &self.aad,
                application_data,
                padding_length,
            )?
        };
        self.reset_aad();
        Ok(targeted_msg.into())
    }

    /// Processes a received targeted message. Decrypts the message content and
    /// verifies the sender's signature. Returns the sender's leaf index and the
    /// decrypted application data.
    pub fn process_targeted_message<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        message: &TargetedMessageIn,
    ) -> Result<ProcessedTargetedMessage, ProcessTargetedMessageError<Provider::StorageError>> {
        if !self.is_active() {
            return Err(ProcessTargetedMessageError::GroupNotActive);
        }

        let own_leaf = self
            .public_group()
            .leaf(self.own_leaf_index())
            .ok_or_else(|| LibraryError::custom("Own leaf node not found in tree"))?;

        let own_encryption_key = own_leaf.encryption_key();

        let epoch_keypairs = self
            .read_epoch_keypairs(provider.storage())
            .map_err(ProcessTargetedMessageError::StorageError)?;

        let own_keypair = epoch_keypairs
            .iter()
            .find(|kp| kp.public_key() == own_encryption_key)
            .ok_or_else(|| LibraryError::custom("Own encryption private key not found"))?;

        let leaves = self.public_group().treesync().leaves();

        let ctx = TargetedMessageGroupContext {
            ciphersuite: self.ciphersuite(),
            group_id: self.group_id(),
            epoch: self.context().epoch(),
            exporter_secret: self.group_epoch_secrets().exporter_secret(),
        };

        targeted_messages::process_targeted_message(
            provider.crypto(),
            &ctx,
            self.own_leaf_index(),
            own_keypair.private_key(),
            message,
            &leaves,
        )
    }
}
