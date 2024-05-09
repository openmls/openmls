use core_group::proposals::QueuedProposal;

use crate::{
    framing::{
        mls_auth_content_in::VerifiableAuthenticatedContentIn, mls_content::FramedContentBody,
    },
    group::{
        errors::{MergeCommitError, StageCommitError, ValidationError},
        mls_group::errors::ProcessMessageError,
    },
};

use super::{proposals::ProposalStore, *};

impl CoreGroup {
    /// Helper function to read decryption keypairs.
    pub(crate) fn read_decryption_keypairs(
        &self,
        provider: &impl OpenMlsProvider,
        own_leaf_nodes: &[LeafNode],
    ) -> Result<(Vec<EncryptionKeyPair>, Vec<EncryptionKeyPair>), StageCommitError> {
        // All keys from the previous epoch are potential decryption keypairs.
        let old_epoch_keypairs = self.read_epoch_keypairs(provider.storage());

        // If we are processing an update proposal that originally came from
        // us, the keypair corresponding to the leaf in the update is also a
        // potential decryption keypair.
        let leaf_node_keypairs = own_leaf_nodes
            .iter()
            .map(|leaf_node| {
                EncryptionKeyPair::read(provider, leaf_node.encryption_key())
                    .ok_or(StageCommitError::MissingDecryptionKey)
            })
            .collect::<Result<Vec<EncryptionKeyPair>, StageCommitError>>()?;

        Ok((old_epoch_keypairs, leaf_node_keypairs))
    }

    /// Merge a [StagedCommit] into the group after inspection
    pub(crate) fn merge_staged_commit<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        staged_commit: StagedCommit,
        proposal_store: &mut ProposalStore,
    ) -> Result<(), MergeCommitError<Provider::StorageError>> {
        // Save the past epoch
        let past_epoch = self.context().epoch();
        // Get all the full leaves
        let leaves = self.public_group().members().collect();
        // Merge the staged commit into the group state and store the secret tree from the
        // previous epoch in the message secrets store.
        if let Some(message_secrets) = self.merge_commit(provider, staged_commit)? {
            self.message_secrets_store
                .add(past_epoch, message_secrets, leaves);
        }
        // Empty the proposal store
        proposal_store.empty();
        Ok(())
    }

    // FIXME: REMOVE. Just to make tests happy for now.
    pub(crate) fn decrypt_message(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        message: ProtocolMessage,
        sender_ratchet_configuration: &SenderRatchetConfiguration,
    ) -> Result<Message, ValidationError> {
        let epoch = message.epoch();

        // Checks the following semantic validation:
        //  - ValSem006
        //  - ValSem007 MembershipTag presence
        match message {
            ProtocolMessage::PublicMessage(public_message) => {
                // If the message is older than the current epoch, we need to fetch the correct secret tree first.
                let message_secrets =
                    self.message_secrets_for_epoch(epoch).map_err(|e| match e {
                        SecretTreeError::TooDistantInThePast => ValidationError::NoPastEpochData,
                        _ => LibraryError::custom(
                            "Unexpected error while retrieving message secrets for epoch.",
                        )
                        .into(),
                    })?;
                DecryptedMessage::from_inbound_public_message(
                    public_message,
                    message_secrets,
                    message_secrets.serialized_context().to_vec(),
                    crypto,
                    self.ciphersuite(),
                )
                .map(|tmp| Message {
                    verifiable_content: tmp.verifiable_content,
                })
            }
            ProtocolMessage::PrivateMessage(ciphertext) => {
                // If the message is older than the current epoch, we need to fetch the correct secret tree first
                DecryptedMessage::from_inbound_ciphertext(
                    ciphertext,
                    crypto,
                    self,
                    sender_ratchet_configuration,
                )
                .map(|tmp| Message {
                    verifiable_content: tmp.verifiable_content,
                })
            }
        }
    }
}

// === FIXME: DELETE - ONLY TO KEEP TESTS WORKING FOR NOW

struct DecryptedMessage {
    verifiable_content: VerifiableAuthenticatedContentIn,
}

impl DecryptedMessage {
    /// Constructs a [DecryptedMessage] from a [VerifiableAuthenticatedContent].
    pub(crate) fn from_inbound_public_message<'a>(
        public_message: PublicMessageIn,
        message_secrets_option: impl Into<Option<&'a MessageSecrets>>,
        serialized_context: Vec<u8>,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<Self, ValidationError> {
        if public_message.sender().is_member() {
            // ValSem007 Membership tag presence
            if public_message.membership_tag.is_none() {
                return Err(ValidationError::MissingMembershipTag);
            }

            if let Some(message_secrets) = message_secrets_option.into() {
                // Verify the membership tag. This needs to be done explicitly for PublicMessage messages,
                // it is implicit for PrivateMessage messages (because the encryption can only be known by members).
                // ValSem008
                public_message.verify_membership(
                    crypto,
                    ciphersuite,
                    message_secrets.membership_key(),
                    message_secrets.serialized_context(),
                )?;
            }
        }

        let verifiable_content = public_message.into_verifiable_content(serialized_context);

        Self::from_verifiable_content(verifiable_content)
    }

    /// Constructs a [DecryptedMessage] from a [PrivateMessage] by attempting to decrypt it
    /// to a [VerifiableAuthenticatedContent] first.
    pub(crate) fn from_inbound_ciphertext(
        ciphertext: PrivateMessageIn,
        crypto: &impl OpenMlsCrypto,
        group: &mut CoreGroup,
        sender_ratchet_configuration: &SenderRatchetConfiguration,
    ) -> Result<Self, ValidationError> {
        // This will be refactored with #265.
        let ciphersuite = group.ciphersuite();
        // TODO: #819 The old leaves should not be needed any more.
        //       Revisit when the transition is further along.
        let message_secrets = group
            .message_secrets_and_leaves_mut(ciphertext.epoch())
            .map_err(|_| MessageDecryptionError::AeadError)?;
        let sender_data = ciphertext.sender_data(message_secrets, crypto, ciphersuite)?;
        let message_secrets = group
            .message_secrets_mut(ciphertext.epoch())
            .map_err(|_| MessageDecryptionError::AeadError)?;
        let verifiable_content = ciphertext.decrypt_to_verifiable_content(
            ciphersuite,
            crypto,
            message_secrets,
            sender_data.leaf_index,
            sender_ratchet_configuration,
            sender_data,
        )?;
        Self::from_verifiable_content(verifiable_content)
    }

    // Internal constructor function. Does the following checks:
    // - Confirmation tag must be present for Commit messages
    // - Membership tag must be present for member messages, if the original incoming message was not an PrivateMessage
    // - Ensures application messages were originally PrivateMessage messages
    fn from_verifiable_content(
        verifiable_content: VerifiableAuthenticatedContentIn,
    ) -> Result<Self, ValidationError> {
        // ValSem009
        if verifiable_content.content_type() == ContentType::Commit
            && verifiable_content.confirmation_tag().is_none()
        {
            return Err(ValidationError::MissingConfirmationTag);
        }
        // ValSem005
        if verifiable_content.content_type() == ContentType::Application {
            if verifiable_content.wire_format() != WireFormat::PrivateMessage {
                return Err(ValidationError::UnencryptedApplicationMessage);
            } else if !verifiable_content.sender().is_member() {
                // This should not happen because the sender of an PrivateMessage should always be a member
                return Err(LibraryError::custom("Expected sender to be member.").into());
            }
        }
        Ok(DecryptedMessage { verifiable_content })
    }
}
