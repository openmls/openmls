use core_group::proposals::QueuedProposal;

use crate::{
    framing::mls_content::FramedContentBody,
    group::{
        errors::{MergeCommitError, StageCommitError, ValidationError},
        mls_group::errors::ProcessMessageError,
    },
};

use super::{proposals::ProposalStore, *};

impl CoreGroup {
    /// This processing function does most of the semantic verifications.
    /// It returns a [ProcessedMessage] enum.
    fn process_unverified_message<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        unverified_message: UnverifiedMessage,
        proposal_store: &ProposalStore,
        old_epoch_keypairs: Vec<EncryptionKeyPair>,
        leaf_node_keypairs: Vec<EncryptionKeyPair>,
    ) -> Result<ProcessedMessage, ProcessMessageError<Provider::StorageError>> {
        // Checks the following semantic validation:
        //  - ValSem010
        //  - ValSem246 (as part of ValSem010)
        let (content, credential) =
            unverified_message.verify(self.ciphersuite(), provider, self.version())?;

        match content.sender() {
            Sender::Member(_) | Sender::NewMemberCommit | Sender::NewMemberProposal => {
                let sender = content.sender().clone();
                let authenticated_data = content.authenticated_data().to_owned();

                let content = match content.content() {
                    FramedContentBody::Application(application_message) => {
                        ProcessedMessageContent::ApplicationMessage(ApplicationMessage::new(
                            application_message.as_slice().to_owned(),
                        ))
                    }
                    FramedContentBody::Proposal(_) => {
                        let proposal = Box::new(QueuedProposal::from_authenticated_content_by_ref(
                            self.ciphersuite(),
                            provider.crypto(),
                            content,
                        )?);

                        if matches!(sender, Sender::NewMemberProposal) {
                            ProcessedMessageContent::ExternalJoinProposalMessage(proposal)
                        } else {
                            ProcessedMessageContent::ProposalMessage(proposal)
                        }
                    }
                    FramedContentBody::Commit(_) => {
                        let staged_commit = self.stage_commit(
                            &content,
                            proposal_store,
                            old_epoch_keypairs,
                            leaf_node_keypairs,
                            provider,
                        )?;
                        ProcessedMessageContent::StagedCommitMessage(Box::new(staged_commit))
                    }
                };

                Ok(ProcessedMessage::new(
                    self.group_id().clone(),
                    self.context().epoch(),
                    sender,
                    authenticated_data,
                    content,
                    credential,
                ))
            }
            Sender::External(_) => {
                let sender = content.sender().clone();
                let data = content.authenticated_data().to_owned();
                match content.content() {
                    FramedContentBody::Application(_) => {
                        Err(ProcessMessageError::UnauthorizedExternalApplicationMessage)
                    }
                    FramedContentBody::Proposal(Proposal::Remove(_)) => {
                        let content = ProcessedMessageContent::ProposalMessage(Box::new(
                            QueuedProposal::from_authenticated_content_by_ref(
                                self.ciphersuite(),
                                provider.crypto(),
                                content,
                            )?,
                        ));
                        Ok(ProcessedMessage::new(
                            self.group_id().clone(),
                            self.context().epoch(),
                            sender,
                            data,
                            content,
                            credential,
                        ))
                    }
                    // TODO #151/#106
                    FramedContentBody::Proposal(_) => {
                        Err(ProcessMessageError::UnsupportedProposalType)
                    }
                    FramedContentBody::Commit(_) => unimplemented!(),
                }
            }
        }
    }

    /// This function is used to parse messages from the DS. It checks for
    /// syntactic errors and does semantic validation as well. If the input is a
    /// [PrivateMessage] message, it will be decrypted. It returns a
    /// [ProcessedMessage] enum.
    ///
    /// ProtocolMessage -> Message -> UnverifiedMessage -> ProcessedMessage
    pub(crate) fn process_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        message: impl Into<ProtocolMessage>,
        sender_ratchet_configuration: &SenderRatchetConfiguration,
        proposal_store: &ProposalStore,
        own_leaf_nodes: &[LeafNode],
    ) -> Result<ProcessedMessage, ProcessMessageError<Provider::StorageError>> {
        let message: ProtocolMessage = message.into();
        self.public_group.validate_framing(&message)?;

        let message = self.message_from_protocol_message(
            provider.crypto(),
            message,
            sender_ratchet_configuration,
        )?;

        let unverified_message = self
            .public_group
            .parse_message(message, &self.message_secrets_store)
            .map_err(ProcessMessageError::from)?;

        // If this is a commit, we need to load the private key material we need for decryption.
        let (old_epoch_keypairs, leaf_node_keypairs) =
            if let ContentType::Commit = unverified_message.content_type() {
                self.read_decryption_keypairs(provider, own_leaf_nodes)?
            } else {
                (vec![], vec![])
            };

        self.process_unverified_message(
            provider,
            unverified_message,
            proposal_store,
            old_epoch_keypairs,
            leaf_node_keypairs,
        )
    }

    /// Performs framing validation and, if necessary, decrypts the given message.
    ///
    /// Returns the [`DecryptedMessage`] if processing is successful, or a
    /// [`ValidationError`] if it is not.
    pub(crate) fn message_from_protocol_message(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        message: ProtocolMessage,
        sender_ratchet_configuration: &SenderRatchetConfiguration,
    ) -> Result<Message, ValidationError> {
        let epoch = message.epoch();

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

                if public_message.sender().is_member() {
                    // Verify the membership tag. This needs to be done explicitly for PublicMessage messages,
                    // it is implicit for PrivateMessage messages (because the encryption can only be known by members).
                    public_message.verify_membership(
                        crypto,
                        self.ciphersuite(),
                        message_secrets.membership_key(),
                        message_secrets.serialized_context(),
                    )?;
                }

                let verifiable_content = public_message
                    .into_verifiable_content(message_secrets.serialized_context().to_vec());

                Ok(Message { verifiable_content })
            }
            ProtocolMessage::PrivateMessage(ciphertext) => {
                // If the message is older than the current epoch, we need to fetch the correct secret tree first
                let ciphersuite = self.ciphersuite();
                let message_secrets = self
                    .message_secrets_and_leaves_mut(ciphertext.epoch())
                    .map_err(|_| MessageDecryptionError::AeadError)?;
                let sender_data = ciphertext.sender_data(message_secrets, crypto, ciphersuite)?;
                let message_secrets = self
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

                Ok(Message { verifiable_content })
            }
        }
    }

    /// Helper function to read decryption keypairs.
    pub(super) fn read_decryption_keypairs(
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
}
