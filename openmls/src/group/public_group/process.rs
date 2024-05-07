use tls_codec::Serialize;

use crate::{
    ciphersuite::OpenMlsSignaturePublicKey,
    credentials::CredentialWithKey,
    error::LibraryError,
    framing::{
        mls_content::FramedContentBody, ApplicationMessage, Message, ProcessedMessage,
        ProcessedMessageContent, ProtocolMessage, Sender, SenderContext, UnverifiedMessage,
    },
    group::{
        core_group::proposals::{ProposalStore, QueuedProposal},
        errors::ValidationError,
        mls_group::errors::ProcessMessageError,
        past_secrets::MessageSecretsStore,
    },
    messages::proposals::Proposal,
    storage::OpenMlsProvider,
};

use super::PublicGroup;

impl PublicGroup {
    /// This function is used to parse messages from the DS. It checks for
    /// syntactic errors and does semantic validation as well. It returns a
    /// [ProcessedMessage] enum.
    ///
    /// ProtocolMessage -> Message -> UnverifiedMessage -> ProcessedMessage
    pub fn process_message<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        message: impl Into<ProtocolMessage>,
    ) -> Result<ProcessedMessage, ProcessMessageError<Provider::StorageError>> {
        // Incoming protocol message.
        let message = message.into();

        self.validate_framing(&message)?;
        crate::validation::application_msg_is_always_private(&message)?;

        let message = match message {
            ProtocolMessage::PrivateMessage(_) => {
                return Err(ProcessMessageError::IncompatibleWireFormat)
            }
            ProtocolMessage::PublicMessage(public_message) => {
                let verifiable_content = public_message.into_verifiable_content(
                    self.group_context()
                        .tls_serialize_detached()
                        .map_err(LibraryError::missing_bound_check)?,
                );

                Message { verifiable_content }
            }
        };

        let message = self
            .parse_message(message, None)
            .map_err(ProcessMessageError::from)?;
        self.process_unverified_message(provider, message, &self.proposal_store)
    }
}

impl PublicGroup {
    /// This function is used to parse messages from the DS.
    /// It checks for syntactic errors and makes some semantic checks as well.
    /// If the input is a [PrivateMessage] message, it will be decrypted.
    /// Returns an [UnverifiedMessage] that can be inspected and later processed in
    /// [Self::process_unverified_message()].
    pub(crate) fn parse_message<'a>(
        &self,
        message: Message,
        message_secrets_store_option: impl Into<Option<&'a MessageSecretsStore>>,
    ) -> Result<UnverifiedMessage, ValidationError> {
        let message_secrets_store_option = message_secrets_store_option.into();

        // Extract the credential if the sender is a member or a new member.
        // External senders are not supported yet #106/#151.
        let CredentialWithKey {
            credential,
            signature_key,
        } = message.credential(
            self.treesync(),
            message_secrets_store_option
                .map(|store| store.leaves_for_epoch(message.verifiable_content().epoch()))
                .unwrap_or_default(),
            self.group_context().extensions().external_senders(),
        )?;
        let signature_public_key = OpenMlsSignaturePublicKey::from_signature_key(
            signature_key,
            self.ciphersuite().signature_algorithm(),
        );

        // For commit messages, we need to check if the sender is a member or a
        // new member and set the tree position accordingly.
        let sender_context = match message.sender() {
            Sender::Member(leaf_index) => Some(SenderContext::Member((
                self.group_id().clone(),
                *leaf_index,
            ))),
            Sender::NewMemberCommit => Some(SenderContext::ExternalCommit((
                self.group_id().clone(),
                self.treesync().free_leaf_index(),
            ))),
            Sender::External(_) | Sender::NewMemberProposal => None,
        };

        Ok(UnverifiedMessage::from_message(
            message,
            credential,
            signature_public_key,
            sender_context,
        ))
    }

    /// This processing function does most of the semantic verifications.
    /// It returns a [ProcessedMessage] enum.
    fn process_unverified_message<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        unverified_message: UnverifiedMessage,
        proposal_store: &ProposalStore,
    ) -> Result<ProcessedMessage, ProcessMessageError<Provider::StorageError>> {
        let crypto = provider.crypto();
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
                            crypto,
                            content,
                        )?);
                        if matches!(sender, Sender::NewMemberProposal) {
                            ProcessedMessageContent::ExternalJoinProposalMessage(proposal)
                        } else {
                            ProcessedMessageContent::ProposalMessage(proposal)
                        }
                    }
                    FramedContentBody::Commit(_) => {
                        let staged_commit = self.stage_commit(&content, proposal_store, crypto)?;
                        ProcessedMessageContent::StagedCommitMessage(Box::new(staged_commit))
                    }
                };

                Ok(ProcessedMessage::new(
                    self.group_id().clone(),
                    self.group_context().epoch(),
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
                                crypto,
                                content,
                            )?,
                        ));
                        Ok(ProcessedMessage::new(
                            self.group_id().clone(),
                            self.group_context().epoch(),
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
}
