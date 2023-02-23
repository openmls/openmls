use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::Serialize;

use crate::{
    ciphersuite::OpenMlsSignaturePublicKey,
    credentials::CredentialWithKey,
    error::LibraryError,
    framing::{
        mls_content::FramedContentBody, ApplicationMessage, DecryptedMessage, ProcessedMessage,
        ProcessedMessageContent, ProtocolMessage, Sender, UnverifiedMessage,
    },
    group::{
        core_group::proposals::{ProposalStore, QueuedProposal},
        errors::ValidationError,
        mls_group::errors::ProcessMessageError,
        past_secrets::MessageSecretsStore,
    },
    messages::proposals::Proposal,
};

use super::PublicGroup;

impl PublicGroup {
    /// This function is used to parse messages from the DS.
    /// It checks for syntactic errors and makes some semantic checks as well.
    /// If the input is a [PrivateMessage] message, it will be decrypted.
    /// Returns an [UnverifiedMessage] that can be inspected and later processed in
    /// [Self::process_unverified_message()].
    /// Checks the following semantic validation:
    ///  - ValSem002
    ///  - ValSem003
    ///  - ValSem004
    ///  - ValSem005
    ///  - ValSem006
    ///  - ValSem007
    ///  - ValSem009
    ///  - ValSem112
    ///  - ValSem245
    pub(crate) fn parse_message<'a>(
        &self,
        decrypted_message: DecryptedMessage,
        message_secrets_store_option: impl Into<Option<&'a MessageSecretsStore>>,
    ) -> Result<UnverifiedMessage, ValidationError> {
        let message_secrets_store_option = message_secrets_store_option.into();
        // Checks the following semantic validation:
        //  - ValSem004
        //  - ValSem005
        //  - ValSem009
        self.validate_verifiable_content(
            decrypted_message.verifiable_content(),
            message_secrets_store_option,
        )?;

        // Extract the credential if the sender is a member or a new member.
        // Checks the following semantic validation:
        //  - ValSem112
        //  - ValSem245
        //  - Prepares ValSem246 by setting the right credential. The remainder
        //    of ValSem246 is validated as part of ValSem010.
        // External senders are not supported yet #106/#151.
        let CredentialWithKey {
            credential,
            signature_key,
        } = decrypted_message.credential(
            self.treesync(),
            message_secrets_store_option
                .map(|store| store.leaves_for_epoch(decrypted_message.verifiable_content().epoch()))
                .unwrap_or_default(),
            self.group_context().extensions().external_senders(),
        )?;
        let pk = OpenMlsSignaturePublicKey::from_signature_key(
            signature_key,
            self.ciphersuite().signature_algorithm(),
        );

        Ok(UnverifiedMessage::from_decrypted_message(
            decrypted_message,
            credential,
            pk,
        ))
    }

    /// This function is used to parse messages from the DS. It checks for
    /// syntactic errors and does semantic validation as well. It returns a
    /// [ProcessedMessage] enum. Checks the following semantic validation:
    ///  - ValSem002
    ///  - ValSem003
    ///  - ValSem004
    ///  - ValSem005
    ///  - ValSem006
    ///  - ValSem007
    ///  - ValSem008
    ///  - ValSem009
    ///  - ValSem010
    ///  - ValSem101
    ///  - ValSem102
    ///  - ValSem104
    ///  - ValSem106
    ///  - ValSem107
    ///  - ValSem108
    ///  - ValSem110
    ///  - ValSem111
    ///  - ValSem112
    ///  - ValSem200
    ///  - ValSem201
    ///  - ValSem202: Path must be the right length
    ///  - ValSem203: Path secrets must decrypt correctly
    ///  - ValSem204: Public keys from Path must be verified and match the
    ///               private keys from the direct path
    ///  - ValSem205
    ///  - ValSem240
    ///  - ValSem241
    ///  - ValSem242
    ///  - ValSem243
    ///  - ValSem244
    ///  - ValSem245
    ///  - ValSem246 (as part of ValSem010)
    pub fn process_message(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        message: impl Into<ProtocolMessage>,
    ) -> Result<ProcessedMessage, ProcessMessageError> {
        let protocol_message = message.into();
        // Checks the following semantic validation:
        //  - ValSem002
        //  - ValSem003
        self.validate_framing(&protocol_message)?;

        let decrypted_message = match protocol_message {
            ProtocolMessage::PrivateMessage(_) => {
                return Err(ProcessMessageError::IncompatibleWireFormat)
            }
            ProtocolMessage::PublicMessage(public_message) => {
                DecryptedMessage::from_inbound_public_message(
                    public_message,
                    None,
                    self.group_context()
                        .tls_serialize_detached()
                        .map_err(LibraryError::missing_bound_check)?,
                    backend,
                )?
            }
        };

        let unverified_message = self
            .parse_message(decrypted_message, None)
            .map_err(ProcessMessageError::from)?;
        self.process_unverified_message(unverified_message, &self.proposal_store, backend)
    }
}

impl PublicGroup {
    /// This processing function does most of the semantic verifications.
    /// It returns a [ProcessedMessage] enum.
    /// Checks the following semantic validation:
    ///  - ValSem008
    ///  - ValSem010
    ///  - ValSem101
    ///  - ValSem102
    ///  - ValSem104
    ///  - ValSem106
    ///  - ValSem107
    ///  - ValSem108
    ///  - ValSem110
    ///  - ValSem111
    ///  - ValSem112
    ///  - ValSem200
    ///  - ValSem201
    ///  - ValSem202: Path must be the right length
    ///  - ValSem203: Path secrets must decrypt correctly
    ///  - ValSem204: Public keys from Path must be verified and match the
    ///               private keys from the direct path
    ///  - ValSem205
    ///  - ValSem240
    ///  - ValSem241
    ///  - ValSem242
    ///  - ValSem243
    ///  - ValSem244
    ///  - ValSem246 (as part of ValSem010)
    pub(crate) fn process_unverified_message(
        &self,
        unverified_message: UnverifiedMessage,
        proposal_store: &ProposalStore,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<ProcessedMessage, ProcessMessageError> {
        // Checks the following semantic validation:
        //  - ValSem010
        //  - ValSem246 (as part of ValSem010)
        let (content, credential) = unverified_message.verify(backend)?;

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
                        let proposal = Box::new(QueuedProposal::from_authenticated_content(
                            self.ciphersuite(),
                            backend,
                            content,
                        )?);
                        if matches!(sender, Sender::NewMemberProposal) {
                            ProcessedMessageContent::ExternalJoinProposalMessage(proposal)
                        } else {
                            ProcessedMessageContent::ProposalMessage(proposal)
                        }
                    }
                    FramedContentBody::Commit(_) => {
                        let staged_commit = self.stage_commit(&content, proposal_store, backend)?;
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
                            QueuedProposal::from_authenticated_content(
                                self.ciphersuite(),
                                backend,
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
