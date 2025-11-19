//! This module contains the implementation of the processing functions for
//! public groups.

use openmls_traits::crypto::OpenMlsCrypto;
use tls_codec::Serialize;

use crate::{
    ciphersuite::OpenMlsSignaturePublicKey,
    credentials::CredentialWithKey,
    error::LibraryError,
    framing::{
        mls_content::FramedContentBody, ApplicationMessage, DecryptedMessage, ProcessedMessage,
        ProcessedMessageContent, ProtocolMessage, Sender, SenderContext, UnverifiedMessage,
    },
    group::{
        errors::ValidationError, past_secrets::MessageSecretsStore, proposal_store::QueuedProposal,
        PublicProcessMessageError,
    },
    messages::proposals::Proposal,
};

#[cfg(feature = "extensions-draft-08")]
use crate::extensions::ComponentData;

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
        let verifiable_content = decrypted_message.verifiable_content();

        // Checks the following semantic validation:
        //  - ValSem004
        //  - ValSem005
        //  - ValSem009
        self.validate_verifiable_content(verifiable_content, message_secrets_store_option)?;

        let message_epoch = verifiable_content.epoch();

        // Depending on the epoch of the message, use the correct set of leaf nodes for getting the
        // credential and signature key for the member with given index.
        let look_up_credential_with_key = |leaf_node_index| {
            if message_epoch == self.group_context().epoch() {
                self.treesync()
                    .leaf(leaf_node_index)
                    .map(CredentialWithKey::from)
            } else if let Some(store) = message_secrets_store_option {
                store
                    .leaves_for_epoch(message_epoch)
                    .get(leaf_node_index.u32() as usize)
                    .map(CredentialWithKey::from)
            } else {
                None
            }
        };

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
            look_up_credential_with_key,
            self.group_context().extensions().external_senders(),
        )?;
        let signature_public_key = OpenMlsSignaturePublicKey::from_signature_key(
            signature_key,
            self.ciphersuite().signature_algorithm(),
        );

        // For commit messages, we need to check if the sender is a member or a
        // new member and set the tree position accordingly.
        let sender_context = match decrypted_message.sender() {
            Sender::Member(leaf_index) => Some(SenderContext::Member((
                self.group_id().clone(),
                *leaf_index,
            ))),
            Sender::NewMemberCommit => Some(SenderContext::ExternalCommit {
                group_id: self.group_id().clone(),
                leftmost_blank_index: self.treesync().free_leaf_index(),
                self_removes_in_store: self.proposal_store.self_removes(),
            }),
            Sender::External(_) | Sender::NewMemberProposal => None,
        };

        Ok(UnverifiedMessage::from_decrypted_message(
            decrypted_message,
            credential,
            signature_public_key,
            sender_context,
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
    ///    private keys from the direct path
    ///  - ValSem205
    ///  - ValSem240
    ///  - ValSem241
    ///  - ValSem242
    ///  - ValSem244
    ///  - ValSem245
    ///  - ValSem246 (as part of ValSem010)
    pub fn process_message(
        &self,
        crypto: &impl OpenMlsCrypto,
        message: impl Into<ProtocolMessage>,
    ) -> Result<ProcessedMessage, PublicProcessMessageError> {
        let protocol_message = message.into();
        // Checks the following semantic validation:
        //  - ValSem002
        //  - ValSem003
        self.validate_framing(&protocol_message)?;

        let decrypted_message = match protocol_message {
            ProtocolMessage::PrivateMessage(_) => {
                return Err(PublicProcessMessageError::IncompatibleWireFormat)
            }
            ProtocolMessage::PublicMessage(public_message) => {
                DecryptedMessage::from_inbound_public_message(
                    *public_message,
                    None,
                    self.group_context()
                        .tls_serialize_detached()
                        .map_err(LibraryError::missing_bound_check)?,
                    crypto,
                    self.ciphersuite(),
                )?
            }
        };

        let unverified_message = self
            .parse_message(decrypted_message, None)
            .map_err(PublicProcessMessageError::from)?;
        self.process_unverified_message(
            crypto,
            unverified_message,
            #[cfg(feature = "extensions-draft-08")]
            None,
        )
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
    ///    private keys from the direct path
    ///  - ValSem205
    ///  - ValSem240
    ///  - ValSem241
    ///  - ValSem242
    ///  - ValSem244
    ///  - ValSem246 (as part of ValSem010)
    pub(crate) fn process_unverified_message(
        &self,
        crypto: &impl OpenMlsCrypto,
        unverified_message: UnverifiedMessage,
        #[cfg(feature = "extensions-draft-08")] app_data_dict_updates: Option<Vec<ComponentData>>,
    ) -> Result<ProcessedMessage, PublicProcessMessageError> {
        // Checks the following semantic validation:
        //  - ValSem010
        //  - ValSem246 (as part of ValSem010)
        //  - https://validation.openmls.tech/#valn1203
        let (content, credential) =
            unverified_message.verify(self.ciphersuite(), crypto, self.version())?;

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
                        let staged_commit = self.stage_commit(
                            &content,
                            crypto,
                            #[cfg(feature = "extensions-draft-08")]
                            app_data_dict_updates,
                        )?;
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
                // https://validation.openmls.tech/#valn1501
                match content.content() {
                    FramedContentBody::Application(_) => {
                        Err(PublicProcessMessageError::UnauthorizedExternalApplicationMessage)
                    }
                    // TODO: https://validation.openmls.tech/#valn1502
                    FramedContentBody::Proposal(Proposal::GroupContextExtensions(_)) => {
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
                    FramedContentBody::Proposal(Proposal::Add(_)) => {
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
                        Err(PublicProcessMessageError::UnsupportedProposalType)
                    }
                    FramedContentBody::Commit(_) => {
                        Err(PublicProcessMessageError::UnauthorizedExternalCommitMessage)
                    }
                }
            }
        }
    }
}
