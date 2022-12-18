use core_group::{proposals::QueuedProposal, staged_commit::StagedCommit};

use crate::{
    group::{errors::ValidationError, mls_group::errors::ProcessMessageError},
    treesync::node::leaf_node::OpenMlsLeafNode,
};

use super::{proposals::ProposalStore, *};

impl CoreGroup {
    /// This function is used to parse messages from the DS.
    /// It checks for syntactic errors and makes some semantic checks as well.
    /// If the input is a [MlsCiphertext] message, it will be decrypted.
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
    pub(crate) fn parse_message(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        message: MlsMessageIn,
        sender_ratchet_configuration: &SenderRatchetConfiguration,
    ) -> Result<UnverifiedMessage, ValidationError> {
        // Checks the following semantic validation:
        //  - ValSem002
        //  - ValSem003
        self.validate_framing(&message)?;

        // Checks the following semantic validation:
        //  - ValSem006
        let decrypted_message = match message.wire_format() {
            WireFormat::MlsPlaintext => DecryptedMessage::from_inbound_plaintext(message)?,
            WireFormat::MlsCiphertext => {
                // If the message is older than the current epoch, we need to fetch the correct secret tree first
                DecryptedMessage::from_inbound_ciphertext(
                    message,
                    backend,
                    self,
                    sender_ratchet_configuration,
                )?
            }
        };

        // Checks the following semantic validation:
        //  - ValSem004
        //  - ValSem005
        //  - ValSem007
        //  - ValSem009
        self.validate_plaintext(decrypted_message.plaintext())?;

        // Extract the credential if the sender is a member or a new member.
        // Checks the following semantic validation:
        //  - ValSem112
        //  - ValSem245
        //  - Prepares ValSem246 by setting the right credential. The remainder
        //    of ValSem246 is validated as part of ValSem010.
        // External senders are not supported yet #106/#151.
        let credential = decrypted_message.credential(
            self.treesync(),
            self.message_secrets_store
                .leaves_for_epoch(decrypted_message.plaintext().epoch()),
        )?;

        Ok(UnverifiedMessage::from_decrypted_message(
            decrypted_message,
            Some(credential),
        ))
    }

    /// This processing function does most of the semantic verifications.
    /// It returns a [ProcessedMessage] enum.
    /// Checks the following semantic validation:
    ///  - ValSem008
    ///  - ValSem010
    ///  - ValSem100
    ///  - ValSem101
    ///  - ValSem102
    ///  - ValSem103
    ///  - ValSem104
    ///  - ValSem105
    ///  - ValSem106
    ///  - ValSem107
    ///  - ValSem108
    ///  - ValSem109
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
        own_leaf_nodes: &[OpenMlsLeafNode],
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<ProcessedMessage, ProcessMessageError> {
        // Add the context to the message and verify the membership tag if necessary.
        // If the message is older than the current epoch, we need to fetch the correct secret tree first.
        let message_secrets = self
            .message_secrets_for_epoch(unverified_message.epoch())
            .map_err(|e| match e {
                SecretTreeError::TooDistantInThePast => ProcessMessageError::NoPastEpochData,
                _ => LibraryError::custom("Unexpected return value").into(),
            })?;

        // Checks the following semantic validation:
        //  - ValSem008
        let context_plaintext = UnverifiedContextMessage::from_unverified_message(
            unverified_message,
            message_secrets,
            backend,
        )
        .map_err(|_| ProcessMessageError::InvalidMembershipTag)?;

        let group_id = self.group_id().clone();
        let epoch = self.group_context.epoch();

        match context_plaintext {
            UnverifiedContextMessage::Group(unverified_message) => {
                let credential = unverified_message.credential().clone();
                // Checks the following semantic validation:
                //  - ValSem010
                //  - ValSem246 (as part of ValSem010)
                let plaintext = unverified_message
                    .into_verified(backend)
                    .map_err(|_| ProcessMessageError::InvalidSignature)?
                    .take_plaintext();

                let sender = plaintext.sender().clone();
                let authenticated_data = plaintext.authenticated_data().to_owned();

                let content = match &plaintext.content() {
                    MlsContentBody::Application(application_message) => {
                        ProcessedMessageContent::ApplicationMessage(ApplicationMessage::new(
                            application_message.as_slice().to_owned(),
                        ))
                    }
                    MlsContentBody::Proposal(_) => ProcessedMessageContent::ProposalMessage(
                        Box::new(QueuedProposal::from_mls_plaintext(
                            self.ciphersuite(),
                            backend,
                            plaintext,
                        )?),
                    ),
                    MlsContentBody::Commit(_) => {
                        //  - ValSem100
                        //  - ValSem101
                        //  - ValSem102
                        //  - ValSem103
                        //  - ValSem104
                        //  - ValSem105
                        //  - ValSem106
                        //  - ValSem107
                        //  - ValSem108
                        //  - ValSem109
                        //  - ValSem110
                        //  - ValSem111
                        //  - ValSem112
                        //  - ValSem200
                        //  - ValSem201
                        //  - ValSem202: Path must be the right length
                        //  - ValSem203: Path secrets must decrypt correctly
                        //  - ValSem204: Public keys from Path must be verified
                        //               and match the private keys from the
                        //               direct path
                        //  - ValSem205
                        //  - ValSem240
                        //  - ValSem241
                        //  - ValSem242
                        //  - ValSem243
                        //  - ValSem244
                        let staged_commit =
                            self.stage_commit(&plaintext, proposal_store, own_leaf_nodes, backend)?;
                        ProcessedMessageContent::StagedCommitMessage(Box::new(staged_commit))
                    }
                };

                Ok(ProcessedMessage::new(
                    group_id,
                    epoch,
                    sender,
                    authenticated_data,
                    content,
                    Some(credential),
                ))
            }
            UnverifiedContextMessage::External(_external_message) => {
                // We don't support messages from external senders yet
                // TODO #151/#106
                todo!()
            }
            UnverifiedContextMessage::NewMember(unverified_new_member_message) => {
                let credential = unverified_new_member_message.credential().clone();
                // Signature verification
                let verified_new_member_message = unverified_new_member_message
                    .into_verified(backend)
                    .map_err(|_| ProcessMessageError::InvalidSignature)?;
                let sender = verified_new_member_message.plaintext().sender().clone();
                let authenticated_data = verified_new_member_message
                    .plaintext()
                    .authenticated_data()
                    .to_owned();

                let content = match verified_new_member_message.plaintext().content() {
                    MlsContentBody::Proposal(_) => {
                        ProcessedMessageContent::ExternalJoinProposalMessage(Box::new(
                            QueuedProposal::from_mls_plaintext(
                                self.ciphersuite(),
                                backend,
                                verified_new_member_message.take_plaintext(),
                            )?,
                        ))
                    }
                    MlsContentBody::Commit(_) => {
                        let staged_commit = self.stage_commit(
                            verified_new_member_message.plaintext(),
                            proposal_store,
                            own_leaf_nodes,
                            backend,
                        )?;
                        ProcessedMessageContent::StagedCommitMessage(Box::new(staged_commit))
                    }
                    _ => {
                        return Err(ProcessMessageError::LibraryError(LibraryError::custom(
                            "Implementation error",
                        )))
                    }
                };

                Ok(ProcessedMessage::new(
                    group_id,
                    epoch,
                    sender,
                    authenticated_data,
                    content,
                    Some(credential),
                ))
            }
        }
    }

    /// This function is used to parse messages from the DS. It checks for
    /// syntactic errors and does semantic validation as well. If the input is a
    /// [MlsCiphertext] message, it will be decrypted. It returns a
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
    ///  - ValSem100
    ///  - ValSem101
    ///  - ValSem102
    ///  - ValSem103
    ///  - ValSem104
    ///  - ValSem105
    ///  - ValSem106
    ///  - ValSem107
    ///  - ValSem108
    ///  - ValSem109
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
    pub(crate) fn process_message(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        message: MlsMessageIn,
        sender_ratchet_configuration: &SenderRatchetConfiguration,
        proposal_store: &ProposalStore,
        own_kpbs: &[OpenMlsLeafNode],
    ) -> Result<ProcessedMessage, ProcessMessageError> {
        let unverified_message = self
            .parse_message(backend, message, sender_ratchet_configuration)
            .map_err(ProcessMessageError::from)?;
        self.process_unverified_message(unverified_message, proposal_store, own_kpbs, backend)
    }

    /// Merge a [StagedCommit] into the group after inspection
    pub(crate) fn merge_staged_commit(
        &mut self,
        staged_commit: StagedCommit,
        proposal_store: &mut ProposalStore,
    ) {
        // Save the past epoch
        let past_epoch = self.context().epoch();
        // Get all the full leaves
        let leaves = self.treesync().full_leave_members().collect();
        // Merge the staged commit into the group state and store the secret tree from the
        // previous epoch in the message secrets store.
        if let Some(message_secrets) = self.merge_commit(staged_commit) {
            self.message_secrets_store
                .add(past_epoch, message_secrets, leaves);
        }
        // Empty the proposal store
        proposal_store.empty();
    }
}
