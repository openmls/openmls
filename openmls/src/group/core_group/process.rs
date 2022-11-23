use core_group::{proposals::QueuedProposal, staged_commit::StagedCommit};

use crate::group::{errors::ValidationError, mls_group::errors::UnverifiedMessageError};

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
        signature_key: Option<&OpenMlsSignaturePublicKey>,
        proposal_store: &ProposalStore,
        own_kpbs: &[KeyPackageBundle],
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<ProcessedMessage, UnverifiedMessageError> {
        // Add the context to the message and verify the membership tag if necessary.
        // If the message is older than the current epoch, we need to fetch the correct secret tree first.
        let message_secrets = self
            .message_secrets_for_epoch(unverified_message.epoch())
            .map_err(|e| match e {
                SecretTreeError::TooDistantInThePast => UnverifiedMessageError::NoPastEpochData,
                _ => LibraryError::custom("Unexpected return value").into(),
            })?;

        // Checks the following semantic validation:
        //  - ValSem008
        let context_plaintext = UnverifiedContextMessage::from_unverified_message(
            unverified_message,
            message_secrets,
            backend,
        )
        .map_err(|_| UnverifiedMessageError::InvalidMembershipTag)?;

        match context_plaintext {
            UnverifiedContextMessage::Group(unverified_message) => {
                // Checks the following semantic validation:
                //  - ValSem010
                //  - ValSem246 (as part of ValSem010)
                let verified_member_message = unverified_message
                    .into_verified(backend, signature_key)
                    .map_err(|_| UnverifiedMessageError::InvalidSignature)?;

                Ok(match verified_member_message.plaintext().content() {
                    MlsContentBody::Application(application_message) => {
                        ProcessedMessage::ApplicationMessage(ApplicationMessage::new(
                            application_message.as_slice().to_vec(),
                        ))
                    }
                    MlsContentBody::Proposal(_proposal) => ProcessedMessage::ProposalMessage(
                        Box::new(QueuedProposal::from_mls_plaintext(
                            self.ciphersuite(),
                            backend,
                            verified_member_message.take_plaintext(),
                        )?),
                    ),
                    MlsContentBody::Commit(_commit) => {
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
                        let staged_commit = self.stage_commit(
                            verified_member_message.plaintext(),
                            proposal_store,
                            own_kpbs,
                            backend,
                        )?;
                        ProcessedMessage::StagedCommitMessage(Box::new(staged_commit))
                    }
                })
            }
            UnverifiedContextMessage::External(external_message) => {
                // Signature verification
                if let Some(signature_public_key) = signature_key {
                    let _verified_external_message = external_message
                        .into_verified(backend, signature_public_key)
                        .map_err(|_| UnverifiedMessageError::InvalidSignature)?;
                } else {
                    return Err(UnverifiedMessageError::MissingSignatureKey);
                }

                // We don't support messages from external senders yet
                // TODO #151/#106
                todo!()
            }
            UnverifiedContextMessage::NewMember(external_message) => {
                // Signature verification
                let verified_external_message = external_message
                    .into_verified(backend, signature_key)
                    .map_err(|_| UnverifiedMessageError::InvalidSignature)?;
                Ok(match verified_external_message.plaintext().content() {
                    MlsContentBody::Proposal(_proposal) => {
                        ProcessedMessage::ExternalJoinProposalMessage(Box::new(
                            QueuedProposal::from_mls_plaintext(
                                self.ciphersuite(),
                                backend,
                                verified_external_message.take_plaintext(),
                            )?,
                        ))
                    }
                    MlsContentBody::Commit(_commit) => {
                        let staged_commit = self.stage_commit(
                            verified_external_message.plaintext(),
                            proposal_store,
                            own_kpbs,
                            backend,
                        )?;
                        ProcessedMessage::StagedCommitMessage(Box::new(staged_commit))
                    }
                    _ => {
                        return Err(UnverifiedMessageError::LibraryError(LibraryError::custom(
                            "Implementation error",
                        )))
                    }
                })
            }
        }
    }

    /// Merge a [StagedCommit] into the group after inspection
    pub(crate) fn merge_staged_commit(
        &mut self,
        staged_commit: StagedCommit,
        proposal_store: &mut ProposalStore,
    ) -> Result<(), LibraryError> {
        // Save the past epoch
        let past_epoch = self.context().epoch();
        // Get all the full leaves
        let leaves = self
            .treesync()
            .full_leave_members()
            // This should disappear after refactoring TreeSync, fetching the leaves should never fail
            .map_err(|_| LibraryError::custom("Unexpected error in TreeSync"))?;
        // Merge the staged commit into the group state and store the secret tree from the
        // previous epoch in the message secrets store.
        if let Some(message_secrets) = self.merge_commit(staged_commit)? {
            self.message_secrets_store
                .add(past_epoch, message_secrets, leaves);
        }
        // Empty the proposal store
        proposal_store.empty();
        Ok(())
    }
}
