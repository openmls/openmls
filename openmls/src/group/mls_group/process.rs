use mls_group::{proposals::StagedProposal, staged_commit::StagedCommit};

use crate::tree::secret_tree::SecretTreeError;

use super::{past_secrets::MessageSecretsStore, proposals::ProposalStore, *};

impl MlsGroup {
    /// This function is used to parse messages from the DS.
    /// It checks for syntactic errors and makes some semantic checks as well.
    /// If the input is a [MlsCiphertext] message, it will be decrypted.
    /// Returns an [UnverifiedMessage] that can be inspected and later processed in
    /// [Self::process_unverified_message()].
    /// Checks the following semantic validation:
    ///  - ValSem2
    ///  - ValSem3
    ///  - ValSem4
    ///  - ValSem5
    ///  - ValSem6
    ///  - ValSem7
    ///  - ValSem9
    pub fn parse_message<'a>(
        &mut self,
        message: MlsMessageIn,
        message_secrets_store: impl Into<Option<&'a mut MessageSecretsStore>>,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<UnverifiedMessage, MlsGroupError> {
        // Checks the following semantic validation:
        //  - ValSem2
        //  - ValSem3
        self.validate_framing(&message)?;

        // Checks the following semantic validation:
        //  - ValSem6
        let decrypted_message = match message.wire_format() {
            WireFormat::MlsPlaintext => DecryptedMessage::from_inbound_plaintext(message)?,
            WireFormat::MlsCiphertext => {
                // If the message is older than the current epoch, we need to fetch the correct secret tree first
                let ciphersuite = self.ciphersuite().clone();
                let message_secrets = if message.epoch() < self.context().epoch() {
                    if let Some(store) = message_secrets_store.into() {
                        if let Some(message_secrets) = store.get_epoch(message.epoch()) {
                            message_secrets
                        } else {
                            return Err(MlsGroupError::MlsCiphertextError(
                                MlsCiphertextError::SecretTreeError(
                                    SecretTreeError::TooDistantInThePast,
                                ),
                            ));
                        }
                    } else {
                        return Err(MlsGroupError::MlsCiphertextError(
                            MlsCiphertextError::SecretTreeError(
                                SecretTreeError::TooDistantInThePast,
                            ),
                        ));
                    }
                } else {
                    self.message_secrets_mut()
                };
                DecryptedMessage::from_inbound_ciphertext(
                    message,
                    &ciphersuite,
                    backend,
                    message_secrets,
                )?
            }
        };

        let mut credential = None;

        // Checks the following semantic validation:
        //  - ValSem4
        //  - ValSem5
        //  - ValSem7
        //  - ValSem9
        self.validate_plaintext(decrypted_message.plaintext())?;

        // Extract the credential if the sender is a member
        let sender = decrypted_message.sender();
        if sender.is_member() {
            let sender_index = sender.to_leaf_index();

            credential = self
                .treesync()
                .leaf(sender_index)?
                .map(|leaf_node| leaf_node.key_package().credential().clone());
        }

        Ok(UnverifiedMessage::from_decrypted_message(
            decrypted_message,
            credential,
        ))
    }

    /// This processing function does most of the semantic verifications.
    /// It returns a [ProcessedMessage] enum.
    /// Checks the following semantic validation:
    ///  - ValSem8
    ///  - ValSem10
    ///  - ValSem100
    ///  - ValSem101
    ///  - ValSem102
    ///  - ValSem103
    ///  - ValSem104
    ///  - ValSem105
    ///  - ValSem106
    ///  - ValSem107
    ///  - ValSem109
    ///  - ValSem110
    pub fn process_unverified_message<'a>(
        &mut self,
        unverified_message: UnverifiedMessage,
        signature_key: Option<&SignaturePublicKey>,
        proposal_store: &ProposalStore,
        message_secrets_store: impl Into<Option<&'a mut MessageSecretsStore>>,
        own_kpbs: &[KeyPackageBundle],
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<ProcessedMessage, MlsGroupError> {
        // Add the context to the message and verify the membership tag if necessary.
        // If the message is older than the current epoch, we need to fetch the correct secret tree first.
        let message_secrets = if unverified_message.epoch() < self.context().epoch() {
            let message_secrets = if let Some(store) = message_secrets_store.into() {
                if let Some(message_secrets) = store.get_epoch(unverified_message.epoch()) {
                    message_secrets
                } else {
                    return Err(MlsGroupError::MlsCiphertextError(
                        MlsCiphertextError::SecretTreeError(SecretTreeError::TooDistantInThePast),
                    ));
                }
            } else {
                return Err(MlsGroupError::MlsCiphertextError(
                    MlsCiphertextError::SecretTreeError(SecretTreeError::TooDistantInThePast),
                ));
            };
            message_secrets
        } else {
            self.message_secrets()
        };

        // Checks the following semantic validation:
        //  - ValSem8
        let context_plaintext =
            UnverifiedContextMessage::from_unverified_message_with_message_secrets(
                unverified_message,
                message_secrets,
                backend,
            )?;

        match context_plaintext {
            UnverifiedContextMessage::Member(member_message) => {
                // Checks the following semantic validation:
                //  - ValSem10
                let verified_member_message =
                    member_message.into_verified(backend, signature_key)?;

                Ok(match verified_member_message.plaintext().content() {
                    MlsPlaintextContentType::Application(application_message) => {
                        ProcessedMessage::ApplicationMessage(ApplicationMessage::new(
                            application_message.as_slice().to_vec(),
                            *verified_member_message.plaintext().sender(),
                        ))
                    }
                    MlsPlaintextContentType::Proposal(_proposal) => {
                        ProcessedMessage::ProposalMessage(Box::new(
                            StagedProposal::from_mls_plaintext(
                                self.ciphersuite(),
                                backend,
                                verified_member_message.take_plaintext(),
                            )?,
                        ))
                    }
                    MlsPlaintextContentType::Commit(_commit) => {
                        //  - ValSem100
                        //  - ValSem101
                        //  - ValSem102
                        //  - ValSem103
                        //  - ValSem104
                        //  - ValSem105
                        //  - ValSem106
                        //  - ValSem107
                        //  - ValSem109
                        //  - ValSem110
                        let staged_commit = self.stage_commit(
                            verified_member_message.plaintext(),
                            proposal_store,
                            own_kpbs,
                            None,
                            backend,
                        )?;
                        ProcessedMessage::StagedCommitMessage(Box::new(staged_commit))
                    }
                })
            }
            UnverifiedContextMessage::External(external_message) => {
                // Signature verification
                if let Some(signature_public_key) = signature_key {
                    let _verified_external_message =
                        external_message.into_verified(backend, signature_public_key)?;
                } else {
                    return Err(MlsGroupError::NoSignatureKey);
                }

                // We don't support external messages yet
                // TODO #192
                todo!()
            }
        }
    }

    /// Merge a [StagedCommit] into the group after inspection
    pub fn merge_staged_commit(
        &mut self,
        staged_commit: StagedCommit,
        proposal_store: &mut ProposalStore,
        message_secrets_store: &mut MessageSecretsStore,
    ) -> Result<(), MlsGroupError> {
        // Save the past epoch
        let past_epoch = self.context().epoch();
        // Merge the staged commit into the group state and store the secret tree from the
        // previous epoch in the message secrets store.
        if let Some(message_secrets) = self.merge_commit_take_message_secrets(staged_commit)? {
            message_secrets_store.add(past_epoch, message_secrets);
        }
        // Empty the proposal store
        proposal_store.empty();
        Ok(())
    }
}
