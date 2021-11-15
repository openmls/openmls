use std::ops::DerefMut;

use mls_group::{proposals::StagedProposal, staged_commit::StagedCommit};
use tls_codec::Serialize;

use super::*;

impl ManagedGroup {
    /// This function is used to parse messages from the DS.
    /// It checks for syntactic errors and makes some semantic checks as well.
    /// If the input is a [MlsCiphertext] message, it will be decrypted.
    /// Returns an [UnverifiedMessage] that can be inspected and later processed in
    /// [self::process_unverified_message()].
    pub fn parse_message(
        &mut self,
        message: MlsMessageIn,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<UnverifiedMessage, ManagedGroupError> {
        /*
        High level checks:
         - epoch must be within bounds
         - IFF content_type is application, wire_format must be ciphertext
         - AAD can be extracted/evaluated
         - decryption
         - IFF content_type is a commit, confirmation_tag must be present
         - IFF sender_type is member, membership tag must be present
        */

        // Make sure we are still a member of the group
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }
        // Check the message has the correct epoch number
        if message.epoch() != self.group.context().epoch() {
            return Err(ManagedGroupError::InvalidMessage(
                InvalidMessageError::WrongEpoch,
            ));
        }

        let decrypted_message = match message.wire_format() {
            WireFormat::MlsPlaintext => DecryptedMessage::from_inbound_plaintext(message)?,
            WireFormat::MlsCiphertext => DecryptedMessage::from_inbound_ciphertext(
                message,
                self.ciphersuite(),
                backend,
                self.group.epoch_secrets(),
                self.group.secret_tree_mut().deref_mut(),
            )?,
        };

        let mut credential = None;

        // Check that the sender is a valid member of the tree
        // The sender index must be within the tree and the corresponding leaf node must not be blank
        let sender = decrypted_message.sender();
        if sender.is_member() {
            let sender_index = sender.to_leaf_index();
            if sender_index > self.group.tree().leaf_count()
                || self.group.tree().nodes[sender_index].is_blank()
            {
                return Err(ManagedGroupError::InvalidMessage(
                    InvalidMessageError::UnknownSender,
                ));
            }

            // Extract the credential
            // Unwrapping here is safe, because we know the leaf node exists and is not blank
            credential = Some(
                self.group.tree().nodes[sender_index]
                    .key_package
                    .as_ref()
                    .unwrap()
                    .credential()
                    .clone(),
            );
        }

        Ok(UnverifiedMessage::from_decrypted_message(
            decrypted_message,
            credential,
        ))
    }

    /// This processing function does most of the semantic verifications.
    /// It returns a [ProcessedMessage] enum.
    pub fn process_unverified_message(
        &mut self,
        unverified_message: UnverifiedMessage,
        signature_key: Option<&SignaturePublicKey>,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<ProcessedMessage, ManagedGroupError> {
        /*
         - IF sender_type is member, membership_tag must be valid
         - Signature verification, either with leaf key or optional parameter
         - IF Commit:
           - Extract all inline & pending proposals
         - Semantic validation of all proposals
           - IF Add Proposal: Double join check
           - IF Remove Proposal: Ghost removal check
           - IF Update Proposal: Identity must be unchanged
         - IF Commit:
           - Commit must not cover inline self Remove proposal
           - Path must be present, if Commit contains Removes or Updates
           - Path must be the right length
           - Staging step: proposals must be applied to modify the provisional tree
           - Path must be applied and decrypt correctly
           - New public keys from Path must be verified and match the private keys from the direct path
           - Confirmation tag must be successfully verified
        */

        // Add the context to the message and verify the membership tag if necessary
        let serialized_context = self.group.context().tls_serialize_detached()?;

        let context_plaintext = UnverifiedContextMessage::from_unverified_message_with_context(
            unverified_message,
            serialized_context,
            self.group.epoch_secrets().membership_key(),
            backend,
        )?;

        match context_plaintext {
            UnverifiedContextMessage::Member(member_message) => {
                // Signature verification
                let verified_member_message =
                    member_message.into_verified(backend, signature_key)?;

                Ok(match verified_member_message.plaintext().content() {
                    MlsPlaintextContentType::Application(application_message) => {
                        ProcessedMessage::ApplicationMessage(
                            application_message.as_slice().to_vec(),
                        )
                    }
                    MlsPlaintextContentType::Proposal(_proposal) => {
                        ProcessedMessage::ProposalMessage(Box::new(
                            StagedProposal::from_mls_plaintext(
                                self.ciphersuite(),
                                backend,
                                verified_member_message.take_plaintext(),
                            )
                            .unwrap(),
                        ))
                    }
                    MlsPlaintextContentType::Commit(_commit) => {
                        let staged_commit = self.group.stage_commit(
                            verified_member_message.plaintext(),
                            &self.proposal_store,
                            &self.own_kpbs,
                            None,
                            backend,
                        )?;
                        ProcessedMessage::StagedCommitMessage(Box::new(staged_commit))
                    }
                })
            }
            UnverifiedContextMessage::External(external_message) => {
                // Signature verification
                match signature_key {
                    Some(signature_public_key) => {
                        let _verified_external_message =
                            external_message.into_verified(backend, signature_public_key)?;
                    }
                    None => {
                        return Err(ManagedGroupError::NoSignatureKey);
                    }
                }

                // We don't support external messages yet
                // TODO #192
                todo!()
            }
        }
    }

    /// Stores a standalone proposal in the internal [ProposalStore]
    pub fn store_pending_proposal(&mut self, pending_proposal: StagedProposal) {
        /*
         - Store proposal in pending proposal list
        */
        self.proposal_store.add(pending_proposal);
    }

    /// Merge a [StagedCommit] into the group after inspection
    pub fn merge_staged_commit(
        &mut self,
        staged_commit: StagedCommit,
    ) -> Result<(), ManagedGroupError> {
        /*
         - Merge staged Commit values into internal group stage
         - Empty the proposal store
        */
        self.group.merge_commit(staged_commit);
        self.proposal_store.empty();
        Ok(())
    }
}
