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
        message: InboundMessage,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<UnverifiedMessage, ManagedGroupError> {
        /*
        High level checks:
         - epoch must be within bounds
         - Sender must be a member
         - AAD can be extracted/evaluated
         - decryption
         - IFF content_type is a commit, confirmation_tag must be present
         - membership tag must be present/verified
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

        // Check the type of message we received
        let mut membership_tag_required = false;
        let (plaintext, aad) = match message {
            // If it is a ciphertext we decrypt it and return the plaintext message.
            // Attempting to decrypt it will also check the bounds of the epoch.
            InboundMessage::Ciphertext(ciphertext) => {
                let aad = ciphertext.authenticated_data.clone().into_vec();

                let plaintext = self.group.decrypt(&ciphertext, backend)?;

                (plaintext, aad)
            }
            // If it is a plaintext message we return it with an empty AAD
            // after we check that the membership tag is present and valid
            InboundMessage::Plaintext(plaintext) => {
                // We expect a membership tag for plaintext messages
                // TODO #106: Membership tag is not expected for external senders
                membership_tag_required = true;
                (plaintext, vec![])
            }
        };

        // Check that the sender is a valid member of the tree
        // The sender index must be within the tree and the corresponding leaf node must not be blank
        let sender = plaintext.sender().to_leaf_index();
        if sender > self.group.tree().leaf_count() || self.group.tree().nodes[sender].is_blank() {
            return Err(ManagedGroupError::InvalidMessage(
                InvalidMessageError::UnknownSender,
            ));
        }

        // Extract the credential
        // Unwrapping here is safe, because we know the leaf node exists and is not blank
        let credential = self.group.tree().nodes[sender]
            .key_package
            .as_ref()
            .unwrap()
            .credential()
            .clone();

        // Get the serialized group context for further verification
        let serialized_context = self.group.context().tls_serialize_detached().map_err(|_| {
            ManagedGroupError::LibraryError("Could not serialize group context".into())
        })?;

        // Verifiy the membership tag if needed
        if membership_tag_required {
            if !plaintext.has_membership_tag() {
                return Err(ManagedGroupError::InvalidMessage(
                    InvalidMessageError::MissingMembershipTag,
                ));
            }
            plaintext
                .verify_membership(
                    backend,
                    serialized_context.as_slice(),
                    self.group.epoch_secrets().membership_key(),
                )
                .map_err(|_| {
                    ManagedGroupError::InvalidMessage(InvalidMessageError::MembershipTagMismatch)
                })?;
        }

        // Check that if the message is a commit the confirmation tag is present
        if plaintext.is_commit() && plaintext.confirmation_tag().is_none() {
            return Err(ManagedGroupError::InvalidMessage(
                InvalidMessageError::MissingConfirmationTag,
            ));
        }

        Ok(UnverifiedMessage {
            plaintext,
            credential,
            aad,
        })
    }

    /// This processing function does most of the semantic verifications.
    /// It returns a [ProcessedMessage] enum.
    pub fn process_unverified_message(
        &mut self,
        message: UnverifiedMessage,
        signature_key: Option<SignaturePublicKey>,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<ProcessedMessage, ManagedGroupError> {
        /*
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

        // Signature verification
        // If a signature key is provided it will be used,
        // otherwise we take the key from the credential

        let serialized_context = self.group.context().tls_serialize_detached().map_err(|_| {
            ManagedGroupError::LibraryError("Could not serialize group context".into())
        })?;

        let verifiable_plaintext = VerifiableMlsPlaintext::from_plaintext(
            message.plaintext,
            Some(serialized_context.as_slice()),
        );

        let plaintext: MlsPlaintext = match signature_key {
            Some(signature_public_key) => {
                verifiable_plaintext.verify_with_key(backend, &signature_public_key)?
            }
            None => verifiable_plaintext.verify(backend, &message.credential)?,
        };

        Ok(match plaintext.content() {
            MlsPlaintextContentType::Application(application_message) => {
                ProcessedMessage::ApplicationMessage(application_message.as_slice().to_vec())
            }
            MlsPlaintextContentType::Proposal(_proposal) => {
                ProcessedMessage::ProposalMessage(Box::new(
                    StagedProposal::from_mls_plaintext(self.ciphersuite(), backend, plaintext)
                        .unwrap(),
                ))
            }
            MlsPlaintextContentType::Commit(_commit) => {
                let staged_commit = self.group.stage_commit(
                    &plaintext,
                    &self.proposal_store,
                    &self.own_kpbs,
                    None,
                    backend,
                )?;
                ProcessedMessage::StagedCommitMessage(Box::new(staged_commit))
            }
        })
    }

    pub fn store_pending_proposal(&mut self, pending_proposal: StagedProposal) {
        /*
         - Store proposal in pending proposal list
        */
        self.proposal_store.add(pending_proposal);
    }

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

/// Inbound message from the DS.
pub enum InboundMessage {
    Plaintext(MlsPlaintext),
    Ciphertext(MlsCiphertext),
}

impl InboundMessage {
    pub fn epoch(&self) -> GroupEpoch {
        match self {
            InboundMessage::Plaintext(plaintext) => plaintext.epoch(),
            InboundMessage::Ciphertext(ciphertext) => ciphertext.epoch(),
        }
    }
}

/// Partially checked and potentially decrypted message.
/// Use this to inspect the [Credential] of the message sender
/// and the optional `aad` if the original message was an [MlsCiphertext].
pub struct UnverifiedMessage {
    plaintext: MlsPlaintext,
    credential: Credential,
    aad: Vec<u8>,
}

impl UnverifiedMessage {
    pub fn aad(&self) -> &[u8] {
        &self.aad
    }
    pub fn credential(&self) -> &Credential {
        &self.credential
    }
}

/// Message that contains messages that are syntactically and semantically correct.
/// [StagedCommit] and [StagedProposal] can be inspected for authorization purposes.
pub enum ProcessedMessage {
    ApplicationMessage(Vec<u8>),
    ProposalMessage(Box<StagedProposal>),
    StagedCommitMessage(Box<StagedCommit>),
}
