use crate::prelude::PreSharedKeys;

use super::*;

impl ManagedGroup {
    pub fn parse_message(
        &mut self,
        message: InboundMessage,
    ) -> Result<UnverifiedMessage, ManagedGroupError> {
        /*
        High level checks:
         - epoch must be within bounds
         - AAD can be extracted/evaluated
         - decryption
         - IFF content_type is a commit, confirmation_tag must be present
         - membership tag must be verified
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
        let (plaintext, aad) = match message {
            // If it is a ciphertext we decrypt it and return the plaintext message.
            // Attempting to decrypt it will also check the bounds of the epoch.
            InboundMessage::Ciphertext(ciphertext) => {
                let aad = ciphertext.authenticated_data.clone().into_vec();

                let plaintext = self.group.decrypt(&ciphertext)?;
                (plaintext, aad)
            }
            // If it is a plaintext message we return it with an empty AAD
            InboundMessage::Plaintext(plaintext) => (plaintext, vec![]),
        };
        // Check that if the message is a commit the confirmation tag is present
        if plaintext.is_commit() && plaintext.confirmation_tag().is_none() {
            return Err(ManagedGroupError::InvalidMessage(
                InvalidMessageError::MissingConfirmationTag,
            ));
        }

        Ok(UnverifiedMessage { plaintext, aad })
    }

    pub fn process_unverified_message(
        &self,
        message: UnverifiedMessage,
        signature_key: Option<SignaturePublicKey>,
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
           - Path must be present, unless Commit only covers Add Proposals
           - Path must be the right length
           - Staging step: proposals must be applied to modify the provisional tree
           - Path must be applied and decrypt correctly
           - New public keys from Path must be verified and match the private keys from the direct path
           - Confirmation tag must be successfully verified
        */
        Ok(match message.plaintext.into() {
            MlsPlaintextContentType::Application(application_message) => {
                ProcessedMessage::ApplicationMessage(application_message.as_slice().to_vec())
            }
            MlsPlaintextContentType::Proposal(proposal) => {
                ProcessedMessage::ProposalMessage(proposal)
            }
            MlsPlaintextContentType::Commit(_) => todo!(),
        })
    }

    pub fn store_pending_proposal(&mut self, pending_proposal: Proposal) {
        /*
         - Store proposal in pending proposal list
        */
        todo!()
    }

    pub fn merge_staged_commit(
        &mut self,
        staged_commit: StagedCommit,
        psks: &[PreSharedKeys],
    ) -> Result<(), ManagedGroupError> {
        /*
         - Merge staged Commit values into internal group stage
        */
        todo!()
    }
}

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

pub struct UnverifiedMessage {
    plaintext: MlsPlaintext,
    aad: Vec<u8>,
}

impl UnverifiedMessage {
    pub fn aad(&self) -> &[u8] {
        todo!()
    }
    pub fn credential(&self) -> &Credential {
        todo!()
    }
}

pub enum ProcessedMessage {
    ApplicationMessage(Vec<u8>),
    ProposalMessage(Proposal),
    StagedCommitMessage(StagedCommit),
}

pub struct StagedCommit {}

impl StagedCommit {
    pub fn adds(&self) -> &[AddProposal] {
        todo!()
    }
    pub fn removes(&self) -> &[RemoveProposal] {
        todo!()
    }
    pub fn updates(&self) -> &[UpdateProposal] {
        todo!()
    }
    pub fn psks(&self) -> &[PreSharedKeyProposal] {
        todo!()
    }
}
