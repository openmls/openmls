//! # Validation steps for incoming messages
//! ```text
//! MlsMessageIn (exposes: wire format, group, epoch)
//! |
//! V
//! parse_message()
//! |
//! V
//! DecryptedMessage
//! |
//! V
//! UnverifiedMessage (exposes AAD, Credential of sender)
//! |
//! V
//! process_unverified_message()
//! |
//! V
//! UnverifiedContextMessage (includes group context)
//! |                        |
//! | (sender is member)     | (sender is not member)
//! |                        |
//! V                        V
//! UnverifiedMemberMessage  UnverifiedExternalMessage
//! |                        |
//! | (verify signature)     | (verify signature)
//! |                        |
//! V                        V
//! VerfiedMemberMessage     VerifiedExternalMessage
//! |                        |
//! +------------------------+
//! |
//! V                        
//! ProcessedMessage (Application, Proposal, ExternalProposal, Commit, External Commit)
//! ```

use mls_group::{proposals::StagedProposal, staged_commit::StagedCommit};
use openmls_traits::OpenMlsCryptoProvider;

use crate::ciphersuite::signable::Verifiable;

use super::*;

pub struct DecryptedMessage {
    plaintext: VerifiableMlsPlaintext,
}

impl DecryptedMessage {
    pub(crate) fn from_inbound_plaintext(
        inbound_message: MlsMessageIn,
    ) -> Result<Self, ValidationError> {
        match inbound_message {
            MlsMessageIn::Plaintext(plaintext) => Ok(DecryptedMessage { plaintext }),
            MlsMessageIn::Ciphertext(_) => Err(ValidationError::WrongWireFormat),
        }
    }
    pub(crate) fn from_inbound_ciphertext(
        inbound_message: MlsMessageIn,
        ciphersuite: &Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        epoch_secrets: &EpochSecrets,
        secret_tree: &mut SecretTree,
    ) -> Result<Self, ValidationError> {
        match inbound_message {
            MlsMessageIn::Plaintext(_) => Err(ValidationError::WrongWireFormat),
            MlsMessageIn::Ciphertext(ciphertext) => {
                let plaintext =
                    ciphertext.to_plaintext(ciphersuite, backend, epoch_secrets, secret_tree)?;
                Ok(DecryptedMessage { plaintext })
            }
        }
    }
    pub fn wire_format(&self) -> WireFormat {
        self.plaintext.wire_format()
    }
    pub fn sender(&self) -> &Sender {
        self.plaintext.sender()
    }
    pub fn content_type(&self) -> ContentType {
        self.plaintext.content_type()
    }
    pub(crate) fn has_membership_tag(&self) -> bool {
        self.plaintext.membership_tag().is_some()
    }
    pub(crate) fn has_confirmation_tag(&self) -> bool {
        self.plaintext.confirmation_tag().is_some()
    }
}

/// Partially checked and potentially decrypted message.
/// Use this to inspect the [Credential] of the message sender
/// and the optional `aad` if the original message was an [MlsCiphertext].
pub struct UnverifiedMessage {
    plaintext: VerifiableMlsPlaintext,
    credential: Option<Credential>,
    aad_option: Option<Vec<u8>>,
}

impl UnverifiedMessage {
    pub(crate) fn from_decrypted_message(
        decrypted_message: DecryptedMessage,
        credential: Option<Credential>,
    ) -> Self {
        UnverifiedMessage {
            plaintext: decrypted_message.plaintext,
            credential,
            aad_option: None,
        }
    }

    pub fn aad(&self) -> &Option<Vec<u8>> {
        &self.aad_option
    }
    pub fn sender(&self) -> &Sender {
        todo!()
    }
    pub fn credential(&self) -> Option<&Credential> {
        self.credential.as_ref()
    }
    pub(crate) fn into_parts(self) -> (VerifiableMlsPlaintext, Option<Credential>) {
        (self.plaintext, self.credential)
    }
}

pub enum UnverifiedContextMessage {
    Member(UnverifiedMemberMessage),
    External(UnverifiedExternalMessage),
}

impl UnverifiedContextMessage {
    pub(crate) fn from_unverified_message_with_context(
        unverified_message: UnverifiedMessage,
        serialized_context: Vec<u8>,
        membership_key: &MembershipKey,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, ValidationError> {
        // Decompose UnverifiedMessage
        let (mut plaintext, credential_option) = unverified_message.into_parts();

        if plaintext.sender().is_member() {
            // Unless the message was encrypted, the membership tag is required
            if plaintext.wire_format() != WireFormat::MlsCiphertext {
                // Check that the membership tag is present if sender is member
                if plaintext.membership_tag.is_none() {
                    return Err(ValidationError::MissingMembershipTag);
                }
                // Add serialized context to plaintext
                plaintext.set_context(serialized_context);
                // Verify the membership key
                plaintext.verify_membership(backend, membership_key)?;
            }
        }
        match plaintext.sender().sender_type {
            SenderType::Member => {
                if let Some(credential) = credential_option {
                    Ok(UnverifiedContextMessage::Member(UnverifiedMemberMessage {
                        plaintext,
                        credential,
                    }))
                } else {
                    Err(ValidationError::LibraryError)
                }
            }
            // TODO #192: We don't support external senders yet
            SenderType::Preconfigured => todo!(),
            SenderType::NewMember => todo!(),
        }
    }
}

pub struct UnverifiedMemberMessage {
    plaintext: VerifiableMlsPlaintext,
    credential: Credential,
}

impl UnverifiedMemberMessage {
    pub(crate) fn into_verified(
        self,
        backend: &impl OpenMlsCryptoProvider,
        signature_key: Option<&SignaturePublicKey>,
    ) -> Result<VerifiedMemberMessage, ValidationError> {
        // If a signature key is provided it will be used,
        // otherwise we take the key from the credential
        match signature_key {
            Some(signature_public_key) => {
                match self
                    .plaintext
                    .verify_with_key(backend, signature_public_key)
                {
                    Ok(plaintext) => Ok(VerifiedMemberMessage { plaintext }),
                    Err(e) => Err(e.into()),
                }
            }
            None => match self.plaintext.verify(backend, &self.credential) {
                Ok(plaintext) => Ok(VerifiedMemberMessage { plaintext }),
                Err(e) => Err(e.into()),
            },
        }
    }
}

// TODO #192: We don't support external senders yet
pub struct UnverifiedExternalMessage {
    plaintext: VerifiableMlsPlaintext,
}

impl UnverifiedExternalMessage {
    pub(crate) fn into_verified(
        self,
        backend: &impl OpenMlsCryptoProvider,
        signature_key: &SignaturePublicKey,
    ) -> Result<VerifiedExternalMessage, ValidationError> {
        match self.plaintext.verify_with_key(backend, signature_key) {
            Ok(plaintext) => Ok(VerifiedExternalMessage { plaintext }),
            Err(e) => Err(e.into()),
        }
    }
}

pub struct VerifiedMemberMessage {
    plaintext: MlsPlaintext,
}

impl VerifiedMemberMessage {
    pub fn plaintext(&self) -> &MlsPlaintext {
        &self.plaintext
    }
    pub fn take_plaintext(self) -> MlsPlaintext {
        self.plaintext
    }
}

pub struct VerifiedExternalMessage {
    plaintext: MlsPlaintext,
}

impl VerifiedExternalMessage {
    pub fn plaintext(&self) -> &MlsPlaintext {
        &self.plaintext
    }
    pub fn take_plaintext(self) -> MlsPlaintext {
        self.plaintext
    }
}

/// Message that contains messages that are syntactically and semantically correct.
/// [StagedCommit] and [StagedProposal] can be inspected for authorization purposes.
pub enum ProcessedMessage {
    ApplicationMessage(Vec<u8>),
    ProposalMessage(Box<StagedProposal>),
    StagedCommitMessage(Box<StagedCommit>),
}
