//! # Validation steps for incoming messages
//! ```text
//! parse_message(MlsMessageIn) -> UnverifiedMessage
//!
//! MlsMessageIn (exposes: wire format, group, epoch)
//! |
//! V
//! DecryptedMessage
//! |
//! V
//! UnverifiedMessage (exposes AAD, Credential of sender)
//!
//! process_unverified_message(UnverfiedMessage) -> ProcessedMessage
//!
//! UnverifiedMessage
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

/// Contains a [VerifiableMlsPlaintext]. Can be built either from a plaintext or ciphertext.
/// In the latter case, it attempts to decrypt the ciphertext.
/// Checks the presence of the membership tag and confirmation tag.
pub struct DecryptedMessage {
    plaintext: VerifiableMlsPlaintext,
}

impl DecryptedMessage {
    pub(crate) fn from_inbound_plaintext(
        inbound_message: MlsMessageIn,
    ) -> Result<Self, ValidationError> {
        if let MlsMessageIn::Plaintext(plaintext) = inbound_message {
            Self::from_plaintext(plaintext)
        } else {
            Err(ValidationError::WrongWireFormat)
        }
    }
    pub(crate) fn from_inbound_ciphertext(
        inbound_message: MlsMessageIn,
        ciphersuite: &Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        epoch_secrets: &EpochSecrets,
        secret_tree: &mut SecretTree,
    ) -> Result<Self, ValidationError> {
        if let MlsMessageIn::Ciphertext(ciphertext) = inbound_message {
            let plaintext =
                ciphertext.to_plaintext(ciphersuite, backend, epoch_secrets, secret_tree)?;
            Self::from_plaintext(plaintext)
        } else {
            Err(ValidationError::WrongWireFormat)
        }
    }
    fn from_plaintext(plaintext: VerifiableMlsPlaintext) -> Result<Self, ValidationError> {
        // Unless the message was encrypted, the membership tag is required when the sender is a member
        if plaintext.sender().is_member()
            && plaintext.wire_format() != WireFormat::MlsCiphertext
            && plaintext.membership_tag().is_none()
        {
            return Err(ValidationError::MissingMembershipTag);
        }
        // Check that if the message is a commit the confirmation tag is present
        if plaintext.content_type() == ContentType::Commit && plaintext.confirmation_tag().is_none()
        {
            return Err(ValidationError::MissingConfirmationTag);
        }
        // Check that application messages are always encrypted
        if plaintext.content_type() == ContentType::Application {
            if plaintext.wire_format() != WireFormat::MlsCiphertext {
                return Err(ValidationError::UnencryptedApplicationMessage);
            } else if !plaintext.sender().is_member() {
                // This should not happen because the sender of an MlsCiphertext should always be a member
                return Err(ValidationError::LibraryError);
            }
        }
        Ok(DecryptedMessage { plaintext })
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
        self.plaintext.sender()
    }
    pub fn credential(&self) -> Option<&Credential> {
        self.credential.as_ref()
    }
    pub(crate) fn into_parts(self) -> (VerifiableMlsPlaintext, Option<Credential>) {
        (self.plaintext, self.credential)
    }
}

/// Contains an [VerifiableMlsPlaintext] and a [Credential] if it is a member message.
/// It sets the serialized group context and verifies the membership tag for member messages.
/// It can be converted to a verified message by verifying the signature, either with the credential
/// or an external signature key.
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
            // Verify the membership tag
            if plaintext.wire_format() != WireFormat::MlsCiphertext {
                // Add serialized context to plaintext
                plaintext.set_context(serialized_context);
                // Verify the membership tag
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
                    // If the sender is a member, there must be a credential
                    Err(ValidationError::LibraryError)
                }
            }
            // TODO #192: We don't support external senders yet
            SenderType::Preconfigured => todo!(),
            SenderType::NewMember => todo!(),
        }
    }
}

/// Part of [UnverifiedContextMessage].
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
        let verified_member_message = if let Some(signature_public_key) = signature_key {
            self.plaintext
                .verify_with_key(backend, signature_public_key)
        } else {
            self.plaintext.verify(backend, &self.credential)
        }
        .map(|plaintext| VerifiedMemberMessage { plaintext })?;
        Ok(verified_member_message)
    }
}

// TODO #192: We don't support external senders yet
/// Part of [UnverifiedContextMessage].
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

/// Member message, where all semantic checks on the framing have been successfully performed.
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

/// External message, where all semantic checks on the framing have been successfully performed.
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
