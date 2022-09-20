//! # Validation steps for incoming messages
//!
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

use crate::{group::errors::ValidationError, tree::index::SecretTreeLeafIndex, treesync::TreeSync};
use core_group::{proposals::QueuedProposal, staged_commit::StagedCommit};
use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    ciphersuite::{hash_ref::KeyPackageRef, signable::Verifiable},
    error::LibraryError,
    tree::sender_ratchet::SenderRatchetConfiguration,
};

use super::*;

/// Intermediate message that can be constructed either from a plaintext message or from ciphertext message.
/// If it it constructed from a ciphertext message, the ciphertext message is decrypted first.
/// This function implements the following checks:
///  - ValSem005
///  - ValSem007
///  - ValSem009
pub(crate) struct DecryptedMessage {
    plaintext: VerifiableMlsPlaintext,
}

impl DecryptedMessage {
    /// Constructs a [DecryptedMessage] from a [VerifiableMlsPlaintext].
    pub(crate) fn from_inbound_plaintext(
        inbound_message: MlsMessageIn,
    ) -> Result<Self, ValidationError> {
        if let MlsMessage::Plaintext(plaintext) = inbound_message.mls_message {
            Self::from_plaintext(*plaintext)
        } else {
            Err(ValidationError::WrongWireFormat)
        }
    }

    /// Constructs a [DecryptedMessage] from a [MlsCiphertext] by attempting to decrypt it
    /// to a [VerifiableMlsPlaintext] first.
    pub(crate) fn from_inbound_ciphertext(
        inbound_message: MlsMessageIn,
        backend: &impl OpenMlsCryptoProvider,
        group: &mut CoreGroup,
        sender_ratchet_configuration: &SenderRatchetConfiguration,
    ) -> Result<Self, ValidationError> {
        // This will be refactored with #265.
        if let MlsMessage::Ciphertext(ciphertext) = inbound_message.mls_message {
            let ciphersuite = group.ciphersuite();
            let (message_secrets, old_leaves) = group
                .message_secrets_and_leaves_mut(ciphertext.epoch())
                .map_err(|_| MessageDecryptionError::AeadError)?;
            let sender_data = ciphertext.sender_data(message_secrets, backend, ciphersuite)?;
            let sender_index = match group.sender_index(&sender_data.sender) {
                Ok(i) => i,
                Err(_) => {
                    // If the message is old, the tree might have changed.
                    // Let's look for the sender in the old leaves.
                    old_leaves
                        .into_iter()
                        .find_map(|(index, kpr)| {
                            if kpr == sender_data.sender {
                                Some(index)
                            } else {
                                None
                            }
                        })
                        .ok_or(ValidationError::UnknownMember)?
                }
            };
            let sender_index = SecretTreeLeafIndex(sender_index);
            let message_secrets = group
                .message_secrets_mut(ciphertext.epoch())
                .map_err(|_| MessageDecryptionError::AeadError)?;
            let plaintext = ciphertext.to_plaintext(
                ciphersuite,
                backend,
                message_secrets,
                sender_index,
                sender_ratchet_configuration,
                sender_data,
            )?;
            Self::from_plaintext(plaintext)
        } else {
            Err(ValidationError::WrongWireFormat)
        }
    }

    // Internal constructor function. Does the following checks:
    // - Confirmation tag must be present for Commit messages
    // - Membership tag must be present for member messages, if the original incoming message was not an MlsCiphertext
    // - Ensures application messages were originally MlsCiphertext messages
    fn from_plaintext(plaintext: VerifiableMlsPlaintext) -> Result<Self, ValidationError> {
        // ValSem007
        if plaintext.sender().is_member()
            && plaintext.wire_format() != WireFormat::MlsCiphertext
            && plaintext.membership_tag().is_none()
        {
            return Err(ValidationError::MissingMembershipTag);
        }
        // ValSem009
        if plaintext.content_type() == ContentType::Commit && plaintext.confirmation_tag().is_none()
        {
            return Err(ValidationError::MissingConfirmationTag);
        }
        // ValSem005
        if plaintext.content_type() == ContentType::Application {
            if plaintext.wire_format() != WireFormat::MlsCiphertext {
                return Err(ValidationError::UnencryptedApplicationMessage);
            } else if !plaintext.sender().is_member() {
                // This should not happen because the sender of an MlsCiphertext should always be a member
                return Err(LibraryError::custom("Expected sender to be member.").into());
            }
        }
        Ok(DecryptedMessage { plaintext })
    }

    /// Gets the correct credential from the message depending on the sender type.
    /// Checks the following semantic validation:
    ///  - ValSem112
    ///  - ValSem246
    ///  - Prepares ValSem247 by setting the right credential. The remainder
    ///    of ValSem247 is validated as part of ValSem010.
    pub(crate) fn credential(
        &self,
        treesync: &TreeSync,
        old_leaves: &[(u32, KeyPackageRef)],
    ) -> Result<Credential, ValidationError> {
        let sender = self.sender();
        match sender {
            Sender::Member(hash_ref) => {
                match treesync.leaf_from_id(hash_ref) {
                    Some(sender_leaf) => Ok(sender_leaf.key_package().credential().clone()),
                    None => {
                        // This might not actually be an error but the sender's
                        // key package changed. Let's check old leaves we still
                        // have around.
                        if let Some((sender_index, _)) =
                            old_leaves.iter().find(|(_, kpr)| kpr == hash_ref)
                        {
                            match treesync
                                .leaf(*sender_index)
                                .map_err(|_| ValidationError::UnknownMember)?
                            {
                                Some(node) => Ok(node.key_package().credential().clone()),
                                None => Err(ValidationError::UnknownMember),
                            }
                        } else {
                            Err(ValidationError::UnknownMember)
                        }
                    }
                }
            }
            // Preconfigured senders are not supported yet #106/#151.
            Sender::Preconfigured(_) => unimplemented!(),
            Sender::NewMember => {
                // Since this allows only commits to have a sender type `Member`, it checks
                // ValSem112
                if let MlsPlaintextContentType::Commit(commit) = self.plaintext().content() {
                    if let Some(path) = commit.path() {
                        Ok(path.leaf_key_package().credential().clone())
                    } else {
                        Err(ValidationError::NoPath)
                    }
                } else {
                    Err(ValidationError::NotACommit)
                }
            }
        }
    }

    /// Returns the sender.
    pub fn sender(&self) -> &Sender {
        self.plaintext.sender()
    }

    /// Returns the plaintext.
    pub(crate) fn plaintext(&self) -> &VerifiableMlsPlaintext {
        &self.plaintext
    }
}

/// Partially checked and potentially decrypted message (if it was originally encrypted).
/// Use this to inspect the [`Credential`] of the message sender
/// and the optional `aad` if the original message was encrypted.
#[derive(Debug)]
pub struct UnverifiedMessage {
    plaintext: VerifiableMlsPlaintext,
    credential: Option<Credential>,
    aad_option: Option<Vec<u8>>,
}

impl UnverifiedMessage {
    /// Construct an [UnverifiedMessage] from a [DecryptedMessage] and an optional [Credential].
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

    /// Returns the epoch.
    pub fn epoch(&self) -> GroupEpoch {
        self.plaintext.epoch()
    }

    /// Returns the AAD.
    pub fn aad(&self) -> &Option<Vec<u8>> {
        &self.aad_option
    }

    /// Returns the sender.
    pub fn sender(&self) -> &Sender {
        self.plaintext.sender()
    }

    /// Return the credential if there is one.
    pub fn credential(&self) -> Option<&Credential> {
        self.credential.as_ref()
    }

    /// Decomposes an [UnverifiedMessage] into its parts.
    pub(crate) fn into_parts(self) -> (VerifiableMlsPlaintext, Option<Credential>) {
        (self.plaintext, self.credential)
    }
}

/// Contains an VerifiableMlsPlaintext and a [Credential] if it is a message
/// from a `Member` or a `NewMember`.  It sets the serialized group context and
/// verifies the membership tag for member messages.  It can be converted to a
/// verified message by verifying the signature, either with the credential or
/// an external signature key.
pub(crate) enum UnverifiedContextMessage {
    /// Unverified message from a group member
    Group(UnverifiedGroupMessage),
    /// Unverfied message from a preconfigured sender
    /// TODO: #106
    #[allow(dead_code)]
    Preconfigured(UnverifiedPreconfiguredMessage),
}

impl UnverifiedContextMessage {
    /// Constructs an [UnverifiedContextMessage] from an [UnverifiedMessage] and adds the serialized group context.
    /// This function implements the following checks:
    ///  - ValSem008
    pub(crate) fn from_unverified_message(
        unverified_message: UnverifiedMessage,
        message_secrets: &MessageSecrets,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, ValidationError> {
        // Decompose UnverifiedMessage
        let (mut plaintext, credential_option) = unverified_message.into_parts();

        if plaintext.sender().is_member() {
            // Add serialized context to plaintext. This is needed for signature & membership verification.
            plaintext.set_context(message_secrets.serialized_context().to_vec());
            // Verify the membership tag. This needs to be done explicitly for MlsPlaintext messages,
            // it is implicit for MlsCiphertext messages (because the encryption can only be known by members).
            if plaintext.wire_format() != WireFormat::MlsCiphertext {
                // ValSem008
                plaintext.verify_membership(backend, message_secrets.membership_key())?;
            }
        }
        match plaintext.sender() {
            Sender::Member(_) | Sender::NewMember => {
                Ok(UnverifiedContextMessage::Group(UnverifiedGroupMessage {
                    plaintext,
                    // If the message type is `Sender` or `NewMember`, the
                    // message always contains a credential.
                    credential: credential_option.ok_or_else(|| {
                        ValidationError::from(LibraryError::custom("Expected credential"))
                    })?,
                }))
            }
            // TODO #151/#106: We don't support preconfigured senders yet
            Sender::Preconfigured(_) => unimplemented!(),
        }
    }
}

/// Part of [UnverifiedContextMessage].
pub(crate) struct UnverifiedGroupMessage {
    plaintext: VerifiableMlsPlaintext,
    credential: Credential,
}

impl UnverifiedGroupMessage {
    /// Verifies the signature on an [UnverifiedMemberMessage] and returns a [VerifiedMemberMessage] if the
    /// verification is successful.
    /// This function implements the following checks:
    ///  - ValSem010
    pub(crate) fn into_verified(
        self,
        backend: &impl OpenMlsCryptoProvider,
        signature_key: Option<&SignaturePublicKey>,
    ) -> Result<VerifiedMemberMessage, ValidationError> {
        // If a signature key is provided it will be used,
        // otherwise we take the key from the credential
        let verified_member_message = if let Some(signature_public_key) = signature_key {
            // ValSem010
            self.plaintext
                .verify_with_key(backend, signature_public_key)
        } else {
            // ValSem010
            self.plaintext.verify(backend, &self.credential)
        }
        .map(|plaintext| VerifiedMemberMessage { plaintext })
        .map_err(|_| ValidationError::InvalidSignature)?;
        Ok(verified_member_message)
    }
}

// TODO #151/#106: We don't support preconfigured senders yet
/// Part of [UnverifiedContextMessage].
pub(crate) struct UnverifiedPreconfiguredMessage {
    plaintext: VerifiableMlsPlaintext,
}

impl UnverifiedPreconfiguredMessage {
    /// Verifies the signature on an [UnverifiedExternalMessage] and returns a [VerifiedExternalMessage] if the
    /// verification is successful.
    /// This function implements the following checks:
    ///  - ValSem010
    pub(crate) fn into_verified(
        self,
        backend: &impl OpenMlsCryptoProvider,
        signature_key: &SignaturePublicKey,
    ) -> Result<VerifiedExternalMessage, ValidationError> {
        // ValSem010
        self.plaintext
            .verify_with_key(backend, signature_key)
            .map(|_plaintext| VerifiedExternalMessage { _plaintext })
            .map_err(|_| ValidationError::InvalidSignature)
    }
}

/// Member message, where all semantic checks on the framing have been successfully performed.
pub(crate) struct VerifiedMemberMessage {
    plaintext: MlsPlaintext,
}

impl VerifiedMemberMessage {
    /// Returns a reference to the inner [MlsPlaintext].
    pub(crate) fn plaintext(&self) -> &MlsPlaintext {
        &self.plaintext
    }

    /// Consumes the message and returns the inner [MlsPlaintext].
    pub(crate) fn take_plaintext(self) -> MlsPlaintext {
        self.plaintext
    }
}

/// External message, where all semantic checks on the framing have been successfully performed.
/// Note: External messages are not fully supported yet #106
pub(crate) struct VerifiedExternalMessage {
    _plaintext: MlsPlaintext,
}

impl VerifiedExternalMessage {
    /// Returns a reference to the inner [MlsPlaintext].
    pub(crate) fn _plaintext(&self) -> &MlsPlaintext {
        &self._plaintext
    }

    /// Consumes the message and returns the inner [MlsPlaintext].
    pub(crate) fn _take_plaintext(self) -> MlsPlaintext {
        self._plaintext
    }
}

/// A message that has passed all syntax and semantics checks.
///
/// See the variants' documentation for more information.
/// [`StagedCommit`] and [`QueuedProposal`] can be inspected for authorization purposes.
#[derive(Debug)]
pub enum ProcessedMessage {
    /// An application message.
    ///
    /// The [`ApplicationMessage`] contains a vector of bytes that can be used right-away.
    ApplicationMessage(ApplicationMessage),
    /// A standalone proposal.
    ///
    /// The [`QueuedProposal`] can be inspected for authorization purposes by the application.
    /// If the proposal is deemed to be allowed, it should be added to the group's proposal
    /// queue using [`MlsGroup::store_pending_proposal()`](crate::group::mls_group::MlsGroup::store_pending_proposal()).
    ProposalMessage(Box<QueuedProposal>),
    /// A Commit message.
    ///
    /// The [`StagedCommit`] can be inspected for authorization purposes by the application.
    /// If the type of the commit and the proposals it covers are deemed to be allowed,
    /// the commit should be merged into the group's state using
    /// [`MlsGroup::merge_staged_commit()`](crate::group::mls_group::MlsGroup::merge_staged_commit()).
    StagedCommitMessage(Box<StagedCommit>),
}

/// Application message received through a [ProcessedMessage].
#[derive(Debug, PartialEq, Eq)]
pub struct ApplicationMessage {
    bytes: Vec<u8>,
}

impl ApplicationMessage {
    /// Create a new [ApplicationMessage].
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the inner bytes and consumes the [`ApplicationMessage`].
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
