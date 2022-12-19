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
//! UnverifiedGroupMessage   UnverifiedExternalMessage
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
// TODO #106/#151: Update the above diagram

use crate::{group::errors::ValidationError, tree::index::SecretTreeLeafIndex, treesync::TreeSync};
use core_group::{proposals::QueuedProposal, staged_commit::StagedCommit};
use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    ciphersuite::signable::Verifiable, error::LibraryError,
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
    plaintext: VerifiableMlsAuthContent,
}

impl DecryptedMessage {
    /// Constructs a [DecryptedMessage] from a [VerifiableMlsAuthContent].
    pub(crate) fn from_inbound_plaintext(
        plaintext: MlsPlaintext,
        message_secrets: &MessageSecrets,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, ValidationError> {
        if plaintext.sender().is_member() {
            // Verify the membership tag. This needs to be done explicitly for MlsPlaintext messages,
            // it is implicit for MlsCiphertext messages (because the encryption can only be known by members).
            // ValSem007 Membership tag presence
            // ValSem008
            plaintext.verify_membership(
                backend,
                message_secrets.membership_key(),
                message_secrets.serialized_context(),
            )?;
        }

        let context = if matches!(
            plaintext.sender(),
            Sender::NewMemberCommit | Sender::Member(_)
        ) {
            Some(message_secrets.serialized_context().to_vec())
        } else {
            None
        };

        Self::from_plaintext(VerifiableMlsAuthContent::from_plaintext(plaintext, context))
    }

    /// Constructs a [DecryptedMessage] from a [MlsCiphertext] by attempting to decrypt it
    /// to a [VerifiableMlsAuthContent] first.
    pub(crate) fn from_inbound_ciphertext(
        ciphertext: MlsCiphertext,
        backend: &impl OpenMlsCryptoProvider,
        group: &mut CoreGroup,
        sender_ratchet_configuration: &SenderRatchetConfiguration,
    ) -> Result<Self, ValidationError> {
        // This will be refactored with #265.
        let ciphersuite = group.ciphersuite();
        // TODO: #819 The old leaves should not be needed any more.
        //       Revisit when the transition is further along.
        let (message_secrets, _old_leaves) = group
            .message_secrets_and_leaves_mut(ciphertext.epoch())
            .map_err(|_| MessageDecryptionError::AeadError)?;
        let sender_data = ciphertext.sender_data(message_secrets, backend, ciphersuite)?;
        let sender_index = SecretTreeLeafIndex(sender_data.leaf_index);
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
    }

    // Internal constructor function. Does the following checks:
    // - Confirmation tag must be present for Commit messages
    // - Membership tag must be present for member messages, if the original incoming message was not an MlsCiphertext
    // - Ensures application messages were originally MlsCiphertext messages
    fn from_plaintext(plaintext: VerifiableMlsAuthContent) -> Result<Self, ValidationError> {
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
    ///  - ValSem245
    ///  - Prepares ValSem246 by setting the right credential. The remainder
    ///    of ValSem246 is validated as part of ValSem010.
    pub(crate) fn credential(
        &self,
        treesync: &TreeSync,
        old_leaves: &[Member],
    ) -> Result<Credential, ValidationError> {
        let sender = self.sender();
        match sender {
            Sender::Member(leaf_index) => {
                match treesync
                    .leaf(*leaf_index)
                    .map_err(|_| ValidationError::UnknownMember)?
                {
                    Some(sender_leaf) => Ok(sender_leaf.credential().clone()),
                    None => {
                        // This might not actually be an error but the sender's
                        // key package changed. Let's check old leaves we still
                        // have around.
                        // TODO: As part of #819 looking up old leaves changes.
                        //       Just checking the index is probably not enough.
                        //       Revisit when the transition is further along
                        //       and we have better test cases.
                        if let Some(Member { index, .. }) = old_leaves
                            .iter()
                            .find(|&old_member| *leaf_index == old_member.index)
                        {
                            match treesync
                                .leaf(*index)
                                .map_err(|_| ValidationError::UnknownMember)?
                            {
                                Some(node) => Ok(node.credential().clone()),
                                None => Err(ValidationError::UnknownMember),
                            }
                        } else {
                            Err(ValidationError::UnknownMember)
                        }
                    }
                }
            }
            // External senders are not supported yet #106/#151.
            Sender::External(_) => unimplemented!(),
            Sender::NewMemberCommit | Sender::NewMemberProposal => {
                // Fetch the credential from the message itself.
                self.plaintext.new_member_credential()
            }
        }
    }

    /// Returns the sender.
    pub fn sender(&self) -> &Sender {
        self.plaintext.sender()
    }

    /// Returns the plaintext.
    pub(crate) fn plaintext(&self) -> &VerifiableMlsAuthContent {
        &self.plaintext
    }
}

/// Partially checked and potentially decrypted message (if it was originally encrypted).
/// Use this to inspect the [`Credential`] of the message sender
/// and the optional `aad` if the original message was encrypted.
#[derive(Debug, Clone)]
pub(crate) struct UnverifiedMessage {
    plaintext: VerifiableMlsAuthContent,
    credential: Option<Credential>,
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
        }
    }

    /// Decomposes an [UnverifiedMessage] into its parts.
    pub(crate) fn into_parts(self) -> (VerifiableMlsAuthContent, Option<Credential>) {
        (self.plaintext, self.credential)
    }
}

/// Contains an VerifiableMlsAuthContent and a [Credential] if it is a message
/// from a `Member`, a `Preconfigured`, a `NewMemberProposal` or a `NewMemberCommit`. It sets the
/// serialized group context and verifies the membership tag for member messages. It can be
/// converted to a verified message by verifying the signature, either with the credential or an
/// external signature key.
pub(crate) enum UnverifiedContextMessage {
    /// Unverified message from a group member
    Group(UnverifiedGroupMessage),
    /// Unverified message from either a `NewMemberProposal` or a `NewMemberCommit`
    NewMember(UnverifiedNewMemberMessage),
    /// Unverified message from an external sender
    /// TODO: #106
    #[allow(dead_code)]
    External(UnverifiedExternalMessage),
}

impl UnverifiedContextMessage {
    /// Constructs an [UnverifiedContextMessage] from an [UnverifiedMessage].
    pub(crate) fn from_unverified_message(
        unverified_message: UnverifiedMessage,
    ) -> Result<Self, LibraryError> {
        // Decompose UnverifiedMessage
        let (plaintext, credential_option) = unverified_message.into_parts();
        match plaintext.sender() {
            Sender::Member(_) => {
                Ok(UnverifiedContextMessage::Group(UnverifiedGroupMessage {
                    plaintext,
                    // If the message type is `Member` it always contains credentials
                    credential: credential_option
                        .ok_or_else(|| LibraryError::custom("Expected credential"))?,
                }))
            }
            // TODO #151/#106: We don't support external senders yet
            Sender::External(_) => unimplemented!(),
            Sender::NewMemberProposal | Sender::NewMemberCommit => {
                Ok(UnverifiedContextMessage::NewMember(
                    UnverifiedNewMemberMessage {
                        plaintext,
                        // If the message type is `NewMemberCommit` or `NewMemberProposal` it always contains credentials
                        credential: credential_option
                            .ok_or_else(|| LibraryError::custom("Expected credential"))?,
                    },
                ))
            }
        }
    }
}

/// Part of [UnverifiedContextMessage].
pub(crate) struct UnverifiedGroupMessage {
    plaintext: VerifiableMlsAuthContent,
    credential: Credential,
}

impl UnverifiedGroupMessage {
    /// Verifies the signature on an [UnverifiedGroupMessage] and returns a [VerifiedMemberMessage] if the
    /// verification is successful.
    /// This function implements the following checks:
    ///  - ValSem010
    pub(crate) fn into_verified(
        self,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<VerifiedMemberMessage, ValidationError> {
        // ValSem010
        self.plaintext
            .verify(backend, &self.credential)
            .map(|plaintext| VerifiedMemberMessage { plaintext })
            .map_err(|_| ValidationError::InvalidSignature)
        // XXX: We have tests checking for errors here. But really we should
        //      rewrite them.
        // debug_assert!(
        //     verified_member_message.is_ok(),
        //     "Verifying signature on UnverifiedGroupMessage failed with {:?}",
        //     verified_member_message
        // );
    }

    /// Returns the credential.
    pub(crate) fn credential(&self) -> &Credential {
        &self.credential
    }
}

/// Part of [UnverifiedContextMessage].
pub(crate) struct UnverifiedNewMemberMessage {
    plaintext: VerifiableMlsAuthContent,
    credential: Credential,
}

impl UnverifiedNewMemberMessage {
    /// Verifies the signature of an [UnverifiedNewMemberMessage] and returns a
    /// [VerifiedExternalMessage] if the verification is successful.
    /// This function implements the following checks:
    /// - ValSem010
    pub(crate) fn into_verified(
        self,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<VerifiedExternalMessage, ValidationError> {
        // ValSem010
        let verified_external_message = self
            .plaintext
            .verify(backend, &self.credential)
            .map(|plaintext| VerifiedExternalMessage { plaintext })
            .map_err(|_| ValidationError::InvalidSignature)?;
        Ok(verified_external_message)
    }

    /// Returns the credential.
    pub(crate) fn credential(&self) -> &Credential {
        &self.credential
    }
}

// TODO #151/#106: We don't support external senders yet
/// Part of [UnverifiedContextMessage].
pub(crate) struct UnverifiedExternalMessage {
    _plaintext: VerifiableMlsAuthContent,
}

/// Member message, where all semantic checks on the framing have been successfully performed.
#[derive(Debug)]
pub(crate) struct VerifiedMemberMessage {
    plaintext: MlsAuthContent,
}

impl VerifiedMemberMessage {
    /// Consumes the message and returns the inner [MlsPlaintext].
    pub(crate) fn take_plaintext(self) -> MlsAuthContent {
        self.plaintext
    }
}

/// External message, where all semantic checks on the framing have been successfully performed.
/// Note: External messages are not fully supported yet #106
pub(crate) struct VerifiedExternalMessage {
    plaintext: MlsAuthContent,
}

impl VerifiedExternalMessage {
    /// Returns a reference to the inner [MlsContent].
    pub(crate) fn plaintext(&self) -> &MlsAuthContent {
        &self.plaintext
    }

    /// Consumes the message and returns the inner [MlsPlaintext].
    pub(crate) fn take_plaintext(self) -> MlsAuthContent {
        self.plaintext
    }
}

/// A message that has passed all syntax and semantics checks.
#[derive(Debug)]
pub struct ProcessedMessage {
    group_id: GroupId,
    epoch: GroupEpoch,
    sender: Sender,
    authenticated_data: Vec<u8>,
    content: ProcessedMessageContent,
    credential: Option<Credential>,
}

impl ProcessedMessage {
    /// Create a new `ProcessedMessage`.
    pub(crate) fn new(
        group_id: GroupId,
        epoch: GroupEpoch,
        sender: Sender,
        authenticated_data: Vec<u8>,
        content: ProcessedMessageContent,
        credential: Option<Credential>,
    ) -> Self {
        Self {
            group_id,
            epoch,
            sender,
            authenticated_data,
            content,
            credential,
        }
    }

    /// Returns the group ID of the message.
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// Returns the epoch of the message.
    pub fn epoch(&self) -> GroupEpoch {
        self.epoch
    }

    /// Returns the sender of the message.
    pub fn sender(&self) -> &Sender {
        &self.sender
    }

    /// Returns the authenticated data of the message.
    pub fn authenticated_data(&self) -> &[u8] {
        &self.authenticated_data
    }

    /// Returns the content of the message.
    pub fn content(&self) -> &ProcessedMessageContent {
        &self.content
    }

    /// Returns the content of the message and consumes the message.
    pub fn into_content(self) -> ProcessedMessageContent {
        self.content
    }

    /// Returns the credential of the message if present.
    pub fn credential(&self) -> Option<&Credential> {
        self.credential.as_ref()
    }
}

/// Content of a processed message.
///
/// See the content variants' documentation for more information.
/// [`StagedCommit`] and [`QueuedProposal`] can be inspected for authorization purposes.
#[derive(Debug)]
pub enum ProcessedMessageContent {
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
    /// An [external join proposal](crate::prelude::JoinProposal) sent by a
    /// [NewMemberProposal](crate::prelude::Sender::NewMemberProposal) sender which is outside the group.
    ///
    /// Since this originates from a party outside the group, the [`QueuedProposal`] SHOULD be
    /// inspected for authorization purposes by the application. If the proposal is deemed to be
    /// allowed, it should be added to the group's proposal queue using
    /// [`MlsGroup::store_pending_proposal()`](crate::group::mls_group::MlsGroup::store_pending_proposal()).
    ExternalJoinProposalMessage(Box<QueuedProposal>),
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
