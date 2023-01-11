//! # Validation steps for incoming messages
//!
//! ```text
//!
//!                             MlsMessageIn
//!                                  │                    -.
//!                                  │                      │
//!                                  │                      │
//!                                  ▼                      │
//!                           DecryptedMessage              +-- parse_message
//!                                  │                      │
//!                                  │                      │
//!                                  │                      │
//!                                  ▼                    -'
//!                           UnverifiedMessage
//!                                  │                                       -.
//!                                  │                                         │
//!                                  │                                         │
//!                                  ▼                                         │
//!                       UnverifiedContextMessage                             │
//!                                  │                                         │
//!                                  │                                         │
//!             (sender is member)   │   (sender is external)                  │
//!               ┌──────────────────┴───────────────────┐                     │
//!               │                                      │                     │
//!               ▼                                      ▼                     +-- process_unverified_message
//!     UnverifiedGroupMessage              UnverifiedExternalMessage          │
//!               │                                      │                     │
//!               │ (verify_signature)                   │ (verify_signature)  │
//!               │                                      │                     │
//!               ▼                                      ▼                     │
//!     VerifiedMemberMessage                VerifiedExternalMessage           │
//!               │                                      │                     │
//!               └──────────────────┬───────────────────┘                     │
//!                                  │                                         │
//!                                  ▼                                       -'
//!                          ProcessedMessage
//!
//! ```
// TODO #106/#151: Update the above diagram

use crate::{group::errors::ValidationError, tree::index::SecretTreeLeafIndex, treesync::TreeSync};
use core_group::{proposals::QueuedProposal, staged_commit::StagedCommit};
use openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};

use crate::{
    ciphersuite::signable::Verifiable, error::LibraryError,
    tree::sender_ratchet::SenderRatchetConfiguration,
};

use super::{
    mls_auth_content::{AuthenticatedContent, VerifiableAuthenticatedContent},
    mls_content::ContentType,
    *,
};

/// Intermediate message that can be constructed either from a public message or from private message.
/// If it it constructed from a ciphertext message, the ciphertext message is decrypted first.
/// This function implements the following checks:
///  - ValSem005
///  - ValSem007
///  - ValSem009
pub(crate) struct DecryptedMessage {
    verifiable_content: VerifiableAuthenticatedContent,
}

impl DecryptedMessage {
    /// Constructs a [DecryptedMessage] from a [VerifiableAuthenticatedContent].
    pub(crate) fn from_inbound_public_message(
        mut public_message: PublicMessage,
        message_secrets: &MessageSecrets,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, ValidationError> {
        // Set the context for verification (happens only for the correct sender types).
        public_message.set_context(message_secrets.serialized_context());
        if public_message.sender().is_member() {
            // Verify the membership tag. This needs to be done explicitly for PublicMessage messages,
            // it is implicit for PrivateMessage messages (because the encryption can only be known by members).
            // ValSem007 Membership tag presence
            // ValSem008
            public_message.verify_membership(backend, message_secrets.membership_key())?;
        }

        let verifiable_content = public_message.into();

        Self::from_verifiable_content(verifiable_content)
    }

    /// Constructs a [DecryptedMessage] from a [PrivateMessage] by attempting to decrypt it
    /// to a [VerifiableAuthenticatedContent] first.
    pub(crate) fn from_inbound_ciphertext(
        ciphertext: PrivateMessage,
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
        let sender_index = SecretTreeLeafIndex::from(sender_data.leaf_index);
        let message_secrets = group
            .message_secrets_mut(ciphertext.epoch())
            .map_err(|_| MessageDecryptionError::AeadError)?;
        let verifiable_content = ciphertext.to_verifiable_content(
            ciphersuite,
            backend,
            message_secrets,
            sender_index,
            sender_ratchet_configuration,
            sender_data,
        )?;
        Self::from_verifiable_content(verifiable_content)
    }

    // Internal constructor function. Does the following checks:
    // - Confirmation tag must be present for Commit messages
    // - Membership tag must be present for member messages, if the original incoming message was not an PrivateMessage
    // - Ensures application messages were originally PrivateMessage messages
    fn from_verifiable_content(
        verifiable_content: VerifiableAuthenticatedContent,
    ) -> Result<Self, ValidationError> {
        // ValSem009
        if verifiable_content.content_type() == ContentType::Commit
            && verifiable_content.confirmation_tag().is_none()
        {
            return Err(ValidationError::MissingConfirmationTag);
        }
        // ValSem005
        if verifiable_content.content_type() == ContentType::Application {
            if verifiable_content.wire_format() != WireFormat::PrivateMessage {
                return Err(ValidationError::UnencryptedApplicationMessage);
            } else if !verifiable_content.sender().is_member() {
                // This should not happen because the sender of an PrivateMessage should always be a member
                return Err(LibraryError::custom("Expected sender to be member.").into());
            }
        }
        Ok(DecryptedMessage { verifiable_content })
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
                match treesync.leaf(*leaf_index) {
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
                            match treesync.leaf(*index) {
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
                self.verifiable_content.new_member_credential()
            }
        }
    }

    /// Returns the sender.
    pub fn sender(&self) -> &Sender {
        self.verifiable_content.sender()
    }

    /// Returns the [`VerifiableAuthenticatedContent`].
    pub(crate) fn verifiable_content(&self) -> &VerifiableAuthenticatedContent {
        &self.verifiable_content
    }
}

/// Partially checked and potentially decrypted message (if it was originally encrypted).
/// Use this to inspect the [`Credential`] of the message sender
/// and the optional `aad` if the original message was encrypted.
#[derive(Debug, Clone)]
pub(crate) struct UnverifiedMessage {
    verifiable_content: VerifiableAuthenticatedContent,
    credential: Option<Credential>,
}

impl UnverifiedMessage {
    /// Construct an [UnverifiedMessage] from a [DecryptedMessage] and an optional [Credential].
    pub(crate) fn from_decrypted_message(
        decrypted_message: DecryptedMessage,
        credential: Option<Credential>,
    ) -> Self {
        UnverifiedMessage {
            verifiable_content: decrypted_message.verifiable_content,
            credential,
        }
    }

    /// Decomposes an [UnverifiedMessage] into its parts.
    pub(crate) fn into_parts(self) -> (VerifiableAuthenticatedContent, Option<Credential>) {
        (self.verifiable_content, self.credential)
    }
}

/// Contains an VerifiableAuthenticatedContent and a [Credential] if it is a message
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
        let (verifiable_content, credential_option) = unverified_message.into_parts();
        match verifiable_content.sender() {
            Sender::Member(_) => {
                Ok(UnverifiedContextMessage::Group(UnverifiedGroupMessage {
                    verifiable_content,
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
                        verifiable_content,
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
    verifiable_content: VerifiableAuthenticatedContent,
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
        ciphersuite: Ciphersuite,
    ) -> Result<VerifiedMemberMessage, ValidationError> {
        // ValSem010
        self.verifiable_content
            .verify(
                backend,
                self.credential.signature_key(),
                ciphersuite.signature_algorithm(),
            )
            .map(|authenticated_content| VerifiedMemberMessage {
                authenticated_content,
            })
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
    verifiable_content: VerifiableAuthenticatedContent,
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
        ciphersuite: Ciphersuite,
    ) -> Result<VerifiedExternalMessage, ValidationError> {
        // ValSem010
        let verified_external_message = self
            .verifiable_content
            .verify(
                backend,
                self.credential.signature_key(),
                ciphersuite.signature_algorithm(),
            )
            .map(|authenticated_content| VerifiedExternalMessage {
                authenticated_content,
            })
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
    _verifiable_content: VerifiableAuthenticatedContent,
}

/// Member message, where all semantic checks on the framing have been successfully performed.
#[derive(Debug)]
pub(crate) struct VerifiedMemberMessage {
    authenticated_content: AuthenticatedContent,
}

impl VerifiedMemberMessage {
    /// Consumes the message and returns the inner [PublicMessage].
    pub(crate) fn take_authenticated_content(self) -> AuthenticatedContent {
        self.authenticated_content
    }
}

/// External message, where all semantic checks on the framing have been successfully performed.
/// Note: External messages are not fully supported yet #106
pub(crate) struct VerifiedExternalMessage {
    authenticated_content: AuthenticatedContent,
}

impl VerifiedExternalMessage {
    /// Returns a reference to the inner [FramedContent].
    pub(crate) fn authenticated_content(&self) -> &AuthenticatedContent {
        &self.authenticated_content
    }

    /// Consumes the message and returns the inner [PublicMessage].
    pub(crate) fn take_authenticated_content(self) -> AuthenticatedContent {
        self.authenticated_content
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
