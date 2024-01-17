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
//!                                  │                    -.
//!                                  │                      │
//!                                  │                      +-- process_unverified_message
//!                                  │                      │
//!                                  ▼                    -'
//!                          ProcessedMessage
//!
//! ```
// TODO #106/#151: Update the above diagram

use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};

use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::signable::Verifiable,
    error::LibraryError,
    extensions::ExternalSendersExtension,
    group::{
        core_group::{proposals::QueuedProposal, staged_commit::StagedCommit},
        errors::ValidationError,
    },
    tree::sender_ratchet::SenderRatchetConfiguration,
    treesync::TreeSync,
    versions::ProtocolVersion,
};

use self::mls_group::errors::ProcessMessageError;

use super::{
    mls_auth_content::AuthenticatedContent,
    mls_auth_content_in::{AuthenticatedContentIn, VerifiableAuthenticatedContentIn},
    private_message_in::PrivateMessageIn,
    public_message_in::PublicMessageIn,
    *,
};

/// Intermediate message that can be constructed either from a public message or from private message.
/// If it it constructed from a ciphertext message, the ciphertext message is decrypted first.
/// This function implements the following checks:
///  - ValSem005
///  - ValSem007
///  - ValSem009
#[derive(Debug)]
pub(crate) struct DecryptedMessage {
    verifiable_content: VerifiableAuthenticatedContentIn,
}

impl DecryptedMessage {
    /// Constructs a [DecryptedMessage] from a [VerifiableAuthenticatedContent].
    pub(crate) fn from_inbound_public_message<'a>(
        public_message: PublicMessageIn,
        message_secrets_option: impl Into<Option<&'a MessageSecrets>>,
        serialized_context: Vec<u8>,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<Self, ValidationError> {
        if public_message.sender().is_member() {
            // ValSem007 Membership tag presence
            if public_message.membership_tag().is_none() {
                return Err(ValidationError::MissingMembershipTag);
            }

            if let Some(message_secrets) = message_secrets_option.into() {
                // Verify the membership tag. This needs to be done explicitly for PublicMessage messages,
                // it is implicit for PrivateMessage messages (because the encryption can only be known by members).
                // ValSem008
                public_message.verify_membership(
                    crypto,
                    message_secrets.membership_key(),
                    message_secrets.serialized_context(),
                )?;
            }
        }

        let verifiable_content = public_message.into_verifiable_content(serialized_context);

        Self::from_verifiable_content(verifiable_content)
    }

    /// Constructs a [DecryptedMessage] from a [PrivateMessage] by attempting to decrypt it
    /// to a [VerifiableAuthenticatedContent] first.
    pub(crate) fn from_inbound_ciphertext(
        ciphertext: PrivateMessageIn,
        crypto: &impl OpenMlsCrypto,
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
        let sender_data = ciphertext.sender_data(message_secrets, crypto, ciphersuite)?;
        let message_secrets = group
            .message_secrets_mut(ciphertext.epoch())
            .map_err(|_| MessageDecryptionError::AeadError)?;
        let verifiable_content = ciphertext.to_verifiable_content(
            ciphersuite,
            crypto,
            message_secrets,
            sender_data.leaf_index,
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
        verifiable_content: VerifiableAuthenticatedContentIn,
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
    ///
    /// Returns the [`Credential`] and the leaf's [`SignaturePublicKey`].
    pub(crate) fn credential(
        &self,
        treesync: &TreeSync,
        old_leaves: &[Member],
        external_senders: Option<&ExternalSendersExtension>,
    ) -> Result<CredentialWithKey, ValidationError> {
        let sender = self.sender();
        match sender {
            Sender::Member(leaf_index) => {
                match treesync.leaf(*leaf_index) {
                    Some(sender_leaf) => {
                        let credential = sender_leaf.credential().clone();
                        let pk = sender_leaf.signature_key().clone();
                        Ok(CredentialWithKey {
                            credential,
                            signature_key: pk,
                        })
                    }
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
                                Some(node) => {
                                    let credential = node.credential().clone();
                                    let signature_key = node.signature_key().clone();
                                    Ok(CredentialWithKey {
                                        credential,
                                        signature_key,
                                    })
                                }
                                None => Err(ValidationError::UnknownMember),
                            }
                        } else {
                            Err(ValidationError::UnknownMember)
                        }
                    }
                }
            }
            Sender::External(index) => {
                let sender = external_senders
                    .ok_or(ValidationError::NoExternalSendersExtension)?
                    .get(index.index())
                    .ok_or(ValidationError::UnauthorizedExternalSender)?;
                Ok(CredentialWithKey {
                    credential: sender.credential().clone(),
                    signature_key: sender.signature_key().clone(),
                })
            }
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
    pub(crate) fn verifiable_content(&self) -> &VerifiableAuthenticatedContentIn {
        &self.verifiable_content
    }
}

/// Context that is needed to verify the signature of a the leaf node of an
/// UpdatePath or an update proposal.
#[derive(Debug, Clone)]
pub(crate) enum SenderContext {
    Member((GroupId, LeafNodeIndex)),
    ExternalCommit((GroupId, LeafNodeIndex)),
}

/// Partially checked and potentially decrypted message (if it was originally encrypted).
/// Use this to inspect the [`Credential`] of the message sender
/// and the optional `aad` if the original message was encrypted.
/// The [`OpenMlsSignaturePublicKey`] is used to verify the signature of the
/// message.
#[derive(Debug, Clone)]
pub(crate) struct UnverifiedMessage {
    verifiable_content: VerifiableAuthenticatedContentIn,
    credential: Credential,
    sender_pk: OpenMlsSignaturePublicKey,
    sender_context: Option<SenderContext>,
}

impl UnverifiedMessage {
    /// Construct an [UnverifiedMessage] from a [DecryptedMessage] and an optional [Credential].
    pub(crate) fn from_decrypted_message(
        decrypted_message: DecryptedMessage,
        credential: Credential,
        sender_pk: OpenMlsSignaturePublicKey,
        sender_context: Option<SenderContext>,
    ) -> Self {
        UnverifiedMessage {
            verifiable_content: decrypted_message.verifiable_content,
            credential,
            sender_pk,
            sender_context,
        }
    }

    /// Verify the [`UnverifiedMessage`]. Returns the [`AuthenticatedContent`]
    /// and the internal [`Credential`].
    pub(crate) fn verify(
        self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        protocol_version: ProtocolVersion,
    ) -> Result<(AuthenticatedContent, Credential), ProcessMessageError> {
        let content: AuthenticatedContentIn = self
            .verifiable_content
            .verify(crypto, &self.sender_pk)
            .map_err(|_| ProcessMessageError::InvalidSignature)?;
        let content =
            content.validate(ciphersuite, crypto, self.sender_context, protocol_version)?;
        Ok((content, self.credential))
    }

    /// Get the content type of the message.
    pub(crate) fn content_type(&self) -> ContentType {
        self.verifiable_content.content_type()
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
    credential: Credential,
}

impl ProcessedMessage {
    /// Create a new `ProcessedMessage`.
    pub(crate) fn new(
        group_id: GroupId,
        epoch: GroupEpoch,
        sender: Sender,
        authenticated_data: Vec<u8>,
        content: ProcessedMessageContent,
        credential: Credential,
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

    /// Returns the credential of the message.
    pub fn credential(&self) -> &Credential {
        &self.credential
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
