//! # Validation steps for incoming messages
//!
//! ```text
//!
//!                             MlsMessageIn
//!                                  │                    -.
//!                                  │                      │
//!                                  │                      │
//!                                  ▼                      │
//!                               Message                   +-- parse_message
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

use openmls_traits::types::Ciphersuite;

use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::signable::Verifiable,
    extensions::ExternalSendersExtension,
    group::{
        core_group::{proposals::QueuedProposal, staged_commit::StagedCommit},
        errors::ValidationError,
    },
    storage::OpenMlsProvider,
    treesync::TreeSync,
    versions::ProtocolVersion,
};

use self::mls_group::errors::ProcessMessageError;

use super::{
    mls_auth_content::AuthenticatedContent,
    mls_auth_content_in::{AuthenticatedContentIn, VerifiableAuthenticatedContentIn},
    *,
};

/// Intermediate message that can be constructed either from a public message or from private message.
/// If it is constructed from a ciphertext message, the ciphertext message is decrypted first.
#[derive(Debug)]
pub(crate) struct Message {
    pub(crate) verifiable_content: VerifiableAuthenticatedContentIn,
}

impl Message {
    /// Gets the correct credential from the message depending on the sender type.
    ///
    /// - Member:
    ///     - Credential from the leaf node
    ///     - Credential from an old leaf when the leaf index is not valid anymore
    /// - External: Credential from the `ExternalSender` extensions
    /// - NewMember:
    ///     - Commit: Credential from the leaf node in the update path
    ///     - Proposal: Credential from the key package in the add proposal (no other proposals are allowed)
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
    pub(crate) fn sender(&self) -> &Sender {
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
    pub(crate) fn from_message(
        decrypted_message: Message,
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
    pub(crate) fn verify<Provider: OpenMlsProvider>(
        self,
        ciphersuite: Ciphersuite,
        provider: &Provider,
        protocol_version: ProtocolVersion,
    ) -> Result<(AuthenticatedContent, Credential), ProcessMessageError<Provider::StorageError>>
    {
        let content: AuthenticatedContentIn = self
            .verifiable_content
            .verify(provider.crypto(), &self.sender_pk)
            .map_err(|_| ProcessMessageError::InvalidSignature)?;
        let content = content.validate(
            ciphersuite,
            provider.crypto(),
            self.sender_context,
            protocol_version,
        )?;
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
