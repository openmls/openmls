//! # MLS group errors
//!
//! This module contains errors that originate at lower levels and are partially re-exported in errors thrown by functions of the `MlsGroup` API.

use thiserror::Error;

pub use super::mls_group::errors::*;
use super::public_group::errors::CreationFromExternalError;
use crate::{
    ciphersuite::signable::SignatureError,
    error::LibraryError,
    extensions::errors::{ExtensionError, InvalidExtensionError},
    framing::errors::MessageDecryptionError,
    group::commit_builder::external_commits::ExternalCommitBuilderError,
    key_packages::errors::{KeyPackageExtensionSupportError, KeyPackageVerifyError},
    messages::{group_info::GroupInfoError, GroupSecretsError},
    schedule::errors::PskError,
    treesync::errors::*,
};

#[cfg(doc)]
use crate::treesync::LeafNodeParameters;

/// Welcome error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum WelcomeError<StorageError> {
    /// See [`GroupSecretsError`] for more details.
    #[error(transparent)]
    GroupSecrets(#[from] GroupSecretsError),
    /// Private part of `init_key` not found in key store.
    #[error("Private part of `init_key` not found in key store.")]
    PrivateInitKeyNotFound,
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Ciphersuites in Welcome and key package bundle don't match.
    #[error("Ciphersuites in Welcome and key package bundle don't match.")]
    CiphersuiteMismatch,
    /// See [`GroupInfoError`] for more details.
    #[error(transparent)]
    GroupInfo(#[from] GroupInfoError),
    /// No joiner secret found in the Welcome message.
    #[error("No joiner secret found in the Welcome message.")]
    JoinerSecretNotFound,
    /// No ratchet tree available to build initial tree after receiving a Welcome message.
    #[error("No ratchet tree available to build initial tree after receiving a Welcome message.")]
    MissingRatchetTree,
    /// The computed confirmation tag does not match the expected one.
    #[error("The computed confirmation tag does not match the expected one.")]
    ConfirmationTagMismatch,
    /// The signature on the GroupInfo is not valid.
    #[error("The signature on the GroupInfo is not valid.")]
    InvalidGroupInfoSignature,
    /// We don't support the version of the group we are trying to join.
    #[error("We don't support the version of the group we are trying to join.")]
    UnsupportedMlsVersion,
    /// We don't support all capabilities of the group.
    #[error("We don't support all capabilities of the group.")]
    UnsupportedCapability,
    /// Sender not found in tree.
    #[error("Sender not found in tree.")]
    UnknownSender,
    /// The provided message is not a Welcome message.
    #[error("Not a Welcome message.")]
    NotAWelcomeMessage,
    /// Malformed Welcome message.
    #[error("Malformed Welcome message.")]
    MalformedWelcomeMessage,
    /// Could not decrypt the Welcome message.
    #[error("Could not decrypt the Welcome message.")]
    UnableToDecrypt,
    /// Unsupported extensions found in the KeyPackage of another member.
    #[error("Unsupported extensions found in the KeyPackage of another member.")]
    UnsupportedExtensions,
    /// See [`PskError`] for more details.
    #[error(transparent)]
    Psk(#[from] PskError),
    /// No matching encryption key was found in the key store.
    #[error("No matching encryption key was found in the key store.")]
    NoMatchingEncryptionKey,
    /// No matching key package was found in the key store.
    #[error("No matching key package was found in the key store.")]
    NoMatchingKeyPackage,
    /// This error indicates the public tree is invalid. See [`PublicTreeError`] for more details.
    #[error(transparent)]
    PublicTreeError(#[from] PublicTreeError),
    /// This error indicates the public tree is invalid. See
    /// [`CreationFromExternalError`] for more details.
    #[error(transparent)]
    PublicGroupError(#[from] CreationFromExternalError<StorageError>),
    /// This error indicates the leaf node is invalid. See [`LeafNodeValidationError`] for more details.
    #[error(transparent)]
    LeafNodeValidation(#[from] LeafNodeValidationError),
    /// This error indicates that an error occurred while reading or writing from/to storage.
    #[error("An error occurred when querying storage")]
    StorageError(StorageError),
}

/// External Commit error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ExternalCommitError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// No ratchet tree available to build initial tree.
    #[error("No ratchet tree available to build initial tree.")]
    MissingRatchetTree,
    /// No external_pub extension available to join group by external commit.
    #[error("No external_pub extension available to join group by external commit.")]
    MissingExternalPub,
    /// We don't support the ciphersuite of the group we are trying to join.
    #[error("We don't support the ciphersuite of the group we are trying to join.")]
    UnsupportedCiphersuite,
    /// Sender not found in tree.
    #[error("Sender not found in tree.")]
    UnknownSender,
    /// The signature over the given group info is invalid.
    #[error("The signature over the given group info is invalid.")]
    InvalidGroupInfoSignature,
    /// Error creating external commit.
    #[error("Error creating external commit.")]
    CommitError(#[from] CreateCommitError),
    /// This error indicates the public tree is invalid. See
    /// [`CreationFromExternalError`] for more details.
    #[error(transparent)]
    PublicGroupError(#[from] CreationFromExternalError<StorageError>),
    /// Credential is missing from external commit.
    #[error("Credential is missing from external commit.")]
    MissingCredential,
    /// An erorr occurred when writing group to storage
    #[error("An error occurred when writing group to storage.")]
    StorageError(StorageError),
}

impl<StorageError> From<ExternalCommitBuilderError<StorageError>>
    for ExternalCommitError<StorageError>
{
    fn from(error: ExternalCommitBuilderError<StorageError>) -> Self {
        match error {
            ExternalCommitBuilderError::LibraryError(library_error) => {
                ExternalCommitError::LibraryError(library_error)
            }
            ExternalCommitBuilderError::MissingRatchetTree => {
                ExternalCommitError::MissingRatchetTree
            }
            ExternalCommitBuilderError::MissingExternalPub => {
                ExternalCommitError::MissingExternalPub
            }
            ExternalCommitBuilderError::UnsupportedCiphersuite => {
                ExternalCommitError::UnsupportedCiphersuite
            }
            ExternalCommitBuilderError::PublicGroupError(creation_from_external_error) => {
                ExternalCommitError::PublicGroupError(creation_from_external_error)
            }
            ExternalCommitBuilderError::StorageError(error) => {
                ExternalCommitError::StorageError(error)
            }
            // These should not happen since `join_by_external_commit` doesn't
            // take proposals as input.
            ExternalCommitBuilderError::InvalidProposal(e) => {
                log::error!("Error validating proposal in external commit: {e}");
                ExternalCommitError::LibraryError(LibraryError::custom(
                    "Error creating external commit",
                ))
            }
        }
    }
}

impl<StorageError> From<ExternalCommitBuilderFinalizeError<StorageError>>
    for ExternalCommitError<StorageError>
{
    fn from(error: ExternalCommitBuilderFinalizeError<StorageError>) -> Self {
        match error {
            ExternalCommitBuilderFinalizeError::LibraryError(library_error) => {
                ExternalCommitError::LibraryError(library_error)
            }
            ExternalCommitBuilderFinalizeError::StorageError(error) => {
                ExternalCommitError::StorageError(error)
            }
            ExternalCommitBuilderFinalizeError::MergeCommitError(e) => {
                log::error!("Error merging external commit: {e}");
                // This shouldn't happen, since we merge our own external
                // commit.
                ExternalCommitError::LibraryError(LibraryError::custom(
                    "Error merging external commit",
                ))
            }
        }
    }
}

/// Stage Commit error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum StageCommitError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The epoch of the group context and PublicMessage didn't match.
    #[error("The epoch of the group context and PublicMessage didn't match.")]
    EpochMismatch,
    /// The Commit was created by this client.
    #[error("The Commit was created by this client.")]
    OwnCommit,
    /// stage_commit was called with an PublicMessage that is not a Commit.
    #[error("stage_commit was called with an PublicMessage that is not a Commit.")]
    WrongPlaintextContentType,
    /// Unable to verify the leaf node signature.
    #[error("Unable to verify the leaf node signature.")]
    PathLeafNodeVerificationFailure,
    /// Unable to determine commit path.
    #[error("Unable to determine commit path.")]
    RequiredPathNotFound,
    /// The confirmation Tag is missing.
    #[error("The confirmation Tag is missing.")]
    ConfirmationTagMissing,
    /// The confirmation tag is invalid.
    #[error("The confirmation tag is invalid.")]
    ConfirmationTagMismatch,
    /// The committer can't remove themselves.
    #[error("The committer can't remove themselves.")]
    AttemptedSelfRemoval,
    /// The proposal queue is missing a proposal for the commit.
    #[error("The proposal queue is missing a proposal for the commit.")]
    MissingProposal,
    /// Missing own key to apply proposal.
    #[error("Missing own key to apply proposal.")]
    OwnKeyNotFound,
    /// External Committer used the wrong index.
    #[error("External Committer used the wrong index.")]
    InconsistentSenderIndex,
    /// The sender is of type external, which is not valid.
    #[error("The sender is of type external, which is not valid.")]
    SenderTypeExternal,
    /// The sender is of type `NewMemberProposal`, which is not valid.
    #[error("The sender is of type NewMemberProposal, which is not valid.")]
    SenderTypeNewMemberProposal,
    /// Too many new members: the tree is full.
    #[error("Too many new members: the tree is full.")]
    TooManyNewMembers,
    /// See [`ProposalValidationError`] for more details.
    #[error(transparent)]
    ProposalValidationError(#[from] ProposalValidationError),
    /// See [`PskError`] for more details.
    #[error(transparent)]
    PskError(#[from] PskError),
    /// See [`ExternalCommitValidationError`] for more details.
    #[error(transparent)]
    ExternalCommitValidation(#[from] ExternalCommitValidationError),
    /// See [`ApplyUpdatePathError`] for more details.
    #[error(transparent)]
    UpdatePathError(#[from] ApplyUpdatePathError),
    /// Missing decryption key.
    #[error("Missing decryption key.")]
    MissingDecryptionKey,
    /// See [`UpdatePathError`] for more details.
    #[error(transparent)]
    VerifiedUpdatePathError(#[from] UpdatePathError),
    /// See [`GroupContextExtensionsProposalValidationError`] for more details.
    #[error(transparent)]
    GroupContextExtensionsProposalValidationError(
        #[from] GroupContextExtensionsProposalValidationError,
    ),
    #[cfg(feature = "extensions-draft-08")]
    /// See [`AppDataUpdateValidationError`] for more details.
    #[error(transparent)]
    AppDataUpdateValidationError(#[from] AppDataUpdateValidationError),
    /// See [`LeafNodeValidationError`] for more details.
    #[error(transparent)]
    LeafNodeValidation(#[from] LeafNodeValidationError),
}

/// Create commit error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CreateCommitError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Missing own key to apply proposal.
    #[error("Missing own key to apply proposal.")]
    OwnKeyNotFound,
    /// The Commit tried to remove self from the group. This is not possible.
    #[error("The Commit tried to remove self from the group. This is not possible.")]
    CannotRemoveSelf,
    /// The proposal queue is missing a proposal for the commit.
    #[error("The proposal queue is missing a proposal for the commit.")]
    MissingProposal,
    /// A proposal has the wrong sender type.
    #[error("A proposal has the wrong sender type.")]
    WrongProposalSenderType,
    /// See [`PskError`] for more details.
    #[error(transparent)]
    PskError(#[from] PskError),
    /// See [`ProposalValidationError`] for more details.
    #[error(transparent)]
    ProposalValidationError(#[from] ProposalValidationError),
    /// See [`SignatureError`] for more details.
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    /// Credential is missing from external commit.
    #[error("Credential is missing from external commit.")]
    MissingCredential,
    /// This error indicates the public tree is invalid. See [`PublicTreeError`] for more details.
    #[error(transparent)]
    PublicTreeError(#[from] PublicTreeError),
    /// See [`InvalidExtensionError`] for more details.
    #[error(transparent)]
    InvalidExtensionError(#[from] InvalidExtensionError),
    #[cfg(feature = "extensions-draft-08")]
    /// See [`AppDataUpdateValidationError`] for more details.
    #[error(transparent)]
    AppDataUpdateValidationError(#[from] AppDataUpdateValidationError),
    /// See [`GroupContextExtensionsProposalValidationError`] for more details.
    #[error(transparent)]
    GroupContextExtensionsProposalValidationError(
        #[from] GroupContextExtensionsProposalValidationError,
    ),
    /// See [`TreeSyncAddLeaf`] for more details.
    #[error(transparent)]
    TreeSyncAddLeaf(#[from] TreeSyncAddLeaf),
    /// Invalid [`LeafNodeParameters`]. `[CredentialWithKey]` can't be set with new signer.
    #[error("Invalid LeafNodeParameters. CredentialWithKey can't be set with new signer.")]
    InvalidLeafNodeParameters,
    /// Invalid external commit.
    #[error("Invalid external commit.")]
    InvalidExternalCommit(#[from] ExternalCommitValidationError),
}

/// Stage commit error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CommitBuilderStageError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Error interacting with storage.
    #[error("Error interacting with storage.")]
    KeyStoreError(StorageError),
}

/// Stage commit error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ExternalCommitBuilderFinalizeError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Error interacting with storage.
    #[error("Error interacting with storage.")]
    StorageError(StorageError),
    /// Error merging external commit.
    #[error("Error merging external commit.")]
    MergeCommitError(#[from] MergePendingCommitError<StorageError>),
}

/// Validation error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ValidationError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Message group ID differs from the group's group ID.
    #[error("Message group ID differs from the group's group ID.")]
    WrongGroupId,
    /// Message epoch differs from the group's epoch.
    #[error("Message epoch differs from the group's epoch.")]
    WrongEpoch,
    /// The PublicMessage is not a Commit despite the sender begin of type [NewMemberCommit](crate::prelude::Sender::NewMemberCommit).
    #[error("The PublicMessage is not a Commit despite the sender begin of type NewMemberCommit.")]
    NotACommit,
    /// The PublicMessage is not an External Add Proposal despite the sender begin of type [NewMemberProposal](crate::prelude::Sender::NewMemberProposal).
    #[error("The PublicMessage is not an external Add proposal despite the sender begin of type NewMemberProposal.")]
    NotAnExternalAddProposal,
    /// The Commit doesn't have a path despite the sender being of type NewMemberCommit.
    #[error("The Commit doesn't have a path despite the sender being of type NewMemberCommit.")]
    NoPath,
    /// The PublicMessage contains an application message but was not encrypted.
    #[error("The PublicMessage contains an application message but was not encrypted.")]
    UnencryptedApplicationMessage,
    /// Sender is not part of the group.
    #[error("Sender is not part of the group.")]
    UnknownMember,
    /// Membership tag is missing.
    #[error("Membership tag is missing.")]
    MissingMembershipTag,
    /// Membership tag is invalid.
    #[error("Membership tag is invalid.")]
    InvalidMembershipTag,
    /// The confirmation tag is missing.
    #[error("The confirmation tag is missing.")]
    MissingConfirmationTag,
    /// Wrong wire format.
    #[error("Wrong wire format.")]
    WrongWireFormat,
    /// Verifying the signature failed.
    #[error("Verifying the signature failed.")]
    InvalidSignature,
    /// An application message was sent from an external sender.
    #[error("An application message was sent from an external sender.")]
    NonMemberApplicationMessage,
    /// Could not decrypt the message
    #[error(transparent)]
    UnableToDecrypt(#[from] MessageDecryptionError),
    /// The message is from an epoch too far in the past.
    #[error("The message is from an epoch too far in the past.")]
    NoPastEpochData,
    /// The provided external sender is not authorized to send external proposals
    #[error("The provided external sender is not authorized to send external proposals")]
    UnauthorizedExternalSender,
    /// The group doesn't contain external senders extension.
    #[error("The group doesn't contain external senders extension")]
    NoExternalSendersExtension,
    /// The KeyPackage could not be validated.
    #[error(transparent)]
    KeyPackageVerifyError(#[from] KeyPackageVerifyError),
    /// The UpdatePath could not be validated.
    #[error(transparent)]
    UpdatePathError(#[from] UpdatePathError),
    /// Invalid LeafNode signature.
    #[error("Invalid LeafNode signature.")]
    InvalidLeafNodeSignature,
    /// Invalid LeafNode source type
    #[error("Invalid LeafNode source type")]
    InvalidLeafNodeSourceType,
    /// Invalid sender type.
    #[error("Invalid sender type")]
    InvalidSenderType,
    /// The Commit includes update proposals from the committer.
    #[error("The Commit includes update proposals from the committer.")]
    CommitterIncludedOwnUpdate,
    /// The ciphersuite in the KeyPackage of the Add proposal does not match the group context.
    #[error(
        "The ciphersuite in the KeyPackage of the Add proposal does not match the group context."
    )]
    InvalidAddProposalCiphersuite,
    /// Cannot decrypt own messages because the necessary key has been deleted according to the deletion schedule.
    #[error("Cannot decrypt own messages.")]
    CannotDecryptOwnMessage,
    /// See [`ExternalCommitValidationError`] for more details.
    #[error(transparent)]
    ExternalCommitValidation(#[from] ExternalCommitValidationError),
}

/// Proposal validation error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposalValidationError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The sender could not be matched to a member of the group.
    #[error("The sender could not be matched to a member of the group.")]
    UnknownMember,
    /// Duplicate signature key in proposals and group.
    #[error("Duplicate signature key in proposals and group.")]
    DuplicateSignatureKey,
    /// Duplicate encryption key in proposals and group.
    #[error("Duplicate encryption key in proposals and group.")]
    DuplicateEncryptionKey,
    /// Duplicate init key in proposals.
    #[error("Duplicate init key in proposals.")]
    DuplicateInitKey,
    /// The HPKE init and encryption keys are the same.
    #[error("The HPKE init and encryption keys are the same.")]
    InitEncryptionKeyCollision,
    /// Duplicate remove proposals for the same member.
    #[error("Duplicate remove proposals for the same member.")]
    DuplicateMemberRemoval,
    /// The remove proposal referenced a non-existing member.
    #[error("The remove proposal referenced a non-existing member.")]
    UnknownMemberRemoval,
    /// Found an update from a non-member.
    #[error("Found an update from a non-member.")]
    UpdateFromNonMember,
    /// The Commit includes update proposals from the committer.
    #[error("The Commit includes update proposals from the committer.")]
    CommitterIncludedOwnUpdate,
    /// The capabilities of the add proposal are insufficient for this group.
    #[error("The capabilities of the add proposal are insufficient for this group.")]
    InsufficientCapabilities,
    /// The add proposal's ciphersuite or protocol version do not match the ones in the group context.
    #[error(
        "The add proposal's ciphersuite or protocol version do not match the ones in the group context."
    )]
    InvalidAddProposalCiphersuiteOrVersion,
    /// See [`PskError`] for more details.
    #[error(transparent)]
    Psk(#[from] PskError),
    /// The proposal type is not supported by all group members.
    #[error("The proposal type is not supported by all group members.")]
    UnsupportedProposalType,
    /// See [`LeafNodeValidationError`] for more details.
    #[error(transparent)]
    LeafNodeValidation(#[from] LeafNodeValidationError),
    /// Regular Commits may not contain ExternalInit proposals, but one was found
    #[error("Found ExternalInit proposal in regular commit")]
    ExternalInitProposalInRegularCommit,
}

/// External Commit validaton error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ExternalCommitValidationError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// No ExternalInit proposal found.
    #[error("No ExternalInit proposal found.")]
    NoExternalInitProposals,
    /// Multiple ExternalInit proposal found.
    #[error("Multiple ExternalInit proposal found.")]
    MultipleExternalInitProposals,
    /// Found inline Add or Update proposals.
    #[error("Found inline Add or Update proposals.")]
    InvalidInlineProposals,
    /// Found multiple inline Remove proposals.
    #[error("Found multiple inline Remove proposals.")]
    MultipleRemoveProposals,
    /// Remove proposal targets the wrong group member.
    #[error("Remove proposal targets the wrong group member.")]
    InvalidRemoveProposal,
    /// External Commit has to contain a path.
    #[error("External Commit has to contain a path.")]
    NoPath,
    /// External commit contains referenced proposal
    #[error("Found a referenced proposal in an External Commit.")]
    ReferencedProposal,
}

/// Create add proposal error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CreateAddProposalError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`LeafNodeValidationError`] for more details.
    #[error(transparent)]
    LeafNodeValidation(#[from] LeafNodeValidationError),
}

// === Crate errors ===

/// Proposal queue error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum ProposalQueueError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Not all proposals in the Commit were found locally.
    #[error("Not all proposals in the Commit were found locally.")]
    ProposalNotFound,
    /// Update proposal from external sender.
    #[error("Update proposal from external sender.")]
    UpdateFromExternalSender,
    /// SelfRemove proposal from a non-Member.
    #[error("SelfRemove proposal from a non-Member.")]
    SelfRemoveFromNonMember,
}

/// Errors that can arise when creating a [`ProposalQueue`] from committed
/// proposals.
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum FromCommittedProposalsError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Not all proposals in the Commit were found locally.
    #[error("Not all proposals in the Commit were found locally.")]
    ProposalNotFound,
    /// The sender of a Commit tried to remove themselves.
    #[error("The sender of a Commit tried to remove themselves.")]
    SelfRemoval,
}

/// Create group context ext proposal error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CreateGroupContextExtProposalError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`KeyPackageExtensionSupportError`] for more details.
    #[error(transparent)]
    KeyPackageExtensionSupport(#[from] KeyPackageExtensionSupportError),
    /// See [`ExtensionError`] for more details.
    #[error(transparent)]
    Extension(#[from] ExtensionError),
    /// See [`LeafNodeValidationError`] for more details.
    #[error(transparent)]
    LeafNodeValidation(#[from] LeafNodeValidationError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    MlsGroupStateError(#[from] MlsGroupStateError),
    /// See [`CreateCommitError`] for more details.
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError),
    /// See [`CommitBuilderStageError`] for more details.
    #[error(transparent)]
    CommitBuilderStageError(#[from] CommitBuilderStageError<StorageError>),
    /// Error writing updated group to storage.
    #[error("Error writing updated group data to storage.")]
    StorageError(StorageError),
}

/// Error merging a commit.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum MergeCommitError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Error writing updated group to storage.
    #[error("Error writing updated group data to storage.")]
    StorageError(StorageError),
}

#[cfg(feature = "extensions-draft-08")]
/// Error validating an AppDataUpdate proposal.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum AppDataUpdateValidationError {
    /// [`AppDataUpdateProposal`](crate::messages::proposals::AppDataUpdateProposal)s
    /// occur before
    /// [`GroupContextExtensionsProposal`](crate::messages::proposals::GroupContextExtensionProposal)s.
    #[error("AppDataUpdate proposals occur before GroupContextExtensions proposals.")]
    IncorrectOrder,
    /// Attempted to update the [`AppDataDictionary`](crate::extensions::AppDataDictionary)
    /// in the
    /// [`GroupContextExtensionsProposal`](crate::messages::proposals::GroupContextExtensionProposal) directly.
    #[error("Attempted to update the AppDataDictionary in the GroupContextExtensions proposal directly.")]
    CannotUpdateDictionaryDirectly,
    /// More than one [`AppDataUpdate]` proposal per
    /// [`ComponentId`](crate::extensions::ComponentId) had a Remove operation.
    #[error("More than one AppDataUpdate proposal per ComponentId had a Remove operation.")]
    MoreThanOneRemovePerComponentId,
    /// Proposals for a [`ComponentId`](crate::extensions::ComponentId) had both Remove and Update operations.
    #[error("Proposals for a ComponentId had both Remove and Update operations.")]
    CombinedRemoveAndUpdateOperations,
}

/// Error validation a GroupContextExtensions proposal.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum GroupContextExtensionsProposalValidationError {
    /// Commit has more than one GroupContextExtensions proposal.
    #[error("Commit has more than one GroupContextExtensions proposal.")]
    TooManyGCEProposals,

    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),

    /// The new extension types in required capabilties contails extensions that are not supported by all group members.
    #[error(
        "The new required capabilties contain extension types that are not supported by all group members."
    )]
    ExtensionNotSupportedByAllMembers,
    /// Proposal changes the immutable metadata extension, which is not allowed.
    #[error("Proposal changes the immutable metadata extension, which is not allowed.")]
    ChangedImmutableMetadata,

    /// The new extension types in required capabilties contails extensions that are not supported by all group members.
    #[error(
        "The new required capabilties contain extension types that are not supported by all group members."
    )]
    RequiredExtensionNotSupportedByAllMembers,

    /// An extension in the group context extensions is not listed in the required capabilties'
    /// extension types.
    #[error(
        "An extension in the group context extensions is not listed in the required capabilties' extension types."
    )]
    ExtensionNotInRequiredCapabilities,
}
