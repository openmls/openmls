//! # MlsGroup errors
//!
//! This module defines the public errors that can be returned from all calls
//! to methods of [`MlsGroup`](super::MlsGroup).

// These errors are exposed through `crate::group::errors`.

use thiserror::Error;

use crate::{
    error::LibraryError,
    extensions::errors::InvalidExtensionError,
    group::{
        errors::{
            CreateAddProposalError, CreateCommitError, MergeCommitError, StageCommitError,
            ValidationError,
        },
        CommitBuilderStageError, CreateGroupContextExtProposalError,
    },
    schedule::errors::PskError,
    treesync::{
        errors::{LeafNodeValidationError, PublicTreeError},
        node::leaf_node::LeafNodeUpdateError,
    },
};

#[cfg(all(feature = "extensions-draft-08", feature = "fs-exporter"))]
pub use crate::schedule::application_export_tree::ApplicationExportTreeError;

/// New group error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum NewGroupError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// No matching KeyPackage was found in the key store.
    #[error("No matching KeyPackage was found in the key store.")]
    NoMatchingKeyPackage,
    /// Error accessing the storage.
    #[error("Error accessing the storage.")]
    StorageError(StorageError),
    /// Unsupported proposal type in required capabilities.
    #[error("Unsupported proposal type in required capabilities.")]
    UnsupportedProposalType,
    /// Unsupported extension type in required capabilities.
    #[error("Unsupported extension type in required capabilities.")]
    UnsupportedExtensionType,
    /// Invalid extensions set in configuration
    #[error("Invalid extensions set in configuration")]
    InvalidExtensions(#[from] InvalidExtensionError),
}

/// EmptyInput error
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum EmptyInputError {
    /// An empty list of KeyPackages was provided.
    #[error("An empty list of KeyPackages was provided.")]
    AddMembers,
    /// An empty list of KeyPackage references was provided.
    #[error("An empty list of KeyPackage references was provided.")]
    RemoveMembers,
}

/// Group state error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum MlsGroupStateError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Tried to use a group after being evicted from it.
    #[error("Tried to use a group after being evicted from it.")]
    UseAfterEviction,
    /// Can't create message because a pending proposal exists.
    #[error("Can't create message because a pending proposal exists.")]
    PendingProposal,
    /// Can't execute operation because a pending commit exists.
    #[error("Can't execute operation because a pending commit exists.")]
    PendingCommit,
    /// Can't execute operation because there is no pending commit.
    #[error("Can't execute operation because there is no pending commit")]
    NoPendingCommit,
    /// Requested pending proposal hasn't been found in local pending proposals
    #[error("Requested pending proposal hasn't been found in local pending proposals.")]
    PendingProposalNotFound,
}

/// Error merging pending commit
#[derive(Error, Debug, PartialEq, Clone)]
pub enum MergePendingCommitError<StorageError> {
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    MlsGroupStateError(#[from] MlsGroupStateError),
    /// See [`MergeCommitError`] for more details.
    #[error(transparent)]
    MergeCommitError(#[from] MergeCommitError<StorageError>),
}

/// Process message error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum PublicProcessMessageError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The message's wire format is incompatible with the group's wire format policy.
    #[error("The message's wire format is incompatible with the group's wire format policy.")]
    IncompatibleWireFormat,
    /// See [`ValidationError`] for more details.
    #[error(transparent)]
    ValidationError(#[from] ValidationError),
    /// See [`StageCommitError`] for more details.
    #[error(transparent)]
    InvalidCommit(#[from] StageCommitError),
    /// External application messages are not permitted.
    #[error("External application messages are not permitted.")]
    UnauthorizedExternalApplicationMessage,
    /// External commit messages are not permitted.
    #[error("Commit messages from external senders are not permitted.")]
    UnauthorizedExternalCommitMessage,
    /// The proposal is invalid for the Sender of type [External](crate::prelude::Sender::External)
    #[error("The proposal is invalid for the Sender of type External")]
    UnsupportedProposalType,
}

/// Process message error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProcessMessageError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Error writing to storage.
    #[error("Error writing to storage: {0}")]
    StorageError(StorageError),
    /// The message's wire format is incompatible with the group's wire format policy.
    #[error("The message's wire format is incompatible with the group's wire format policy.")]
    IncompatibleWireFormat,
    /// See [`ValidationError`] for more details.
    #[error(transparent)]
    ValidationError(#[from] ValidationError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// See [`StageCommitError`] for more details.
    #[error(transparent)]
    InvalidCommit(#[from] StageCommitError),
    /// External application messages are not permitted.
    #[error("External application messages are not permitted.")]
    UnauthorizedExternalApplicationMessage,
    /// External commit messages are not permitted.
    #[error("Commit messages from external senders are not permitted.")]
    UnauthorizedExternalCommitMessage,
    /// The proposal is invalid for the Sender of type [External](crate::prelude::Sender::External)
    #[error("The proposal is invalid for the Sender of type External")]
    UnsupportedProposalType,
}

/// Create message error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CreateMessageError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Add members error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum AddMembersError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`EmptyInputError`] for more details.
    #[error(transparent)]
    EmptyInput(#[from] EmptyInputError),
    /// See [`CreateCommitError`] for more details.
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError),
    /// See [`CommitBuilderStageError`] for more details.
    #[error(transparent)]
    CommitBuilderStageError(#[from] CommitBuilderStageError<StorageError>),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// Error writing to storage.
    #[error("Error writing to storage")]
    StorageError(StorageError),
}

/// Add members error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum SwapMembersError<StorageError> {
    /// Unable to map the key packages to the given leaf indices.
    #[error("Number of added and removed members is not the same")]
    InvalidInput,

    /// See [`EmptyInputError`] for more details.
    #[error(transparent)]
    EmptyInput(#[from] EmptyInputError),

    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),

    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),

    /// The member that should be removed can not be found.
    #[error("The member that should be removed can not be found.")]
    UnknownMember,

    /// Error writing to storage
    #[error("Error writing to storage: {0}")]
    StorageError(StorageError),

    /// See [`CommitBuilderStageError`] for more details.
    #[error(transparent)]
    CommitBuilderStageError(#[from] CommitBuilderStageError<StorageError>),

    /// See [`CreateCommitError`] for more details.
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError),
}

/// Propose add members error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposeAddMemberError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The new member does not support all required extensions.
    #[error("The new member does not support all required extensions.")]
    UnsupportedExtensions,
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// See [`LeafNodeValidationError`] for more details.
    #[error(transparent)]
    LeafNodeValidation(#[from] LeafNodeValidationError),
    /// Error writing to storage
    #[error("Error writing to storage: {0}")]
    StorageError(StorageError),
}

/// Propose remove members error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposeRemoveMemberError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// The member that should be removed can not be found.
    #[error("The member that should be removed can not be found.")]
    UnknownMember,
    /// Error writing to storage
    #[error("Error writing to storage: {0}")]
    StorageError(StorageError),
}

/// Remove members error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum RemoveMembersError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`EmptyInputError`] for more details.
    #[error(transparent)]
    EmptyInput(#[from] EmptyInputError),
    /// See [`CreateCommitError`] for more details.
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError),
    /// See [`CommitBuilderStageError`] for more details.
    #[error(transparent)]
    CommitBuilderStageError(#[from] CommitBuilderStageError<StorageError>),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// The member that should be removed can not be found.
    #[error("The member that should be removed can not be found.")]
    UnknownMember,
    /// Error writing to storage
    #[error("Error writing to storage: {0}")]
    StorageError(StorageError),
}

/// Leave group error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum LeaveGroupError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// An error ocurred while writing to storage
    #[error("An error ocurred while writing to storage")]
    StorageError(StorageError),
    /// SelfRemove not allowed with pure ciphertext outgoing wire format policy.
    #[error("SelfRemove not allowed with pure ciphertext outgoing wire format policy.")]
    CannotSelfRemoveWithPureCiphertext,
}

/// Self update error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum SelfUpdateError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`CreateCommitError`] for more details.
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError),
    /// See [`CommitBuilderStageError`] for more details.
    #[error(transparent)]
    CommitBuilderStageError(#[from] CommitBuilderStageError<StorageError>),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// Error accessing the storage.
    #[error("Error accessing the storage.")]
    StorageError(StorageError),
}

/// Propose self update error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposeSelfUpdateError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),

    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// Error accessing storage.
    #[error("Error accessing storage.")]
    StorageError(StorageError),
    /// See [`PublicTreeError`] for more details.
    #[error(transparent)]
    PublicTreeError(#[from] PublicTreeError),
    /// See [`LeafNodeUpdateError`] for more details.
    #[error(transparent)]
    LeafNodeUpdateError(#[from] LeafNodeUpdateError<StorageError>),
}

/// Commit to pending proposals error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CommitToPendingProposalsError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`CreateCommitError`] for more details.
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError),
    /// See [`CommitBuilderStageError`] for more details.
    #[error(transparent)]
    CommitBuilderStageError(#[from] CommitBuilderStageError<StorageError>),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// Error writing to storage
    #[error("Error writing to storage: {0}")]
    StorageError(StorageError),
}

/// Errors that can happen when exporting a group info object.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ExportGroupInfoError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Export secret error
#[cfg(all(feature = "extensions-draft-08", feature = "fs-exporter"))]
#[derive(Error, Debug, PartialEq, Clone)]
pub enum SafeExportSecretError<StorageError> {
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupState(#[from] MlsGroupStateError),
    /// See [`ApplicationExportTreeError`] for more details.
    #[error(transparent)]
    ApplicationExportTree(#[from] ApplicationExportTreeError),
    /// Group doesn't support application exports.
    #[error("Group doesn't support application exports.")]
    Unsupported,
    /// Storage error
    #[error("Error accessing storage: {0}")]
    Storage(StorageError),
}

/// Export secret error
#[cfg(all(feature = "extensions-draft-08", feature = "fs-exporter"))]
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProcessedMessageSafeExportSecretError {
    /// See [`StagedSafeExportSecretError`] for more details.
    #[error(transparent)]
    SafeExportSecretError(#[from] StagedSafeExportSecretError),
    /// Processed message is not a commit.
    #[error("Processed message is not a commit.")]
    NotACommit,
}

/// Export secret error
#[cfg(all(feature = "extensions-draft-08", feature = "fs-exporter"))]
#[derive(Error, Debug, PartialEq, Clone)]
pub enum PendingSafeExportSecretError<StorageError> {
    /// See [`StagedSafeExportSecretError`] for more details.
    #[error(transparent)]
    SafeExportSecretError(#[from] StagedSafeExportSecretError),
    /// No pending commit.
    #[error("No pending commit.")]
    NoPendingCommit,
    /// Storage error
    #[error("Error accessing storage: {0}")]
    Storage(StorageError),
    /// Only group members can export secrets.
    #[error("Only group members can export secrets.")]
    NotGroupMember,
}

/// Export secret from a pending commit
#[cfg(all(feature = "extensions-draft-08", feature = "fs-exporter"))]
#[derive(Error, Debug, PartialEq, Clone)]
pub enum StagedSafeExportSecretError {
    /// Only group members can export secrets.
    #[error("Only group members can export secrets.")]
    NotGroupMember,
    /// See [`ApplicationExportTreeError`] for more details.
    #[error(transparent)]
    ApplicationExportTree(#[from] ApplicationExportTreeError),
    /// Group doesn't support application exports.
    #[error("Group doesn't support application exports.")]
    Unsupported,
}

/// Export secret error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ExportSecretError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The requested key length is too long.
    #[error("The requested key length is too long.")]
    KeyLengthTooLong,
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Propose PSK error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposePskError {
    /// See [`PskError`] for more details.
    #[error(transparent)]
    Psk(#[from] PskError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
}

/// Proposal error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposalError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`ProposeAddMemberError`] for more details.
    #[error(transparent)]
    ProposeAddMemberError(#[from] ProposeAddMemberError<StorageError>),
    /// See [`CreateAddProposalError`] for more details.
    #[error(transparent)]
    CreateAddProposalError(#[from] CreateAddProposalError),
    /// See [`ProposeSelfUpdateError`] for more details.
    #[error(transparent)]
    ProposeSelfUpdateError(#[from] ProposeSelfUpdateError<StorageError>),
    /// See [`ProposeRemoveMemberError`] for more details.
    #[error(transparent)]
    ProposeRemoveMemberError(#[from] ProposeRemoveMemberError<StorageError>),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// See [`ValidationError`] for more details.
    #[error(transparent)]
    ValidationError(#[from] ValidationError),
    /// See [`CreateGroupContextExtProposalError`] for more details.
    #[error(transparent)]
    CreateGroupContextExtProposalError(#[from] CreateGroupContextExtProposalError<StorageError>),
    /// Error writing proposal to storage.
    #[error("error writing proposal to storage")]
    StorageError(StorageError),
}

/// Remove proposal error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum RemoveProposalError<StorageError> {
    /// Couldn't find the proposal for the given `ProposalRef`.
    #[error("Couldn't find the proposal for the given `ProposalRef`")]
    ProposalNotFound,
    /// Error erasing proposal from storage.
    #[error("error writing proposal to storage")]
    Storage(StorageError),
}
