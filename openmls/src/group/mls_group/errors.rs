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
        CreateGroupContextExtProposalError,
    },
    schedule::errors::PskError,
    treesync::errors::{LeafNodeValidationError, PublicTreeError},
};

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
pub enum MlsGroupStateError<StorageError> {
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
    /// An error ocurred while writing to storage
    #[error("An error ocurred while writing to storage")]
    StorageError(StorageError),
}

/// Error merging pending commit
#[derive(Error, Debug, PartialEq, Clone)]
pub enum MergePendingCommitError<StorageError> {
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    MlsGroupStateError(#[from] MlsGroupStateError<StorageError>),
    /// See [`MergeCommitError`] for more details.
    #[error(transparent)]
    MergeCommitError(#[from] MergeCommitError<StorageError>),
}

/// Process message error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProcessMessageError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The message's wire format is incompatible with the group's wire format policy.
    #[error("The message's wire format is incompatible with the group's wire format policy.")]
    IncompatibleWireFormat,
    /// See [`ValidationError`] for more details.
    #[error(transparent)]
    ValidationError(#[from] ValidationError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError<StorageError>),
    /// The message's signature is invalid.
    #[error("The message's signature is invalid.")]
    InvalidSignature,
    /// See [`StageCommitError`] for more details.
    #[error(transparent)]
    InvalidCommit(#[from] StageCommitError),
    /// External application messages are not permitted.
    #[error("External application messages are not permitted.")]
    UnauthorizedExternalApplicationMessage,
    /// The proposal is invalid for the Sender of type [External](crate::prelude::Sender::External)
    #[error("The proposal is invalid for the Sender of type External")]
    UnsupportedProposalType,
}

/// Create message error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CreateMessageError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError<StorageError>),
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
    CreateCommitError(#[from] CreateCommitError<StorageError>),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError<StorageError>),
    /// Error writing to storage.
    #[error("Error writing to storage")]
    StorageError(StorageError),
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
    GroupStateError(#[from] MlsGroupStateError<StorageError>),
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
    GroupStateError(#[from] MlsGroupStateError<StorageError>),
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
    CreateCommitError(#[from] CreateCommitError<StorageError>),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError<StorageError>),
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
    GroupStateError(#[from] MlsGroupStateError<StorageError>),
}

/// Self update error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum SelfUpdateError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`CreateCommitError`] for more details.
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError<StorageError>),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError<StorageError>),
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
    GroupStateError(#[from] MlsGroupStateError<StorageError>),
    /// Error accessing storage.
    #[error("Error accessing storage.")]
    StorageError(StorageError),
    /// See [`PublicTreeError`] for more details.
    #[error(transparent)]
    PublicTreeError(#[from] PublicTreeError),
}

/// Commit to pending proposals error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CommitToPendingProposalsError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`CreateCommitError`] for more details.
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError<StorageError>),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError<StorageError>),
    /// Error writing to storage
    #[error("Error writing to storage: {0}")]
    StorageError(StorageError),
}

/// Errors that can happen when exporting a group info object.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ExportGroupInfoError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError<StorageError>),
}

/// Export secret error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ExportSecretError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The requested key length is too long.
    #[error("The requested key length is too long.")]
    KeyLengthTooLong,
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError<StorageError>),
}

/// Propose PSK error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposePskError<StorageError> {
    /// See [`PskError`] for more details.
    #[error(transparent)]
    Psk(#[from] PskError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError<StorageError>),
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
}

/// Export secret error
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
    GroupStateError(#[from] MlsGroupStateError<StorageError>),
    /// See [`ValidationError`] for more details.
    #[error(transparent)]
    ValidationError(#[from] ValidationError),
    /// See [`CreateGroupContextExtProposalError`] for more details.
    #[error(transparent)]
    CreateGroupContextExtProposalError(#[from] CreateGroupContextExtProposalError),
    /// Error writing proposal to storage.
    #[error("error writing proposal to storage")]
    StorageError(StorageError),
}
