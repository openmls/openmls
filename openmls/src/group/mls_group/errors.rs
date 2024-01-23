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
pub enum NewGroupError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// No matching KeyPackage was found in the key store.
    #[error("No matching KeyPackage was found in the key store.")]
    NoMatchingKeyPackage,
    /// Error accessing the key store.
    #[error("Error accessing the key store.")]
    KeyStoreError(KeyStoreError),
    /// Unsupported proposal type in required capabilities.
    #[error("Unsupported proposal type in required capabilities.")]
    UnsupportedProposalType,
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
pub enum MergePendingCommitError<KeyStoreError> {
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    MlsGroupStateError(#[from] MlsGroupStateError),
    /// See [`MergeCommitError`] for more details.
    #[error(transparent)]
    MergeCommitError(#[from] MergeCommitError<KeyStoreError>),
}

/// Process message error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProcessMessageError {
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
    GroupStateError(#[from] MlsGroupStateError),
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
pub enum AddMembersError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`EmptyInputError`] for more details.
    #[error(transparent)]
    EmptyInput(#[from] EmptyInputError),
    /// See [`CreateCommitError`] for more details.
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError<KeyStoreError>),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Propose add members error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposeAddMemberError {
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
}

/// Propose remove members error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposeRemoveMemberError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// The member that should be removed can not be found.
    #[error("The member that should be removed can not be found.")]
    UnknownMember,
}

/// Remove members error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum RemoveMembersError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`EmptyInputError`] for more details.
    #[error(transparent)]
    EmptyInput(#[from] EmptyInputError),
    /// See [`CreateCommitError`] for more details.
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError<KeyStoreError>),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// The member that should be removed can not be found.
    #[error("The member that should be removed can not be found.")]
    UnknownMember,
}

/// Leave group error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum LeaveGroupError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Self update error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum SelfUpdateError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`CreateCommitError`] for more details.
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError<KeyStoreError>),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// Error accessing the key store.
    #[error("Error accessing the key store.")]
    KeyStoreError,
}

/// Propose self update error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposeSelfUpdateError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),

    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// Error accessing the key store.
    #[error("Error accessing the key store.")]
    KeyStoreError(KeyStoreError),
    /// See [`PublicTreeError`] for more details.
    #[error(transparent)]
    PublicTreeError(#[from] PublicTreeError),
}

/// Commit to pending proposals error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CommitToPendingProposalsError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`CreateCommitError`] for more details.
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError<KeyStoreError>),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
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

/// Export secret error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposalError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`ProposeAddMemberError`] for more details.
    #[error(transparent)]
    ProposeAddMemberError(#[from] ProposeAddMemberError),
    /// See [`CreateAddProposalError`] for more details.
    #[error(transparent)]
    CreateAddProposalError(#[from] CreateAddProposalError),
    /// See [`ProposeSelfUpdateError`] for more details.
    #[error(transparent)]
    ProposeSelfUpdateError(#[from] ProposeSelfUpdateError<KeyStoreError>),
    /// See [`ProposeRemoveMemberError`] for more details.
    #[error(transparent)]
    ProposeRemoveMemberError(#[from] ProposeRemoveMemberError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// See [`ValidationError`] for more details.
    #[error(transparent)]
    ValidationError(#[from] ValidationError),
    /// See [`CreateGroupContextExtProposalError`] for more details.
    #[error(transparent)]
    CreateGroupContextExtProposalError(#[from] CreateGroupContextExtProposalError),
}
