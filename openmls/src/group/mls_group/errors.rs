//! # MlsGroup errors
//!
//! This module defines the public errors that can be returned from all calls
//! to methods of [`MlsGroup`](super::MlsGroup).

// These errors are exposed through `crate::group::errors`.

use thiserror::Error;

use crate::{
    error::LibraryError,
    group::errors::{CreateCommitError, MergeCommitError, StageCommitError, ValidationError},
    treesync::errors::LeafNodeValidationError,
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
    /// No matching CredentialBundle was found in the key store.
    #[error("No matching CredentialBundle was found in the key store.")]
    NoMatchingCredentialBundle,
    /// Error accessing the key store.
    #[error("Error accessing the key store.")]
    KeyStoreError(KeyStoreError),
    /// Unsupported proposal type in required capabilities.
    #[error("Unsupported proposal type in required capabilities.")]
    UnsupportedProposalType,
    /// Unsupported extension type in required capabilities.
    #[error("Unsupported extension type in required capabilities.")]
    UnsupportedExtensionType,
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
    /// A signature key was not provided for an external message.
    #[error("A signature key was not provided for an external message.")]
    MissingSignatureKey,
    /// See [`StageCommitError`] for more details.
    #[error(transparent)]
    InvalidCommit(#[from] StageCommitError),
}

/// Create message error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CreateMessageError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The own CredentialBundle could not be found in the key store.
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
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
    /// The own CredentialBundle could not be found in the key store.
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
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
    /// The own CredentialBundle could not be found in the key store.
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
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
    /// The own CredentialBundle could not be found in the key store.
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
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
    /// The own CredentialBundle could not be found in the key store.
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
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
    /// The own CredentialBundle could not be found in the key store.
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
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
    /// The own CredentialBundle could not be found in the key store.
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
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
    /// The own CredentialBundle could not be found in the key store.
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    /// Error accessing the key store.
    #[error("Error accessing the key store.")]
    KeyStoreError(KeyStoreError),
}

/// Commit to pending proposals error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CommitToPendingProposalsError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The own CredentialBundle could not be found in the key store.
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
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
    /// The own CredentialBundle could not be found in the key store.
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
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
