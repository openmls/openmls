//! # MlsGroup errors
//!
//! This module defines the public errors that can be returned from all calls
//! to methods of [`MlsGroup`](super::MlsGroup).

// These errors are exposed through `crate::group::errors`.

use crate::{
    error::LibraryError,
    group::errors::{CreateCommitError, StageCommitError, ValidationError},
};
use thiserror::Error;

/// New group error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum NewGroupError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// No matching KeyPackageBundle was found in the key store.
    #[error("No matching KeyPackageBundle was found in the key store.")]
    NoMatchingKeyPackageBundle,
    /// Failed to delete the KeyPackageBundle from the key store.
    #[error("Failed to delete the KeyPackageBundle from the key store.")]
    KeyStoreDeletionError,
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
}

/// Parse message error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ParseMessageError {
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
}

/// Unverified message error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum UnverifiedMessageError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The message is from an epoch too far in the past.
    #[error("The message is from an epoch too far in the past.")]
    NoPastEpochData,
    /// The message's signature is invalid.
    #[error("The message's signature is invalid.")]
    InvalidSignature,
    /// The message's membership tag is invalid.
    #[error("The message's membership tag is invalid.")]
    InvalidMembershipTag,
    /// A signature key was not provided for a preconfigured message.
    #[error("A signature key was not provided for a preconfigured message.")]
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
pub enum AddMembersError {
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
    CreateCommitError(#[from] CreateCommitError),
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
}

/// Remove members error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum RemoveMembersError {
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
    CreateCommitError(#[from] CreateCommitError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
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
pub enum SelfUpdateError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The own CredentialBundle could not be found in the key store.
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
    /// See [`CreateCommitError`] for more details.
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Propose self update error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposeSelfUpdateError {
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

/// Commit to pending proposals error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CommitToPendingProposalsError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The own CredentialBundle could not be found in the key store.
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
    /// See [`CreateCommitError`] for more details.
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Export public group state error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ExportPublicGroupStateError {
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
