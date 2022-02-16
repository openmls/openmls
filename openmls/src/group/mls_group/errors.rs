//! # MLS MlsGroup errors
//!
//! `WelcomeError`, `StageCommitError`, `DecryptionError`, and
//! `CreateCommitError`.

use crate::{
    error::LibraryError,
    group::errors::{CreateCommitError, StageCommitError, ValidationError},
};
use thiserror::Error;

/// New group error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum NewGroupError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("No matching KeyPackageBundle was found in the key store.")]
    NoMatchingKeyPackageBundle,
    #[error("Failed to delete the KeyPackageBundle from the key store.")]
    KeyStoreDeletionError,
    #[error("Unsupported proposal type in required capabilities.")]
    UnsupportedProposalType,
    #[error("Unsupported extension type in required capabilities.")]
    UnsupportedExtensionType,
}

/// EmptyInput error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum EmptyInputError {
    #[error("An empty list of KeyPackages was provided.")]
    AddMembers,
    #[error("An empty list of KeyPackage references was provided.")]
    RemoveMembers,
}

/// Group state error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum MlsGroupStateError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("Tried to use a group after being evicted from it.")]
    UseAfterEviction,
    #[error("Can't create message because a pending proposal exists.")]
    PendingProposal,
    #[error("Can't execute operation because a pending commit exists.")]
    PendingCommit,
}

/// Parse message error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ParseMessageError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The message's wire format is incompatible with the group's wire format policy.")]
    IncompatibleWireFormat,
    #[error(transparent)]
    ValidationError(#[from] ValidationError),
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Unverified message error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum UnverifiedMessageError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The message is from an epoch too far in the past.")]
    NoPastEpochData,
    #[error("The message's signature is invalid.")]
    InvalidSignature,
    #[error("The message's membership tag is invalid.")]
    InvalidMembershipTag,
    #[error("A signature key was not provided for a preconfigured message.")]
    MissingSignatureKey,
    #[error(transparent)]
    InvalidCommit(#[from] StageCommitError),
}

/// Create message error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CreateMessageError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Add members error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum AddMembersError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
    #[error(transparent)]
    EmptyInput(#[from] EmptyInputError),
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError),
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Propose add members error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposeAddMemberError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
    #[error("The new member does not support all required extensions.")]
    UnsupportedExtensions,
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Propose remove members error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposeRemoveMemberError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Remove members error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum RemoveMembersError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
    #[error(transparent)]
    EmptyInput(#[from] EmptyInputError),
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError),
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Leave group error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum LeaveGroupError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Self update error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum SelfUpdateError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError),
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Propose self update error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposeSelfUpdateError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Commit to pending proposals error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CommitToPendingProposalsError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError),
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Export public group state error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ExportPublicGroupStateError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The own CredentialBundle could not be found in the key store.")]
    NoMatchingCredentialBundle,
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Export secret error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ExportSecretError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The requested key length is too long.")]
    KeyLengthTooLong,
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}
