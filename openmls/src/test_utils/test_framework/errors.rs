use thiserror::Error;

use crate::{error::LibraryError, group::errors::*};
use openmls_rust_crypto::{MemoryStorage, MemoryStorageError};

/// Setup error
#[derive(Error, Debug, PartialEq)]
pub enum SetupError {
    #[error("")]
    UnknownGroupId,
    #[error("")]
    UnknownClientId,
    #[error("")]
    NotEnoughClients,
    #[error("")]
    ClientAlreadyInGroup,
    #[error("")]
    ClientNotInGroup,
    #[error("")]
    NoFreshKeyPackage,
    /// See [`ClientError`] for more details.
    #[error(transparent)]
    ClientError(#[from] ClientError),
    /// See [`ExportSecretError`] for more details.
    #[error(transparent)]
    ExportSecretError(#[from] ExportSecretError<MemoryStorageError>),
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("")]
    Unknown,
}

#[derive(Debug)]
pub enum SetupGroupError {
    NotEnoughMembers,
}

/// Errors that can occur when processing messages with the client.
#[derive(Error, Debug, PartialEq)]
pub enum ClientError {
    #[error("")]
    NoMatchingKeyPackage,
    #[error("")]
    NoMatchingCredential,
    #[error("")]
    CiphersuiteNotSupported,
    #[error("")]
    NoMatchingGroup,
    #[error("")]
    NoCiphersuite,
    /// See [`WelcomeError`] for more details.
    #[error(transparent)]
    FailedToJoinGroup(#[from] WelcomeError<MemoryStorageError>),
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
    /// See [`ProcessMessageError`] for more details.
    #[error(transparent)]
    ProcessMessageError(#[from] ProcessMessageError<MemoryStorageError>),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    MlsGroupStateError(#[from] MlsGroupStateError<MemoryStorageError>),
    /// See [`AddMembersError`] for more details.
    #[error(transparent)]
    AddMembersError(#[from] AddMembersError<MemoryStorageError>),
    /// See [`RemoveMembersError`] for more details.
    #[error(transparent)]
    RemoveMembersError(#[from] RemoveMembersError<MemoryStorageError>),
    /// See [`ProposeAddMemberError`] for more details.
    #[error(transparent)]
    ProposeAddMemberError(#[from] ProposeAddMemberError<MemoryStorageError>),
    /// See [`ProposeRemoveMemberError`] for more details.
    #[error(transparent)]
    ProposeRemoveMemberError(#[from] ProposeRemoveMemberError<MemoryStorageError>),
    /// See [`ExportSecretError`] for more details.
    #[error(transparent)]
    ExportSecretError(#[from] ExportSecretError<MemoryStorageError>),
    /// See [`NewGroupError`] for more details.
    #[error(transparent)]
    NewGroupError(#[from] NewGroupError<MemoryStorageError>),
    /// See [`SelfUpdateError`] for more details.
    #[error(transparent)]
    SelfUpdateError(#[from] SelfUpdateError<MemoryStorageError>),
    /// See [`ProposeSelfUpdateError`] for more details.
    #[error(transparent)]
    ProposeSelfUpdateError(#[from] ProposeSelfUpdateError<MemoryStorageError>),
    /// See [`MergePendingCommitError`] for more details.
    #[error(transparent)]
    MergePendingCommitError(#[from] MergePendingCommitError<MemoryStorageError>),
    /// See [`MergeCommitError`] for more details.
    #[error(transparent)]
    MergeCommitError(#[from] MergeCommitError<MemoryStorageError>),
    /// See [`MemoryStorageError`] for more details.
    #[error(transparent)]
    KeyStoreError(#[from] MemoryStorageError),
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("")]
    Unknown,
}
