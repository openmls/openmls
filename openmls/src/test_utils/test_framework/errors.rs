use thiserror::Error;

use crate::{error::LibraryError, group::errors::*};
use openmls_rust_crypto::MemoryStorage;

/// Setup error
#[derive(Error, Debug, PartialEq)]
pub enum SetupError<StorageError> {
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
    ClientError(#[from] ClientError<StorageError>),
    /// See [`ExportSecretError`] for more details.
    #[error(transparent)]
    ExportSecretError(#[from] ExportSecretError),
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
pub enum ClientError<StorageError> {
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
    FailedToJoinGroup(#[from] WelcomeError<StorageError>),
    /// See [`tls_codec::Error`] for more details.
    #[error(transparent)]
    TlsCodecError(tls_codec::Error),
    /// See [`ProcessMessageError`] for more details.
    #[error("See ProcessMessageError for more details.")]
    ProcessMessageError(ProcessMessageError),
    /// See [`AddMembersError`] for more details.
    #[error(transparent)]
    AddMembersError(#[from] AddMembersError<StorageError>),
    /// See [`RemoveMembersError`] for more details.
    #[error(transparent)]
    RemoveMembersError(#[from] RemoveMembersError<StorageError>),
    /// See [`ProposeAddMemberError`] for more details.
    #[error(transparent)]
    ProposeAddMemberError(#[from] ProposeAddMemberError<StorageError>),
    /// See [`ProposeRemoveMemberError`] for more details.
    #[error(transparent)]
    ProposeRemoveMemberError(#[from] ProposeRemoveMemberError<StorageError>),
    /// See [`ExportSecretError`] for more details.
    #[error("Error exporting secret")]
    ExportSecretError(ExportSecretError),
    /// See [`NewGroupError`] for more details.
    #[error(transparent)]
    NewGroupError(#[from] NewGroupError<StorageError>),
    /// See [`SelfUpdateError`] for more details.
    #[error(transparent)]
    SelfUpdateError(#[from] SelfUpdateError<StorageError>),
    /// See [`ProposeSelfUpdateError`] for more details.
    #[error(transparent)]
    ProposeSelfUpdateError(#[from] ProposeSelfUpdateError<StorageError>),
    /// See [`MergePendingCommitError`] for more details.
    #[error(transparent)]
    MergePendingCommitError(#[from] MergePendingCommitError<StorageError>),
    /// See [`MergeCommitError`] for more details.
    #[error(transparent)]
    MergeCommitError(#[from] MergeCommitError<StorageError>),
    /// See `StorageError` for more details.
    #[error(transparent)]
    KeyStoreError(#[from] StorageError),
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(LibraryError),
    #[error("")]
    Unknown,
}
