use openmls_traits::key_store::OpenMlsKeyStore;
use thiserror::Error;

use crate::{error::LibraryError, group::errors::*};
use openmls_rust_crypto::{MemoryKeyStore, MemoryKeyStoreError};

/// Setup error
#[derive(Error, Debug, PartialEq, Clone)]
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
#[derive(Error, Debug, PartialEq, Clone)]
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
    FailedToJoinGroup(#[from] WelcomeError<MemoryKeyStoreError>),
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
    /// See [`ProcessMessageError`] for more details.
    #[error(transparent)]
    ProcessMessageError(#[from] ProcessMessageError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    MlsGroupStateError(#[from] MlsGroupStateError),
    /// See [`AddMembersError`] for more details.
    #[error(transparent)]
    AddMembersError(#[from] AddMembersError<MemoryKeyStoreError>),
    /// See [`RemoveMembersError`] for more details.
    #[error(transparent)]
    RemoveMembersError(#[from] RemoveMembersError<MemoryKeyStoreError>),
    /// See [`ProposeAddMemberError`] for more details.
    #[error(transparent)]
    ProposeAddMemberError(#[from] ProposeAddMemberError),
    /// See [`ProposeRemoveMemberError`] for more details.
    #[error(transparent)]
    ProposeRemoveMemberError(#[from] ProposeRemoveMemberError),
    /// See [`ExportSecretError`] for more details.
    #[error(transparent)]
    ExportSecretError(#[from] ExportSecretError),
    /// See [`NewGroupError`] for more details.
    #[error(transparent)]
    NewGroupError(#[from] NewGroupError<MemoryKeyStoreError>),
    /// See [`SelfUpdateError`] for more details.
    #[error(transparent)]
    SelfUpdateError(#[from] SelfUpdateError<MemoryKeyStoreError>),
    /// See [`ProposeSelfUpdateError`] for more details.
    #[error(transparent)]
    ProposeSelfUpdateError(#[from] ProposeSelfUpdateError<MemoryKeyStoreError>),
    /// See [`MergePendingCommitError`] for more details.
    #[error(transparent)]
    MergePendingCommitError(#[from] MergePendingCommitError<MemoryKeyStoreError>),
    /// See [`MergeCommitError`] for more details.
    #[error(transparent)]
    MergeCommitError(#[from] MergeCommitError<MemoryKeyStoreError>),
    /// See [`MemoryKeyStoreError`] for more details.
    #[error(transparent)]
    KeyStoreError(#[from] MemoryKeyStoreError),
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("")]
    Unknown,
}
