use thiserror::Error;

use crate::{error::LibraryError, group::errors::*};

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
    FailedToJoinGroup(#[from] WelcomeError),
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
    /// See [`UnverifiedMessageError`] for more details.
    #[error(transparent)]
    UnverifiedMessageError(#[from] UnverifiedMessageError),
    /// See [`MlsGroupStateError`] for more details.
    #[error(transparent)]
    MlsGroupStateError(#[from] MlsGroupStateError),
    /// See [`AddMembersError`] for more details.
    #[error(transparent)]
    AddMembersError(#[from] AddMembersError),
    /// See [`RemoveMembersError`] for more details.
    #[error(transparent)]
    RemoveMembersError(#[from] RemoveMembersError),
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
    NewGroupError(#[from] NewGroupError),
    /// See [`SelfUpdateError`] for more details.
    #[error(transparent)]
    SelfUpdateError(#[from] SelfUpdateError),
    /// See [`ProposeSelfUpdateError`] for more details.
    #[error(transparent)]
    ProposeSelfUpdateError(#[from] ProposeSelfUpdateError),
    /// See [`ParseMessageError`] for more details.
    #[error(transparent)]
    ParseMessageError(#[from] ParseMessageError),
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("")]
    Unknown,
}
