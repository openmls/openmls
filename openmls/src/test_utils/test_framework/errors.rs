use thiserror::Error;

use crate::{error::LibraryError, group::*, key_packages::*};

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
    #[error(transparent)]
    ClientError(#[from] ClientError),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
    #[error(transparent)]
    MlsGroupError(#[from] MlsGroupError),
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
    #[error(transparent)]
    FailedToJoinGroup(#[from] WelcomeError),
    #[error(transparent)]
    MlsGroupError(#[from] MlsGroupError),
    #[error(transparent)]
    GroupError(#[from] CoreGroupError),
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
    #[error(transparent)]
    UnverifiedMessageError(#[from] UnverifiedMessageError),
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("")]
    Unknown,
}
