use crate::prelude::*;

#[derive(Debug)]
pub enum SetupError {
    UnknownGroupId,
    UnknownClientId,
    NotEnoughClients,
    ClientAlreadyInGroup,
    ClientNotInGroup,
    NoFreshKeyPackage,
    ClientError(ClientError),
    KeyPackageError(KeyPackageError),
    Unknown,
}

impl From<ClientError> for SetupError {
    fn from(e: ClientError) -> Self {
        SetupError::ClientError(e)
    }
}

impl From<ManagedGroupError> for SetupError {
    fn from(e: ManagedGroupError) -> Self {
        SetupError::ClientError(ClientError::ManagedGroupError(e))
    }
}

impl From<KeyPackageError> for SetupError {
    fn from(e: KeyPackageError) -> Self {
        SetupError::KeyPackageError(e)
    }
}

#[derive(Debug)]
pub enum SetupGroupError {
    NotEnoughMembers,
}

/// Errors that can occur when processing messages with the client.
#[derive(Debug, PartialEq)]
pub enum ClientError {
    NoMatchingKeyPackage,
    NoMatchingCredential,
    CiphersuiteNotSupported,
    NoMatchingGroup,
    NoCiphersuite,
    FailedToJoinGroup(WelcomeError),
    InvalidMessage(MlsGroupError),
    ManagedGroupError(ManagedGroupError),
    GroupError(MlsGroupError),
    TlsCodecError(tls_codec::Error),
    KeyPackageError(KeyPackageError),
    Unknown,
}

impl From<WelcomeError> for ClientError {
    fn from(e: WelcomeError) -> Self {
        ClientError::FailedToJoinGroup(e)
    }
}

impl From<ManagedGroupError> for ClientError {
    fn from(e: ManagedGroupError) -> Self {
        ClientError::ManagedGroupError(e)
    }
}

impl From<MlsGroupError> for ClientError {
    fn from(e: MlsGroupError) -> Self {
        ClientError::GroupError(e)
    }
}

impl From<tls_codec::Error> for ClientError {
    fn from(e: tls_codec::Error) -> Self {
        ClientError::TlsCodecError(e)
    }
}

impl From<KeyPackageError> for ClientError {
    fn from(e: KeyPackageError) -> Self {
        ClientError::KeyPackageError(e)
    }
}
