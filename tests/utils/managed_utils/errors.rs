use openmls::prelude::*;

#[derive(Debug)]
pub enum SetupError {
    UnknownGroupId,
    UnknownClientId,
    NotEnoughClients,
    ClientAlreadyInGroup,
    ClientNotInGroup,
    NoFreshKeyPackage,
    ClientError(ClientError),
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

#[derive(Debug)]
pub enum SetupGroupError {
    NotEnoughMembers,
}

/// Errors that can occur when processing messages with the client.
#[derive(Debug)]
pub enum ClientError {
    NoMatchingKeyPackage,
    NoMatchingCredential,
    CiphersuiteNotSupported,
    NoMatchingGroup,
    NoCiphersuite,
    FailedToJoinGroup(WelcomeError),
    InvalidMessage(GroupError),
    ManagedGroupError(ManagedGroupError),
    GroupError(GroupError),
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

impl From<GroupError> for ClientError {
    fn from(e: GroupError) -> Self {
        ClientError::GroupError(e)
    }
}
