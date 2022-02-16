//! # MLS MlsGroup errors
//!
//! `WelcomeError`, `StageCommitError`, `DecryptionError`, and
//! `CreateCommitError`.

use crate::{
    credentials::CredentialError,
    error::LibraryError,
    framing::ValidationError,
    group::{errors::StageCommitError, CoreGroupError, CreateCommitError, ExporterError},
    treesync::TreeSyncError,
};
use openmls_traits::types::CryptoError;
use thiserror::Error;
use tls_codec::Error as TlsCodecError;

/// MlsGroup error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum MlsGroupError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error(
        "Couldn't find a `CredentialBundle` in the `KeyStore` that matches the one in my leaf."
    )]
    NoMatchingCredentialBundle,
    #[error("Couldn't find a `KeyPackageBundle` in the `KeyStore` that matches the given `KeyPackage` hash.")]
    NoMatchingKeyPackageBundle,
    #[error("There is no pending commit that can be merged.")]
    NoPendingCommit,
    #[error("Error performing key store operation.")]
    KeyStoreError,
    #[error("The incoming message's wire format was not compatible with the wire format policy for incoming messages.")]
    IncompatibleWireFormat,
    #[error(transparent)]
    Group(#[from] CoreGroupError),
    #[error(transparent)]
    CreateCommit(#[from] CreateCommitError),
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    #[error(transparent)]
    Exporter(#[from] ExporterError),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error(transparent)]
    TreeSyncError(#[from] TreeSyncError),
    #[error(transparent)]
    ValidationError(#[from] ValidationError),
    #[error(transparent)]
    TlsCodecError(#[from] TlsCodecError),
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
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
