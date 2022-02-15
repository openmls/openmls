//! # MLS MlsGroup errors
//!
//! `WelcomeError`, `StageCommitError`, `DecryptionError`, and
//! `CreateCommitError`.

use crate::config::ConfigError;
use crate::credentials::CredentialError;
use crate::error::LibraryError;
use crate::framing::ValidationError;
use crate::group::errors::StageCommitError;
use crate::group::WelcomeError;
use crate::group::{CoreGroupError, CreateCommitError, ExporterError};
use crate::treesync::TreeSyncError;
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
    #[error("Tried to access a poisoned `CredentialBundle`. See [`PoisonError`](`std::sync::PoisonError`) for details.")]
    PoisonedCredentialBundle,
    #[error("No signature key was available to verify the message signature.")]
    NoSignatureKey,
    #[error("Can't create a new commit while another commit is still pending. Please clear or merge the pending commit before creating a new one.")]
    PendingCommitError,
    #[error("There is no pending commit that can be merged.")]
    NoPendingCommit,
    #[error("Can't clear an external commit, as the group can't merge `Member` commits yet. If an external commit is rejected by the DS, a new external init must be performed. See the MLS spec for more information.")]
    ExternalCommitError,
    #[error("Error performing key store operation.")]
    KeyStoreError,
    #[error("The incoming message's wire format was not compatible with the wire format policy for incoming messages.")]
    IncompatibleWireFormat,
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Group(#[from] CoreGroupError),
    #[error(transparent)]
    CreateCommit(#[from] CreateCommitError),
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
    #[error(transparent)]
    Exporter(#[from] ExporterError),
    #[error(transparent)]
    EmptyInput(#[from] EmptyInputError),
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
    #[error(transparent)]
    WelcomeError(#[from] WelcomeError),
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
    #[error("Tried to use a group after being evicted from it.")]
    UseAfterEviction,
    #[error("Can't create message because a pending proposal exists.")]
    PendingProposal,
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
