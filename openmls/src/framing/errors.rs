//! # Framing errors.
//!
//! This module contains errors related to message framing operations.

use crate::error::LibraryError;
use thiserror::Error;

#[cfg(feature = "virtual-clients-draft")]
use crate::ciphersuite::ReuseGuardDerivationError;

// === Public ===

// Re-export errors
pub use crate::tree::secret_tree::SecretTreeError;

/// Message decryption error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum MessageDecryptionError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Couldn't find a ratcheting secret for the given sender and generation.
    #[error("Couldn't find a ratcheting secret for the given sender and generation.")]
    GenerationOutOfBound,
    /// An error occurred during AEAD decryption.
    #[error("An error occurred during AEAD decryption.")]
    AeadError,
    /// The WireFormat was not PrivateMessage.
    #[error("The WireFormat was not PrivateMessage.")]
    WrongWireFormat,
    /// The content is malformed.
    #[error("The content is malformed.")]
    MalformedContent,
    /// See [`SecretTreeError`] for more details.
    #[error(transparent)]
    SecretTreeError(#[from] SecretTreeError),
    /// Virtual-clients reuse-guard inversion failed.
    #[cfg(feature = "virtual-clients-draft")]
    #[error(transparent)]
    VirtualClientsError(#[from] crate::components::vc_derivation_info::VirtualClientsError),
}

#[cfg(feature = "virtual-clients-draft")]
impl From<ReuseGuardDerivationError> for MessageDecryptionError {
    fn from(error: ReuseGuardDerivationError) -> Self {
        match error {
            ReuseGuardDerivationError::VirtualClients(inner) => Self::VirtualClientsError(inner),
            ReuseGuardDerivationError::Library(inner) => Self::LibraryError(inner),
        }
    }
}

/// Message encryption error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum MessageEncryptionError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The WireFormat was not PrivateMessage.
    #[error("The WireFormat was not PrivateMessage.")]
    WrongWireFormat,
    /// See [`SecretTreeError`] for more details.
    #[error(transparent)]
    SecretTreeError(#[from] SecretTreeError),
    /// Error reading from or writing to storage
    #[error("Error reading from or writing to storage: {0}")]
    StorageError(StorageError),
    /// Virtual-clients reuse-guard derivation failed.
    #[cfg(feature = "virtual-clients-draft")]
    #[error(transparent)]
    VirtualClientsError(#[from] crate::components::vc_derivation_info::VirtualClientsError),
}

#[cfg(feature = "virtual-clients-draft")]
impl<StorageError> From<ReuseGuardDerivationError> for MessageEncryptionError<StorageError> {
    fn from(error: ReuseGuardDerivationError) -> Self {
        match error {
            ReuseGuardDerivationError::VirtualClients(inner) => Self::VirtualClientsError(inner),
            ReuseGuardDerivationError::Library(inner) => Self::LibraryError(inner),
        }
    }
}

/// MlsMessage error
#[derive(Error, Debug, Clone)]
pub enum MlsMessageError {
    /// The message could not be decoded.
    #[error("The message could not be decoded.")]
    UnableToDecode,
    /// The message (or one of its parts) is too large to be encoded.
    #[error("The message (or one of its parts) is too large to be encoded.")]
    UnableToEncode,
}

/// ProtocolMessage error
#[derive(Error, Debug, Clone)]
pub enum ProtocolMessageError {
    /// Wrong wire format
    #[error("Wrong wire format")]
    WrongWireFormat,
}
