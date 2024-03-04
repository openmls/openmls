//! # Framing errors.
//!
//! This module contains errors related to message framing operations.

use crate::error::LibraryError;
use thiserror::Error;

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
}

/// Message encryption error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum MessageEncryptionError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The WireFormat was not PrivateMessage.
    #[error("The WireFormat was not PrivateMessage.")]
    WrongWireFormat,
    /// See [`SecretTreeError`] for more details.
    #[error(transparent)]
    SecretTreeError(#[from] SecretTreeError),
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
