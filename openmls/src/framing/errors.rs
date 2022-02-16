//! # Framing errors.
//!
//! `MlsPlaintextError` and `MlsCiphertextError` are thrown on errors
//! handling `MlsPlaintext` and `MlsCiphertext`.

use crate::{error::LibraryError, tree::secret_tree::SecretTreeError};
use thiserror::Error;

// === Public ===

/// Message decryption error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum MessageDecryptionError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("Couldn't find a ratcheting secret for the given sender and generation.")]
    GenerationOutOfBound,
    #[error("An error occurred during AEAD decryption.")]
    AeadError,
    #[error("The WireFormat was not MLSCiphertext.")]
    WrongWireFormat,
    #[error("The content is malformed.")]
    MalformedContent,
    #[error(transparent)]
    SecretTreeError(#[from] SecretTreeError),
    #[error(transparent)]
    SenderError(#[from] SenderError),
}

/// Message encryption error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum MessageEncryptionError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The WireFormat was not MLSCiphertext.")]
    WrongWireFormat,
    #[error(transparent)]
    SecretTreeError(#[from] SecretTreeError),
    #[error(transparent)]
    SenderError(#[from] SenderError),
}

/// Sender error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum SenderError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The requested client is not a member of the group.")]
    NotAMember,
    #[error("Unknown sender")]
    UnknownSender,
}

/// MlsMessage error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum MlsMessageError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The message could not be decoded.")]
    UnableToDecode,
}
