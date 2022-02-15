//! # Framing errors.
//!
//! `MlsPlaintextError` and `MlsCiphertextError` are thrown on errors
//! handling `MlsPlaintext` and `MlsCiphertext`.

use crate::{
    credentials::CredentialError, error::LibraryError, tree::secret_tree::SecretTreeError,
};
use thiserror::Error;

// === Public ===

/// Message decryption error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum MessageDecryptionError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("Couldn't find a ratcheting secret for the given sender and generation.")]
    GenerationOutOfBound,
    #[error("An error occurred while decrypting.")]
    DecryptionError,
    #[error("The WireFormat was MLSPlaintext.")]
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
    #[error("The WireFormat was MLSPlaintext.")]
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

/// Verification error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum VerificationError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The MlsPlaintext membership tag is missing")]
    MissingMembershipTag,
    #[error("The MlsPlaintext membership tag is invalid")]
    InvalidMembershipTag,
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
}

/// Validation error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ValidationError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error(
        "The MlsPlaintext message is not a Commit despite the sender begin of type NewMember."
    )]
    NotACommit,
    #[error("The Commit doesn't have a path despite the sender being of type NewMember.")]
    NoPath,
    #[error("The MlsPlaintext contains an application message but was not encrypted.")]
    UnencryptedApplicationMessage,
    #[error("Sender is not part of the group.")]
    UnknownSender,
    #[error("The confirmation tag is missing.")]
    MissingConfirmationTag,
    #[error("Wrong wire format.")]
    WrongWireFormat,
    #[error("Verifying the signature failed.")]
    InvalidSignature,
    #[error(transparent)]
    VerificationError(#[from] VerificationError),
    /// Could not decrypt the message
    #[error(transparent)]
    UnableToDecrypt(#[from] MessageDecryptionError),
}

/// MlsMessage error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum MlsMessageError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The message could not be decoded.")]
    UnableToDecode,
}
