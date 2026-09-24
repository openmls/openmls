//! Errors for targeted messages.

use thiserror::Error;

use crate::error::LibraryError;

/// Error creating a targeted message.
#[derive(Debug, Error)]
pub enum CreateTargetedMessageError {
    /// The recipient's leaf index is not in the group tree.
    #[error("The recipient is not a member of the group.")]
    RecipientNotFound,
    /// The group is not active.
    #[error("The group is not in an active state.")]
    GroupNotActive,
    /// A library error occurred.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
}

/// Error processing a targeted message.
#[derive(Debug, Error)]
pub enum ProcessTargetedMessageError<StorageError> {
    /// The group ID in the message doesn't match.
    #[error("The group ID in the targeted message does not match.")]
    GroupIdMismatch,
    /// The epoch in the message doesn't match.
    #[error("The epoch in the targeted message does not match.")]
    EpochMismatch,
    /// The message was not intended for this recipient.
    #[error("The recipient leaf index does not match own leaf index.")]
    NotIntendedRecipient,
    /// The sender's leaf index refers to a blank leaf.
    #[error("The sender's leaf index refers to a blank or missing leaf.")]
    SenderNotFound,
    /// Decryption of sender auth data failed.
    #[error("Failed to decrypt sender authentication data.")]
    SenderAuthDataDecryptionFailed,
    /// The sender auth data could not be deserialized.
    #[error("Malformed sender authentication data.")]
    MalformedSenderAuthData,
    /// Signature verification failed.
    #[error("Signature verification on targeted message failed.")]
    SignatureVerificationFailed,
    /// Decryption of the message content failed.
    #[error("Failed to decrypt targeted message content.")]
    ContentDecryptionFailed,
    /// The decrypted content could not be deserialized.
    #[error("Malformed targeted message content.")]
    MalformedContent,
    /// The group is not active.
    #[error("The group is not in an active state.")]
    GroupNotActive,
    /// Error reading from storage.
    #[error("Error reading from storage: {0}")]
    StorageError(StorageError),
    /// A library error occurred.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
}
