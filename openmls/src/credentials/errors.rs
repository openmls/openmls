use thiserror::Error;

use crate::error::LibraryError;

/// An error that occurs in methods of a [`Credential`].
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CredentialError {
    /// A library error occured.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The type of credential is not supported.
    #[error("Unsupported credential type.")]
    UnsupportedCredentialType,
    /// Verifying the signature with this credential failed.
    #[error("Invalid signature.")]
    InvalidSignature,
}
