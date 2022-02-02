use thiserror::Error;

use crate::error::LibraryError;

/// An error that occurs in methods of a [`Credential`].
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CredentialError {
    /// The type of credential is not supported.
    #[error("Unsupported credential type.")]
    UnsupportedCredentialType,
    /// The signature that was verified with the credential was invalid.
    #[error("Invalid signature.")]
    InvalidSignature,
    /// A library error occured.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
}
