use thiserror::Error;

use crate::error::LibraryError;

#[derive(Error, Debug, PartialEq, Clone)]
pub enum CredentialError {
    #[error("Unsupported credential type.")]
    UnsupportedCredentialType,
    #[error("Invalid signature.")]
    InvalidSignature,
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
}
