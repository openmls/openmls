use thiserror::Error;

#[derive(Error, Debug, PartialEq, Clone)]
pub enum CredentialError {
    #[error("Unsupported credential type.")]
    UnsupportedCredentialType,
    #[error("Invalid signature.")]
    InvalidSignature,
    #[error("An unrecoverable error has occurred due to a bug in the implementation.")]
    LibraryError,
}

#[derive(Error, Debug, PartialEq, Clone)]
pub enum CredentialBundleError {
    #[error("Could not sign with the CredentialBundle.")]
    SigningFailed,
    #[error("An unrecoverable error has occurred due to a bug in the implementation.")]
    LibraryError,
}
