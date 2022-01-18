use thiserror::Error;

#[derive(Error, Debug, PartialEq, Clone)]
pub enum CredentialError {
    #[error("Unsupported credential type.")]
    UnsupportedCredentialType,
    #[error("Invalid signature.")]
    InvalidSignature,
    #[error("An unrecoverable error has occurred due to a bug in the implementation.")]
    LibraryError,
    #[error("Could not verify the signature of the Credential.")]
    VerificationFailed,
}

#[derive(Error, Debug, PartialEq, Clone)]
pub enum CredentialBundleError {
    #[error("An unrecoverable error has occurred due to a bug in the implementation.")]
    LibraryError,
    #[error("Could not sign with the CredentialBundle.")]
    SigningFailed,
}
