//! Key schedule errors.

use openmls_traits::types::CryptoError;
use thiserror::Error;

use crate::error::LibraryError;

/// Key schedule state error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ErrorState {
    #[error("Expected to be in initial state.")]
    Init,
    #[error("Expected to be in epoch state.")]
    Context,
}

/// Key schedule error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum KeyScheduleError {
    #[error("The ciphersuite of the given public group state is not supported.")]
    UnsupportedCiphersuite,
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error(transparent)]
    InvalidState(#[from] ErrorState),
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
}

/// PSK secret error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum PskError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("More than 2^16 PSKs were provided.")]
    TooManyKeys,
    #[error("The PSK could not be found in the key store.")]
    KeyNotFound,
}

#[cfg(any(feature = "test-utils", test))]
implement_error! {
    pub enum KsTestVectorError {
        JoinerSecretMismatch = "The computed joiner secret doesn't match the one in the test vector.",
        WelcomeSecretMismatch = "The computed welcome secret doesn't match the one in the test vector.",
        InitSecretMismatch = "The computed init secret doesn't match the one in the test vector.",
        GroupContextMismatch = "The group context doesn't match the one in the test vector.",
        SenderDataSecretMismatch = "The computed sender data secret doesn't match the one in the test vector.",
        EncryptionSecretMismatch = "The computed encryption secret doesn't match the one in the test vector.",
        ExporterSecretMismatch = "The computed exporter secret doesn't match the one in the test vector.",
        AuthenticationSecretMismatch = "The computed authentication secret doesn't match the one in the test vector.",
        ExternalSecretMismatch = "The computed external secret doesn't match the one in the test vector.",
        ConfirmationKeyMismatch = "The computed confirmation key doesn't match the one in the test vector.",
        MembershipKeyMismatch = "The computed membership key doesn't match the one in the test vector.",
        ResumptionSecretMismatch = "The computed resumption secret doesn't match the one in the test vector.",
        ExternalPubMismatch = "The computed external public key doesn't match the one in the test vector.",
    }
}
