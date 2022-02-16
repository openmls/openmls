//! Key schedule errors.

use openmls_traits::types::CryptoError;
use thiserror::Error;

use crate::error::LibraryError;

// === Public ===

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

// === Crate ===

/// Key schedule state error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum ErrorState {
    #[error("Expected to be in initial state.")]
    Init,
    #[error("Expected to be in epoch state.")]
    Context,
}

/// Key schedule error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum KeyScheduleError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error(transparent)]
    InvalidState(#[from] ErrorState),
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
}

#[cfg(any(feature = "test-utils", test))]
/// KeySchedule test vector error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum KsTestVectorError {
    #[error("The computed joiner secret doesn't match the one in the test vector.")]
    JoinerSecretMismatch,
    #[error("The computed welcome secret doesn't match the one in the test vector.")]
    WelcomeSecretMismatch,
    #[error("The computed init secret doesn't match the one in the test vector.")]
    InitSecretMismatch,
    #[error("The group context doesn't match the one in the test vector.")]
    GroupContextMismatch,
    #[error("The computed sender data secret doesn't match the one in the test vector.")]
    SenderDataSecretMismatch,
    #[error("The computed encryption secret doesn't match the one in the test vector.")]
    EncryptionSecretMismatch,
    #[error("The computed exporter secret doesn't match the one in the test vector.")]
    ExporterSecretMismatch,
    #[error("The computed authentication secret doesn't match the one in the test vector.")]
    AuthenticationSecretMismatch,
    #[error("The computed external secret doesn't match the one in the test vector.")]
    ExternalSecretMismatch,
    #[error("The computed confirmation key doesn't match the one in the test vector.")]
    ConfirmationKeyMismatch,
    #[error("The computed membership key doesn't match the one in the test vector.")]
    MembershipKeyMismatch,
    #[error("The computed resumption secret doesn't match the one in the test vector.")]
    ResumptionSecretMismatch,
    #[error("The computed external public key doesn't match the one in the test vector.")]
    ExternalPubMismatch,
}
