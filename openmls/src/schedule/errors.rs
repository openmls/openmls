//! Key schedule errors.

use openmls_traits::types::CryptoError;
use thiserror::Error;

use crate::{
    error::LibraryError,
    schedule::psk::{PreSharedKeyId, PskType, ResumptionPskUsage},
};

/// PSK secret error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum PskError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// More than 2^16 PSKs were provided.
    #[error("More than 2^16 PSKs were provided.")]
    TooManyKeys,
    /// The PSK could not be found in the store.
    #[error("The PSK could not be found in the store.")]
    KeyNotFound,
    /// Failed to write PSK into storage.
    #[error("Failed to write PSK storage.")]
    Storage,
    /// Type mismatch.
    #[error("Type mismatch. Expected {allowed:?}, got {got:?}.")]
    TypeMismatch {
        /// Allowed PSK types.
        allowed: Vec<PskType>,
        /// Got PSK type.
        got: PskType,
    },
    /// Usage mismatch.
    #[error("Usage mismatch. Expected either of `{allowed:?}`, got `{got:?}`.")]
    UsageMismatch {
        /// Allowed PSK types.
        allowed: Vec<ResumptionPskUsage>,
        /// Got PSK type.
        got: ResumptionPskUsage,
    },
    /// Nonce length mismatch.
    #[error("Nonce length mismatch. Expected either of `{expected:?}`, got `{got:?}`.")]
    NonceLengthMismatch {
        /// Expected nonce length.
        expected: usize,
        /// Got nonce length.
        got: usize,
    },
    /// Duplicate PSK ID.
    #[error("Duplicate PSK ID. First detected duplicate is `{first:?}`.")]
    Duplicate {
        /// First detected duplicate.
        first: PreSharedKeyId,
    },
}

// === Crate ===

/// Key schedule state error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum ErrorState {
    /// Expected to be in initial state.
    #[error("Expected to be in initial state.")]
    Init,
    /// Expected to be in epoch state.
    #[error("Expected to be in epoch state.")]
    Context,
}

/// Key schedule error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum KeyScheduleError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`ErrorState`] for more details.
    #[error(transparent)]
    InvalidState(#[from] ErrorState),
    /// See [`CryptoError`] for more details.
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
}

#[cfg(any(feature = "test-utils", test))]
/// KeySchedule test vector error
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum KsTestVectorError {
    /// The computed joiner secret doesn't match the one in the test vector.
    #[error("The computed joiner secret doesn't match the one in the test vector.")]
    JoinerSecretMismatch,
    /// The computed welcome secret doesn't match the one in the test vector.
    #[error("The computed welcome secret doesn't match the one in the test vector.")]
    WelcomeSecretMismatch,
    /// The computed init secret doesn't match the one in the test vector.
    #[error("The computed init secret doesn't match the one in the test vector.")]
    InitSecretMismatch,
    /// The group context doesn't match the one in the test vector.
    #[error("The group context doesn't match the one in the test vector.")]
    GroupContextMismatch,
    /// The computed sender data secret doesn't match the one in the test vector.
    #[error("The computed sender data secret doesn't match the one in the test vector.")]
    SenderDataSecretMismatch,
    /// The computed encryption secret doesn't match the one in the test vector.
    #[error("The computed encryption secret doesn't match the one in the test vector.")]
    EncryptionSecretMismatch,
    /// The computed exporter secret doesn't match the one in the test vector.
    #[error("The computed exporter secret doesn't match the one in the test vector.")]
    ExporterSecretMismatch,
    /// The computed epoch authenticator doesn't match the one in the test vector.
    #[error("The computed epoch authenticator doesn't match the one in the test vector.")]
    EpochAuthenticatorMismatch,
    /// The computed external secret doesn't match the one in the test vector.
    #[error("The computed external secret doesn't match the one in the test vector.")]
    ExternalSecretMismatch,
    /// The computed confirmation key doesn't match the one in the test vector.
    #[error("The computed confirmation key doesn't match the one in the test vector.")]
    ConfirmationKeyMismatch,
    /// The computed membership key doesn't match the one in the test vector.
    #[error("The computed membership key doesn't match the one in the test vector.")]
    MembershipKeyMismatch,
    /// The computed resumption psk doesn't match the one in the test vector.
    #[error("The computed resumption psk doesn't match the one in the test vector.")]
    ResumptionPskMismatch,
    /// The computed external public key doesn't match the one in the test vector.
    #[error("The computed external public key doesn't match the one in the test vector.")]
    ExternalPubMismatch,
    /// The computed exporter secret doesn't match the on ein the test vector.
    #[error("The computed exporter secret doesn't match the on ein the test vector.")]
    ExporterMismatch,
}
