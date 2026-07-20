//! Key schedule errors.

use thiserror::Error;

use crate::{
    error::LibraryError,
    schedule::psk::{PreSharedKeyId, PskType, ResumptionPskUsage},
};

// TODO: only the storage errors may be needed
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
