//! TreeSync errors
//!
//! This module exposes [`ApplyUpdatePathError`] and [`PublicTreeError`].

use thiserror::Error;

// === Public errors ===

/// Errors that can happen during lifetime validation.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LifetimeError {
    /// Lifetime range is too wide.
    #[error("Lifetime range is too wide.")]
    RangeTooBig,
    /// Lifetime doesn't cover current time.
    #[error("Lifetime doesn't cover current time.")]
    NotCurrent,
}
