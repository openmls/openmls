//! # Key Package errors
//!
//! `KeyPackageError` are thrown on errors handling `KeyPackage`s.

use thiserror::Error;

/// KeyPackage extension support error
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum KeyPackageExtensionSupportError {
    /// The key package does not support all required extensions.
    #[error("The key package does not support all required extensions.")]
    UnsupportedExtension,
}
