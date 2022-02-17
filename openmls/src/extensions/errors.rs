//! # Extension errors.
//!
//! An `ExtensionError` is thrown when an extension is invalid (for example when
//! decoding from raw bytes) or when a check on an extension fails.
//!
//! `ExtensionError` holds individual errors for each extension.
//! * `CapabilitiesExtensionError`
//! * `LifetimeExtensionError`
//! * `KeyPackageIdError`
//! * `ParentHashError`
//! * `RatchetTreeError`

use crate::error::{ErrorString, LibraryError};

use thiserror::Error;

/// Extension error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ExtensionError {
    /// Found a duplicate ratchet tree extension.
    #[error("Found a duplicate ratchet tree extension.")]
    DuplicateRatchetTreeExtension,
    /// Unsupported proposal type in required capabilities.
    #[error("Unsupported proposal type in required capabilities.")]
    UnsupportedProposalType,
    /// Unsupported extension type in required capabilities.
    #[error("Unsupported extension type in required capabilities.")]
    UnsupportedExtensionType,
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`ErrorString`] for more details.
    #[error(transparent)]
    InvalidExtensionType(#[from] ErrorString),
    /// See [`CapabilitiesExtensionError`] for more details.
    #[error(transparent)]
    Capabilities(#[from] CapabilitiesExtensionError),
    /// See [`LifetimeExtensionError`] for more details.
    #[error(transparent)]
    Lifetime(#[from] LifetimeExtensionError),
    /// See [`KeyPackageIdError`] for more details.
    #[error(transparent)]
    KeyPackageId(#[from] KeyPackageIdError),
    /// See [`ParentHashError`] for more details.
    #[error(transparent)]
    ParentHash(#[from] ParentHashError),
    /// See [`RatchetTreeError`] for more details.
    #[error(transparent)]
    RatchetTree(#[from] RatchetTreeError),
    /// See [`InvalidExtensionError`] for more details.
    #[error(transparent)]
    InvalidExtension(#[from] InvalidExtensionError),
}

/// Lifetime extension error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum LifetimeExtensionError {
    /// Invalid lifetime extensions.
    #[error("Invalid lifetime extensions.")]
    Invalid,
    /// Lifetime extension is expired.
    #[error("Lifetime extension is expired.")]
    Expired,
}

/// Capabilities extension error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CapabilitiesExtensionError {
    /// Invalid capabilities extensions.
    #[error("Invalid capabilities extensions.")]
    Invalid,
    /// Capabilities extension is missing a version field.
    #[error("Capabilities extension is missing a version field.")]
    EmptyVersionsField,
    /// Capabilities contains only unsupported ciphersuites.
    #[error("Capabilities contains only unsupported ciphersuites.")]
    UnsupportedCiphersuite,
}

/// KeyPackage Id error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum KeyPackageIdError {
    /// Invalid key package ID extensions.
    #[error("Invalid key package ID extensions.")]
    Invalid,
}

/// Parent hash error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ParentHashError {
    /// Invalid parent hash extensions.
    #[error("Invalid parent hash extensions.")]
    Invalid,
}

/// Ratchet tree error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum RatchetTreeError {
    /// Invalid ratchet tree extensions.
    #[error("Invalid ratchet tree extensions.")]
    Invalid,
}

/// Invalid extension error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum InvalidExtensionError {
    /// The provided extension list contains duplicate extensions.
    #[error("The provided extension list contains duplicate extensions.")]
    Duplicate,
}
