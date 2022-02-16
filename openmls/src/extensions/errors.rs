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

use openmls_traits::types::CryptoError;
use thiserror::Error;
use tls_codec::Error as TlsCodecError;

/// Extension error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ExtensionError {
    #[error("Found a duplicate ratchet tree extension.")]
    DuplicateRatchetTreeExtension,
    #[error("Unsupported proposal type in required capabilities.")]
    UnsupportedProposalType,
    #[error("Unsupported extension type in required capabilities.")]
    UnsupportedExtensionType,
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error(transparent)]
    InvalidExtensionType(#[from] ErrorString),
    #[error(transparent)]
    Capabilities(#[from] CapabilitiesExtensionError),
    #[error(transparent)]
    Lifetime(#[from] LifetimeExtensionError),
    #[error(transparent)]
    KeyPackageId(#[from] KeyPackageIdError),
    #[error(transparent)]
    ParentHash(#[from] ParentHashError),
    #[error(transparent)]
    RatchetTree(#[from] RatchetTreeError),
    #[error(transparent)]
    CodecError(#[from] TlsCodecError),
    #[error(transparent)]
    InvalidExtension(#[from] InvalidExtensionError),
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
}

/// Lifetime extension error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum LifetimeExtensionError {
    #[error("Invalid lifetime extensions.")]
    Invalid,
    #[error("Lifetime extension is expired.")]
    Expired,
}

/// Capabilities extension error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CapabilitiesExtensionError {
    #[error("Invalid capabilities extensions.")]
    Invalid,
    #[error("Capabilities extension is missing a version field.")]
    EmptyVersionsField,
    #[error("Capabilities contains only unsupported ciphersuites.")]
    UnsupportedCiphersuite,
}

/// KeyPackage Id error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum KeyPackageIdError {
    #[error("Invalid key package ID extensions.")]
    Invalid,
}

/// Parent hash error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ParentHashError {
    #[error("Invalid parent hash extensions.")]
    Invalid,
}

/// Ratchet tree error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum RatchetTreeError {
    #[error("Invalid ratchet tree extensions.")]
    Invalid,
}

/// Invalid extension error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum InvalidExtensionError {
    #[error("The provided extension list contains duplicate extensions.")]
    Duplicate,
}
