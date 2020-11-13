//! # Key Package errors
//!
//! `KeyPackageError` are thrown on errors handling `KeyPackage`s and
//! `KeyPackageBundle`s.

use crate::{config::ConfigError, extensions::ExtensionError};
use std::error::Error;

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u16)]
pub enum KeyPackageError {
    /// An unknown extension error occurred.
    UnknownExtensionError = 0,

    /// The requested extension is not present in the key package.
    ExtensionNotPresent = 1,

    /// The requested ciphersuite is not supported.
    UnsupportedCiphersuite = 2,

    /// An unknown configuration error occurred.
    UnknownConfigError = 3,

    /// A mandatory extension is missing in the key package.
    MandatoryExtensionsMissing = 4,

    /// The lifetime extension of the key package is not valid.
    InvalidLifetimeExtension = 5,

    /// The key package signature is not valid.
    InvalidSignature = 6,

    /// An unknown OpenMLS library error occurred.
    LibraryError = 7,

    /// Duplicate extensions are not allowed.
    DuplicateExtension = 8,

    /// Creating a new key package requires at least one ciphersuite.
    NoCiphersuitesSupplied = 9,

    /// The list of ciphersuites is not consistent with the capabilities extension.
    InvalidCapabilitiesExtension = 10,
}

implement_enum_display!(KeyPackageError);

impl From<ExtensionError> for KeyPackageError {
    fn from(e: ExtensionError) -> Self {
        match e {
            ExtensionError::InvalidExtensionType => KeyPackageError::ExtensionNotPresent,
            _ => KeyPackageError::UnknownExtensionError,
        }
    }
}

impl From<ConfigError> for KeyPackageError {
    fn from(e: ConfigError) -> Self {
        match e {
            ConfigError::UnsupportedCiphersuite => KeyPackageError::UnsupportedCiphersuite,
            _ => KeyPackageError::UnknownConfigError,
        }
    }
}

impl Error for KeyPackageError {
    fn description(&self) -> &str {
        match self {
            Self::UnknownExtensionError => "An unknown extension error occurred.",
            Self::ExtensionNotPresent => {
                "The requested extension is not present in the key package."
            }
            Self::UnsupportedCiphersuite => "The requested ciphersuite is not supported.",
            Self::UnknownConfigError => "An unknown configuration error occurred.",
            Self::MandatoryExtensionsMissing => {
                "A mandatory extension is missing in the key package."
            }
            Self::InvalidLifetimeExtension => {
                "The lifetime extension of the key package is not valid."
            }
            Self::InvalidSignature => "The key package signature is not valid.",
            Self::LibraryError => "An unknown OpenMLS library error occurred.",
            Self::DuplicateExtension => "Duplicate extensions are not allowed.",
            Self::NoCiphersuitesSupplied => {
                "Creating a new key package requires at least one ciphersuite."
            }
            Self::InvalidCapabilitiesExtension => {
                "The list of ciphersuites is not consistent with the capabilities extension."
            }
        }
    }
}
