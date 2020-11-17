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

use crate::{codec::CodecError, config::ConfigError};
use std::error::Error;

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u16)]
pub enum ExtensionError {
    /// Invalid extension type error.
    InvalidExtensionType,

    /// Error when decoding an extension.
    DecodingError,

    /// Capabilities extension error.
    /// See `CapabilitiesExtensionError` for details.
    Capabilities(CapabilitiesExtensionError),

    /// Lifetime extension error.
    /// See `LifetimeExtensionError` for details.
    Lifetime(LifetimeExtensionError),

    /// Key package ID extension error.
    /// See `KeyPackageIdError` for details.
    KeyPackageId(KeyPackageIdError),

    /// Parent hash extension error.
    /// See `ParentHashError` for details.
    ParentHash(ParentHashError),

    /// Ratchet tree extension error.
    /// See `RatchetTreeError` for details.
    RatchetTree(RatchetTreeError),
}

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u16)]
pub enum LifetimeExtensionError {
    /// Invalid lifetime extensions.
    Invalid = 0,

    /// Lifetime extension is expired.
    Expired = 1,
}

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u16)]
pub enum CapabilitiesExtensionError {
    /// Invalid capabilities extensions.
    Invalid = 0,

    /// Capabilities extension is missing a version field.
    EmptyVersionsField = 1,

    /// Capabilities contains only unsupported ciphersuites.
    UnsupportedCiphersuite = 2,
}

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u16)]
pub enum KeyPackageIdError {
    /// Invalid key package ID extensions.
    Invalid = 0,
}

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u16)]
pub enum ParentHashError {
    /// Invalid parent hash extensions.
    Invalid = 0,
}

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u16)]
pub enum RatchetTreeError {
    /// Invalid ratchet tree extensions.
    Invalid = 0,
}

implement_enum_display!(ExtensionError);
implement_enum_display!(LifetimeExtensionError);
implement_enum_display!(CapabilitiesExtensionError);
implement_enum_display!(KeyPackageIdError);
implement_enum_display!(ParentHashError);
implement_enum_display!(RatchetTreeError);

impl Error for ExtensionError {
    fn description(&self) -> &str {
        match self {
            Self::DecodingError => "Error decoding an extension.",
            Self::InvalidExtensionType => {
                "The requested extension type is not supported by OpenMLS."
            }
            Self::Capabilities(e) => match e {
                CapabilitiesExtensionError::Invalid => "Error decoding a capabilities extensions.",
                CapabilitiesExtensionError::EmptyVersionsField => {
                    "The versions field in the extension is empty."
                }
                CapabilitiesExtensionError::UnsupportedCiphersuite => {
                    "No supported ciphersuite in the extension."
                }
            },
            Self::KeyPackageId(e) => match e {
                KeyPackageIdError::Invalid => "Error decoding a key package id extensions.",
            },
            Self::ParentHash(e) => match e {
                ParentHashError::Invalid => "Error decoding a parent hash extensions.",
            },
            Self::RatchetTree(e) => match e {
                RatchetTreeError::Invalid => "Error decoding a ratchet tree extensions.",
            },
            Self::Lifetime(e) => match e {
                LifetimeExtensionError::Invalid => "Invalid lifetime extensions.",
                LifetimeExtensionError::Expired => "Lifetime extension is expired.",
            },
        }
    }
}

impl From<ConfigError> for ExtensionError {
    fn from(_e: ConfigError) -> Self {
        ExtensionError::InvalidExtensionType
    }
}

impl From<CodecError> for ExtensionError {
    fn from(e: CodecError) -> Self {
        match e {
            CodecError::DecodingError => ExtensionError::DecodingError,
            CodecError::EncodingError | CodecError::Other => {
                panic!("Extension errors can't result from encoding errors.")
            }
        }
    }
}

impl From<ExtensionError> for CodecError {
    fn from(_e: ExtensionError) -> Self {
        CodecError::DecodingError
    }
}
