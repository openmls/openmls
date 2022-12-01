//! # Key Package errors
//!
//! `KeyPackageError` are thrown on errors handling `KeyPackage`s and
//! `KeyPackageBundle`s.

use thiserror::Error;

use crate::{error::LibraryError, extensions::errors::ExtensionError};

/// KeyPackage verify error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum KeyPackageVerifyError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The lifetime of the leaf node is not valid.
    #[error("The lifetime of the leaf node is not valid.")]
    InvalidLifetime,
    /// The lifetime of the leaf node is missing.
    #[error("The lifetime of the leaf node is missing.")]
    MissingLifetime,
    /// A key package extension is not supported in the leaf's capabilities.
    #[error("A key package extension is not supported in the leaf's capabilities.")]
    UnsupportedExtension,
    /// The key package signature is not valid.
    #[error("The key package signature is not valid.")]
    InvalidSignature,
}

/// KeyPackage extension support error
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum KeyPackageExtensionSupportError {
    /// The key package does not support all required extensions.
    #[error("The key package does not support all required extensions.")]
    UnsupportedExtension,
}

/// KeyPackage new error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum KeyPackageNewError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The ciphersuite does not match the signature scheme.
    #[error("The ciphersuite does not match the signature scheme.")]
    CiphersuiteSignatureSchemeMismatch,
}

/// KeyPackageBundle new error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum KeyPackageBundleNewError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Creating a new key package requires at least one ciphersuite.
    #[error("Creating a new key package requires at least one ciphersuite.")]
    NoCiphersuitesSupplied,
    /// The ciphersuite does not match the signature scheme.
    #[error("The ciphersuite does not match the signature scheme.")]
    CiphersuiteSignatureSchemeMismatch,
    /// Duplicate extensions are not allowed.
    #[error("Duplicate extensions are not allowed.")]
    DuplicateExtension,
    /// The list of ciphersuites is not consistent with the capabilities extension.
    #[error("The list of ciphersuites is not consistent with the capabilities extension.")]
    CiphersuiteMismatch,
    /// See [`ExtensionError`] for more details.
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
}
