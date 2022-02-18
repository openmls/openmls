//! # Key Package errors
//!
//! `KeyPackageError` are thrown on errors handling `KeyPackage`s and
//! `KeyPackageBundle`s.

use openmls_traits::types::CryptoError;
use thiserror::Error;
use tls_codec::Error as TlsCodecError;

use crate::{credentials::CredentialError, error::LibraryError, extensions::ExtensionError};

/// KeyPackage error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum KeyPackageError {
    /// A mandatory extension is missing in the key package.
    #[error("A mandatory extension is missing in the key package.")]
    MandatoryExtensionsMissing,
    /// The lifetime extension of the key package is not valid.
    #[error("The lifetime extension of the key package is not valid.")]
    InvalidLifetimeExtension,
    /// The key package signature is not valid.
    #[error("The key package signature is not valid.")]
    InvalidSignature,
    /// Duplicate extensions are not allowed.
    #[error("Duplicate extensions are not allowed.")]
    DuplicateExtension,
    /// The key package does not support all required extensions.
    #[error("The key package does not support all required extensions.")]
    UnsupportedExtension,
    /// Creating a new key package requires at least one ciphersuite.
    #[error("Creating a new key package requires at least one ciphersuite.")]
    NoCiphersuitesSupplied,
    /// The list of ciphersuites is not consistent with the capabilities extension.
    #[error("The list of ciphersuites is not consistent with the capabilities extension.")]
    CiphersuiteMismatch,
    /// The ciphersuite does not match the signature scheme.
    #[error("The ciphersuite does not match the signature scheme.")]
    CiphersuiteSignatureSchemeMismatch,
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`ExtensionError`] for more details.
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    /// See [`CredentialError`] for more details.
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    /// See [`TlsCodecError`] for more details.
    #[error(transparent)]
    CodecError(#[from] TlsCodecError),
    /// See [`CryptoError`] for more details.
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
}
