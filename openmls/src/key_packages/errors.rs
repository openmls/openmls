//! # Key Package errors
//!
//! `KeyPackageError` are thrown on errors handling `KeyPackage`s and
//! `KeyPackageBundle`s.

use openmls_traits::types::CryptoError;
use thiserror::Error;
use tls_codec::Error as TlsCodecError;

use crate::{
    config::ConfigError, credentials::CredentialError, error::LibraryError,
    extensions::ExtensionError,
};

/// KeyPackage error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum KeyPackageError {
    #[error("A mandatory extension is missing in the key package.")]
    MandatoryExtensionsMissing,
    #[error("The lifetime extension of the key package is not valid.")]
    InvalidLifetimeExtension,
    #[error("The key package signature is not valid.")]
    InvalidSignature,
    #[error("Duplicate extensions are not allowed.")]
    DuplicateExtension,
    #[error("The key package does not support all required extensions.")]
    UnsupportedExtension,
    #[error("Creating a new key package requires at least one ciphersuite.")]
    NoCiphersuitesSupplied,
    #[error("The list of ciphersuites is not consistent with the capabilities extension.")]
    CiphersuiteMismatch,
    #[error("The ciphersuite does not match the signature scheme.")]
    CiphersuiteSignatureSchemeMismatch,
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    ConfigError(#[from] ConfigError),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error(transparent)]
    CodecError(#[from] TlsCodecError),
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
}
