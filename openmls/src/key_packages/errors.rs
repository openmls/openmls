//! # Key Package errors
//!
//! `KeyPackageError` are thrown on errors handling `KeyPackage`s.

use thiserror::Error;

use crate::{ciphersuite::signable::SignatureError, error::LibraryError};

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
    /// The leaf node signature is not valid.
    #[error("The leaf node signature is not valid.")]
    InvalidLeafNodeSignature,
    /// Invalid LeafNode source type
    #[error("Invalid LeafNode source type")]
    InvalidLeafNodeSourceType,
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
pub enum KeyPackageNewError<KeyStoreError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The ciphersuite does not match the signature scheme.
    #[error("The ciphersuite does not match the signature scheme.")]
    CiphersuiteSignatureSchemeMismatch,
    /// Accessing the key store failed.
    #[error("Accessing the key store failed.")]
    KeyStoreError(KeyStoreError),
    /// Unable to find the private key in the key store corresponding to the
    /// provided public key.
    #[error(
        "Unable to find the private key in the key store corresponding to the provided public key."
    )]
    MissingPrivateKey,
    /// See [`SignatureError`] for more details.
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
}
