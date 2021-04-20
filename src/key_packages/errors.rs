//! # Key Package errors
//!
//! `KeyPackageError` are thrown on errors handling `KeyPackage`s and
//! `KeyPackageBundle`s.

use crate::{codec::CodecError, config::ConfigError, extensions::ExtensionError};

implement_error! {
    pub enum KeyPackageError {
        Simple {
            UnsupportedCiphersuite = "The requested ciphersuite is not supported.",
            UnknownConfigError = "An unknown configuration error occurred.",
            MandatoryExtensionsMissing = "A mandatory extension is missing in the key package.",
            InvalidLifetimeExtension = "The lifetime extension of the key package is not valid.",
            InvalidSignature = "The key package signature is not valid.",
            LibraryError = "An unknown OpenMLS library error occurred.",
            DuplicateExtension = "Duplicate extensions are not allowed.",
            NoCiphersuitesSupplied = "Creating a new key package requires at least one ciphersuite.",
            CiphersuiteMismatch = "The list of ciphersuites is not consistent with the capabilities extension.",
            CiphersuiteSignatureSchemeMismatch = "The ciphersuite does not match the signature scheme.",
        }
        Complex {
            ExtensionError(ExtensionError) =
                "See [`ExtensionError`](crate::extensions::ExtensionError`) for details.",
            ConfigError(ConfigError) =
                "See [`ConfigError`](crate::config::ConfigError`) for details.",
            CodecError(CodecError) =
                "See [`CodecError`](crate::codec::CodecError`) for details.",
        }
    }
}
