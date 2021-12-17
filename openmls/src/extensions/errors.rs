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

use crate::config::ConfigError;
use crate::error::ErrorString;

use tls_codec::Error as TlsCodecError;

implement_error! {
    pub enum ExtensionError {
        Simple {
            DuplicateRatchetTreeExtension =
                "Found a duplicate ratchet tree extension.",
            LibraryError = "An unrecoverable error has occurred due to a bug in the implementation.",
        }
        Complex {
            InvalidExtensionType(ErrorString) =
                "Invalid extension type error.",
            Capabilities(CapabilitiesExtensionError) =
                "Capabilities extension error. See `CapabilitiesExtensionError` for details.",
            Lifetime(LifetimeExtensionError) =
                "Lifetime extension error. See `LifetimeExtensionError` for details.",
            KeyPackageId(KeyPackageIdError) =
                "Key package ID extension error. See `KeyPackageIdError` for details.",
            ParentHash(ParentHashError) =
                "Parent hash extension error. See `ParentHashError` for details.",
            RatchetTree(RatchetTreeError) =
                "Ratchet tree extension error. See `RatchetTreeError` for details.",
            CodecError(TlsCodecError) =
                "Error decoding or encoding an extension.",
            ConfigError(ConfigError) =
                "Configuration error. See `ConfigError` for details.",
            InvalidExtension(InvalidExtensionError) =
                "The extension is malformed. See [`InvalidExtensionError`](`InvalidExtensionError`) for details.",
        }
    }
}

implement_error! {
    pub enum LifetimeExtensionError {
        Invalid = "Invalid lifetime extensions.",
        Expired = "Lifetime extension is expired.",
    }
}

implement_error! {
    pub enum CapabilitiesExtensionError {
        Invalid = "Invalid capabilities extensions.",
        EmptyVersionsField = "Capabilities extension is missing a version field.",
        UnsupportedCiphersuite = "Capabilities contains only unsupported ciphersuites.",
    }
}

implement_error! {
    pub enum KeyPackageIdError {
        Invalid = "Invalid key package ID extensions.",
    }
}

implement_error! {
    pub enum ParentHashError {
        Invalid = "Invalid parent hash extensions.",
    }
}

implement_error! {
    pub enum RatchetTreeError {
        Invalid = "Invalid ratchet tree extensions.",
    }
}

implement_error! {
    pub enum InvalidExtensionError {
        Duplicate = "The provided extension list contains duplicate extensions.",
    }
}
