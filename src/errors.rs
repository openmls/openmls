//! # Errors
//!
//! ## ConfigError
//! This error type is thrown when the configuration is invalid or not supported
//! by OpenMLS.

#[derive(Debug, PartialEq)]
pub enum ConfigError {
    InvalidConfig,
    UnsupportedMlsVersion,
    UnsupportedCiphersuite,
    ExpiredLifetimeExtension,
    DuplicateExtension,
    InvalidCapabilitiesExtension,
    NoCiphersuitesSupplied,
    DecodingError,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    DecodingError,
    UnsupportedCiphersuite,
    CryptoLibraryError,
}
