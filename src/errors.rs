//! # Errors
//!
//! ## ConfigError
//! This error type is thrown when the configuration is invalid or not supported
//! by openmls.
//!

#[derive(Debug, PartialEq)]
pub enum ConfigError {
    InvalidConfig,
    UnsupportedMlsVersion,
    UnsupportedCiphersuite,
    ExpiredLifetimeExtension,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    DecodingError,
    UnsupportedCiphersuite,
    CryptoLibraryError,
}
