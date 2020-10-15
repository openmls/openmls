//! # Errors
//!
//! ## ConfigError
//! This error type is thrown when the configuration is invalid or not supported
//! by maelstrom.
//!

#[derive(Debug, PartialEq)]
pub enum ConfigError {
    InvalidConfig,
    UnsupportedMlsVersion,
    UnsupportedCiphersuite,
    ExpiredLifetimeExtension,
}
