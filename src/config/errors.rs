//!# Config errors
//!
//! A `ConfigError` is thrown when either the configuration itself is invalid or
//! inconsistent, or if an MLS configuration is being used that is not supported.
use std::error::Error;

#[derive(Debug, PartialEq)]
#[repr(u16)]
pub enum ConfigError {
    /// Invalid configuration.
    InvalidConfig = 0,

    /// MLS version is not supported by this configuration.
    UnsupportedMlsVersion = 1,

    /// Ciphersuite is not supported by this configuration.
    UnsupportedCiphersuite = 2,

    /// Signature scheme is not supported by this configuration.
    UnsupportedSignatureScheme = 3,
}

implement_enum_display!(ConfigError);

impl Error for ConfigError {
    fn description(&self) -> &str {
        match self {
            Self::InvalidConfig => "The configuration is invalid.",
            Self::UnsupportedMlsVersion => "The requested MLS version is not supported by OpenMLS.",
            Self::UnsupportedCiphersuite => {
                "The requested ciphersuite is not supported by OpenMLS."
            }
            Self::UnsupportedSignatureScheme => {
                "The requested signature scheme is not supported by OpenMLS."
            }
        }
    }
}
