//! # Group Configurations
//!
//! This modules holds helper structs to group together configurations and
//! parameters.

use openmls_traits::types::Ciphersuite;

use crate::versions::ProtocolVersion;

/// A config struct for commonly used values when performing cryptographic
/// operations.
#[derive(Debug, Clone, Copy)]
pub struct CryptoConfig {
    /// The [`Ciphersuite`] used.
    pub ciphersuite: Ciphersuite,

    /// The MLS [`ProtocolVersion`] used.
    pub version: ProtocolVersion,
}

impl CryptoConfig {
    /// Create a new crypto config with the given ciphersuite and the default
    /// protocol version.
    pub fn with_default_version(ciphersuite: Ciphersuite) -> Self {
        Self {
            ciphersuite,
            version: ProtocolVersion::default(),
        }
    }
}
