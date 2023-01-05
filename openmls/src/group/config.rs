//! # Group Configurations
//!
//! This modules holds helper structs to group together configurations and
//! parameters.

use openmls_traits::types::Ciphersuite;
use serde::{Deserialize, Serialize};

use crate::versions::ProtocolVersion;

/// A config struct for commonly used values when performing cryptographic
/// operations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            ciphersuite: Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            version: ProtocolVersion::default(),
        }
    }
}
