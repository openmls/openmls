//! # Group Configurations
//!
//! This modules holds helper structs to group together configurations and
//! parameters.

use openmls_traits::types::Ciphersuite;

use crate::versions::ProtocolVersion;

/// A config struct for commonly used values when performing cryptographic
/// operations.
pub struct CryptoConfig {
    /// The [`Ciphersuite`] used.
    pub ciphersuite: Ciphersuite,

    /// The MLS [`ProtocolVersion`] used.
    pub version: ProtocolVersion,
}
