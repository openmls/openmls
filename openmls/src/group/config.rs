use openmls_traits::types::Ciphersuite;

use crate::versions::ProtocolVersion;

/// A config struct for commonly used values when performing cryptographic
/// operations.
pub struct CryptoConfig {
    pub ciphersuite: Ciphersuite,
    pub version: ProtocolVersion,
}
