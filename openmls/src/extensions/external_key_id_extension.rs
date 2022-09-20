use tls_codec::{TlsByteVecU16, TlsDeserialize, TlsSerialize, TlsSize};

use super::{Deserialize, Serialize};

/// # External KeyPackage Identifiers
///
/// Within MLS, a KeyPackage is identified by its hash ([`KeyPackageRef`](`crate::ciphersuite::hash_ref::KeyPackageRef`)).
/// The external key id extension allows applications to add an explicit,
/// application-defined identifier to a KeyPackage.
///
/// A byte vector of length at most 2^16-1.
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Default,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsSize,
)]
pub struct ExternalKeyIdExtension {
    key_id: TlsByteVecU16,
}

impl ExternalKeyIdExtension {
    /// Create a new key identifier extension from a byte slice.
    pub fn new(id: &[u8]) -> Self {
        Self { key_id: id.into() }
    }

    /// Get the value of the key id as byte slice.
    pub fn as_slice(&self) -> &[u8] {
        self.key_id.as_slice()
    }
}
