//! # KeyPackage Identifiers
//!
//! Within MLS, a KeyPackage is identified by its hash (see, e.g., Section
//! 11.2.1). The key_id extension allows applications to add an explicit,
//! application-defined identifier to a KeyPackage.
//!
//! ```text
//! opaque external_key_id<0..2^16-1>;
//! ```

use tls_codec::{TlsByteVecU16, TlsDeserialize, TlsSerialize, TlsSize};

use super::{Deserialize, Serialize};

/// External key ID extension.
#[derive(
    PartialEq, Clone, Debug, Default, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
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
