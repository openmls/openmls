use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

use super::{Deserialize, Serialize};

/// # Application Identifiers
///
/// The application id extension allows applications to add an explicit,
/// application-defined identifier to a [`LeafNode`].
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct ApplicationIdExtension {
    key_id: VLBytes,
}

impl ApplicationIdExtension {
    /// Create a new key identifier extension from a byte slice.
    pub fn new(id: &[u8]) -> Self {
        Self { key_id: id.into() }
    }

    /// Get the value of the key id as byte slice.
    pub fn as_slice(&self) -> &[u8] {
        self.key_id.as_slice()
    }
}
