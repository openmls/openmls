use super::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

/// Metadata is an extension that keeps arbitrary application-specific metadata, in the form of a
/// byte sequence. The application is responsible for specifying a format and parsing the contents.
#[derive(
    PartialEq, Eq, Clone, Debug, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct Metadata {
    metadata: Vec<u8>,
}

impl Metadata {
    /// Create a new [`Metadata`] extension.
    pub fn new(metadata: Vec<u8>) -> Self {
        Self { metadata }
    }

    /// Get the metadata bytes.
    pub fn metadata(&self) -> &Vec<u8> {
        &self.metadata
    }
}
