use super::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(
    PartialEq, Eq, Clone, Debug, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct Metadata {
    metadata: Vec<u8>,
}

impl Metadata {
    pub fn new(metadata: Vec<u8>) -> Self {
        Self { metadata }
    }

    pub fn metadata(&self) -> &Vec<u8> {
        &self.metadata
    }
}
