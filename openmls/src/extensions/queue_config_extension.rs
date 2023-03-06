use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(
    Debug, Clone, PartialEq, Serialize, Deserialize, TlsSerialize, TlsSize, TlsDeserialize,
)]
pub struct QueueConfigExtension {
    bytes: Vec<u8>,
}

impl QueueConfigExtension {
    pub fn payload(&self) -> &[u8] {
        &self.bytes
    }
}
