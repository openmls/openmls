use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use super::{Deserialize, Serialize};

/// ```c
/// // draft-ietf-mls-extensions-03
/// struct {} LastResort;
/// ```
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
    Default,
)]
pub struct LastResortExtension {}

impl LastResortExtension {
    /// Create a new `last_resort` extension.
    pub fn new() -> Self {
        Self::default()
    }
}
