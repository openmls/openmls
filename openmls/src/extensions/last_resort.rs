use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use super::{Deserialize, Serialize};

/// ```c
/// // draft-ietf-mls-extensions-1
/// struct {} LastResort;
/// ```
#[derive(
    PartialEq, Eq, Clone, Debug, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct LastResortExtension {}

impl LastResortExtension {
    /// Create a new `external_pub` extension.
    pub fn new() -> Self {
        Self {}
    }
}
