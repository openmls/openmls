use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use super::{Deserialize, Serialize};
use crate::prelude::HpkePublicKey;

/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///     HPKEPublicKey external_pub;
/// } ExternalPub;
/// ```
#[derive(
    PartialEq, Eq, Clone, Debug, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct ExternalPubExtension {
    external_pub: HpkePublicKey,
}

impl ExternalPubExtension {
    /// Create a new `external_pub` extension.
    pub fn new(external_pub: HpkePublicKey) -> Self {
        Self { external_pub }
    }

    /// Get a reference to the HPKE public key.
    pub fn external_pub(&self) -> &HpkePublicKey {
        &self.external_pub
    }
}
