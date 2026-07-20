use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use super::{Deserialize, Serialize};
use crate::ciphersuite::HpkePublicKey;

/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///     HPKEPublicKey external_pub;
/// } ExternalPub;
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
)]
pub struct ExternalPubExtension {
    external_pub: HpkePublicKey,
}
