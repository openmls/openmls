use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::{ciphersuite::SignaturePublicKey, credentials::Credential};

/// ExternalSender
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///   SignaturePublicKey signature_key;
///   Credential credential;
/// } ExternalSender;
/// ```
#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct ExternalSender {
    signature_key: SignaturePublicKey,
    credential: Credential,
}

/// ExternalSender (extension data)
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// ExternalSender external_senders<V>;
/// ```
pub type ExternalSendersExtension = Vec<ExternalSender>;
/// Identifies an external sender in the `ExternalSendersExtension`.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct SenderExtensionIndex(u32);
