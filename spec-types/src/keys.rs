use crate::hpke::HpkePublicKey;
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

/// [`EncryptionKey`] contains an HPKE public key that allows the encryption of
/// [`EncryptionKey`] contains an HPKE public key that allows the encryption of
/// path secrets in MLS commits.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    TlsDeserializeBytes,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
pub struct InitKey {
    pub key: HpkePublicKey,
}

/// path secrets in MLS commits.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    TlsDeserializeBytes,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
pub struct EncryptionKey {
    pub key: HpkePublicKey,
}

/// A public signature key.
#[derive(
    Eq,
    PartialEq,
    Hash,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserializeBytes,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
pub struct SignaturePublicKey {
    pub value: VLBytes,
}
