use crate::hpke::HpkePublicKey;
use crate::VLBytes;
use serde::{Deserialize, Serialize};

/// [`EncryptionKey`] contains an HPKE public key that allows the encryption of
/// [`EncryptionKey`] contains an HPKE public key that allows the encryption of
/// path secrets in MLS commits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct InitKey {
    pub key: HpkePublicKey,
}

/// path secrets in MLS commits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EncryptionKey {
    pub key: HpkePublicKey,
}

/// A public signature key.
#[derive(Eq, PartialEq, Hash, Debug, Clone, Serialize, Deserialize)]
pub struct SignaturePublicKey {
    pub value: VLBytes,
}
