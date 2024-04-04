use super::hpke::HpkePublicKey;
use serde::{Deserialize, Serialize};
use tls_codec::VLBytes;

/// [`EncryptionKey`] contains an HPKE public key that allows the encryption of
/// [`EncryptionKey`] contains an HPKE public key that allows the encryption of
/// path secrets in MLS commits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InitKey {
    pub(super) key: HpkePublicKey,
}

/// path secrets in MLS commits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EncryptionKey {
    pub(super) key: HpkePublicKey,
}

/// A public signature key.
#[derive(Eq, PartialEq, Hash, Debug, Clone)]
pub struct SignaturePublicKey {
    pub(super) value: VLBytes,
}
