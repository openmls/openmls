use super::hpke::HpkePublicKey;
use tls_codec::VLBytes;

/// [`EncryptionKey`] contains an HPKE public key that allows the encryption of
/// [`EncryptionKey`] contains an HPKE public key that allows the encryption of
/// path secrets in MLS commits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InitKey {
    pub(super) key: HpkePublicKey,
}

impl InitKey {
    /// Return the internal [`HpkePublicKey`].
    pub fn key(&self) -> &HpkePublicKey {
        &self.key
    }

    /// Return the internal [`HpkePublicKey`] as a slice.
    pub fn as_slice(&self) -> &[u8] {
        self.key.0.as_slice()
    }
}

impl From<Vec<u8>> for InitKey {
    fn from(key: Vec<u8>) -> Self {
        Self {
            key: HpkePublicKey::from(key.into()),
        }
    }
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
