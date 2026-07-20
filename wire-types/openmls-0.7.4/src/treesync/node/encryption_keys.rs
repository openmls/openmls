use std::fmt::Debug;

#[cfg(feature = "migration-export")]
use openmls_traits::storage::{StorageProvider as StorageProviderTrait, CURRENT_VERSION};
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::ciphersuite::{HpkePrivateKey, HpkePublicKey};

#[cfg(feature = "migration-export")]
use crate::storage::{OpenMlsProvider, StorageProvider};

/// [`EncryptionKey`] contains an HPKE public key that allows the encryption of
/// path secrets in MLS commits.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
    PartialEq,
    Eq,
    Hash,
)]
pub struct EncryptionKey {
    key: HpkePublicKey,
}

impl From<Vec<u8>> for EncryptionKey {
    fn from(key: Vec<u8>) -> Self {
        Self { key: key.into() }
    }
}

#[derive(
    Clone, Serialize, Deserialize, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
)]
pub struct EncryptionPrivateKey {
    key: HpkePrivateKey,
}

impl Debug for EncryptionPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ds = f.debug_struct("EncryptionPrivateKey");

        #[cfg(feature = "crypto-debug")]
        ds.field("key", &self.key);
        #[cfg(not(feature = "crypto-debug"))]
        ds.field("key", &"***");

        ds.finish()
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
)]
pub(crate) struct EncryptionKeyPair {
    public_key: EncryptionKey,
    private_key: EncryptionPrivateKey,
}

#[cfg(feature = "migration-export")]
impl EncryptionKeyPair {
    /// Write the [`EncryptionKeyPair`] to the store of the `provider`.
    ///
    /// This must only be used for encryption key pairs that are generated for
    /// update leaf nodes. All other encryption key pairs are stored as part
    /// of the key package or the epoch encryption key pairs.
    pub(crate) fn write<Storage: StorageProvider>(
        &self,
        store: &Storage,
    ) -> Result<(), Storage::Error> {
        store.write_encryption_key_pair(self.public_key(), self)
    }

    /// Read the [`EncryptionKeyPair`] from the key store of the `provider`. This
    /// function is meant to read standalone keypairs, not ones that are
    /// already in use with an MLS group.
    ///
    /// This must only be used for encryption key pairs that are generated for
    /// update leaf nodes. All other encryption key pairs are stored as part
    /// of the key package or the epoch encryption key pairs.
    ///
    /// Returns `None` if the keypair cannot be read from the store.
    pub(crate) fn read(
        provider: &impl OpenMlsProvider,
        encryption_key: &EncryptionKey,
    ) -> Option<EncryptionKeyPair> {
        provider
            .storage()
            .encryption_key_pair(encryption_key)
            .ok()
            .flatten()
    }

    /// Delete the [`EncryptionKeyPair`] from the store of the `provider`.
    ///
    /// This must only be used for encryption key pairs that are generated for
    /// update leaf nodes. All other encryption key pairs are stored as part
    /// of the key package or the epoch encryption key pairs.
    pub(crate) fn delete<Storage: StorageProviderTrait<CURRENT_VERSION>>(
        &self,
        store: &Storage,
    ) -> Result<(), Storage::Error> {
        store.delete_encryption_key_pair(self.public_key())
    }

    pub(crate) fn public_key(&self) -> &EncryptionKey {
        &self.public_key
    }

    pub(crate) fn private_key(&self) -> &EncryptionPrivateKey {
        &self.private_key
    }
}
