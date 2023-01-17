use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::key_store::{FromKeyStoreValue, OpenMlsKeyStore, ToKeyStoreValue};
use openmls_traits::types::{Ciphersuite, CryptoError, HpkeCiphertext, HpkeKeyPair};
use openmls_traits::OpenMlsCryptoProvider;
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

use crate::ciphersuite::{HpkePrivateKey, HpkePublicKey, Secret};
use crate::error::LibraryError;
use crate::versions::ProtocolVersion;

#[derive(
    Debug, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize, PartialEq, Eq,
)]
pub struct EncryptionKey {
    key: HpkePublicKey,
}

impl EncryptionKey {
    pub fn key(&self) -> &HpkePublicKey {
        &self.key
    }

    pub fn as_slice(&self) -> &[u8] {
        self.key.as_slice()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionPrivateKey {
    key: HpkePrivateKey,
}

impl From<HpkePrivateKey> for EncryptionPrivateKey {
    fn from(key: HpkePrivateKey) -> Self {
        Self { key }
    }
}

impl EncryptionPrivateKey {
    /// Decrypt a given `HpkeCiphertext` using this [`EncryptionPrivateKey`] and
    /// `group_context`.
    ///
    /// Returns the decrypted [`Secret`]. Returns an error if the decryption was
    /// unsuccessful.
    pub(crate) fn decrypt(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        version: ProtocolVersion,
        ciphertext: &HpkeCiphertext,
        group_context: &[u8],
    ) -> Result<Secret, CryptoError> {
        // ValSem203: Path secrets must decrypt correctly
        let secret_bytes = backend.crypto().hpke_open(
            ciphersuite.hpke_config(),
            ciphertext,
            self.key.as_slice(),
            group_context,
            &[],
        )?;
        Ok(Secret::from_slice(&secret_bytes, version, ciphersuite))
    }
}

impl From<HpkePublicKey> for EncryptionKey {
    fn from(key: HpkePublicKey) -> Self {
        Self { key }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionKeyPair {
    public_key: EncryptionKey,
    private_key: EncryptionPrivateKey,
}

const ENCRYPTION_KEY_LABEL: &[u8; 19] = b"leaf_encryption_key";

impl EncryptionKeyPair {
    /// Write the [`EncryptionKeyPair`] to the key store of the `backend`. This
    /// function is meant to store standalone keypairs, not ones that are
    /// already in use with an MLS group.
    ///
    /// Returns a key store error if access to the key store fails.
    pub fn write_to_key_store<KeyStore: OpenMlsKeyStore>(
        &self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
    ) -> Result<(), KeyStore::Error> {
        let mut key_store_index = ENCRYPTION_KEY_LABEL.to_vec();
        key_store_index.extend_from_slice(self.public_key().as_slice());
        backend.key_store().store(&key_store_index, self)
    }

    /// Read the [`EncryptionKeyPair`] from the key store of the `backend`. This
    /// function is meant to read standalone keypairs, not ones that are
    /// already in use with an MLS group.
    ///
    /// Returns `None` if the keypair cannot be read from the store.
    pub fn read_from_key_store(
        backend: &impl OpenMlsCryptoProvider,
        encryption_key: &EncryptionKey,
    ) -> Option<EncryptionKeyPair> {
        let mut key_store_index = ENCRYPTION_KEY_LABEL.to_vec();
        key_store_index.extend_from_slice(encryption_key.as_slice());
        backend.key_store().read(&key_store_index)
    }

    /// Delete the [`EncryptionKeyPair`] from the key store of the `backend`.
    /// This function is meant to delete standalone keypairs, not ones that are
    /// already in use with an MLS group.
    ///
    /// Returns a key store error if access to the key store fails.
    pub fn delete_from_key_store<KeyStore: OpenMlsKeyStore>(
        &self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
    ) -> Result<(), KeyStore::Error> {
        let mut key_store_index = ENCRYPTION_KEY_LABEL.to_vec();
        key_store_index.extend_from_slice(self.public_key().as_slice());
        backend.key_store().delete(&key_store_index)
    }

    pub fn public_key(&self) -> &EncryptionKey {
        &self.public_key
    }

    pub fn private_key(&self) -> &EncryptionPrivateKey {
        &self.private_key
    }

    pub(crate) fn derive(
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        ikm: Secret,
    ) -> Self {
        backend
            .crypto()
            .derive_hpke_keypair(ciphersuite.hpke_config(), ikm.as_slice())
            .into()
    }
}

impl From<(HpkePublicKey, HpkePrivateKey)> for EncryptionKeyPair {
    fn from((public_key, private_key): (HpkePublicKey, HpkePrivateKey)) -> Self {
        Self {
            public_key: public_key.into(),
            private_key: private_key.into(),
        }
    }
}

impl From<HpkeKeyPair> for EncryptionKeyPair {
    fn from(hpke_keypair: HpkeKeyPair) -> Self {
        let public_bytes: VLBytes = hpke_keypair.public.into();
        let private_bytes: VLBytes = hpke_keypair.private.into();
        Self {
            public_key: public_bytes.into(),
            private_key: private_bytes.into(),
        }
    }
}

impl From<(EncryptionKey, EncryptionPrivateKey)> for EncryptionKeyPair {
    fn from((public_key, private_key): (EncryptionKey, EncryptionPrivateKey)) -> Self {
        Self {
            public_key,
            private_key,
        }
    }
}

impl ToKeyStoreValue for EncryptionKeyPair {
    type Error = LibraryError;

    fn to_key_store_value(&self) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(self)
            .map_err(|_| LibraryError::custom("Error serializing encryption key."))
    }
}

impl FromKeyStoreValue for EncryptionKeyPair {
    type Error = LibraryError;

    fn from_key_store_value(ksv: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(ksv).map_err(|_| LibraryError::custom("Invalid encryption key."))
    }
}
