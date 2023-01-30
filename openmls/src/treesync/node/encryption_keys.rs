use openmls_traits::{
    crypto::OpenMlsCrypto,
    key_store::{MlsEntity, MlsEntityId, OpenMlsKeyStore},
    types::{Ciphersuite, CryptoError, HpkeCiphertext, HpkeKeyPair},
    OpenMlsCryptoProvider,
};
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

use crate::ciphersuite::{HpkePrivateKey, HpkePublicKey, Secret};
use crate::error::LibraryError;
use crate::group::config::CryptoConfig;
use crate::versions::ProtocolVersion;

/// [`EncryptionKey`] contains an HPKE public key that allows the encryption of
/// path secrets in MLS commits.
#[derive(
    Debug, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize, PartialEq, Eq,
)]
pub(crate) struct EncryptionKey {
    key: HpkePublicKey,
}

impl EncryptionKey {
    /// Return the internal [`HpkePublicKey`].
    pub(crate) fn key(&self) -> &HpkePublicKey {
        &self.key
    }

    /// Return the internal [`HpkePublicKey`] as slice.
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.key.as_slice()
    }

    /// Helper function to prefix the given (serialized) [`EncryptionKey`] with
    /// the `ENCRYPTION_KEY_LABEL`.
    ///
    /// Returns the resulting bytes.
    fn to_bytes_with_prefix(&self) -> Vec<u8> {
        let mut key_store_index = ENCRYPTION_KEY_LABEL.to_vec();
        key_store_index.extend_from_slice(self.as_slice());
        key_store_index
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EncryptionPrivateKey {
    key: HpkePrivateKey,
}

impl From<Vec<u8>> for EncryptionPrivateKey {
    fn from(key: Vec<u8>) -> Self {
        Self { key: key.into() }
    }
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
pub(crate) struct EncryptionKeyPair {
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
    pub(crate) fn write_to_key_store<KeyStore: OpenMlsKeyStore>(
        &self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
    ) -> Result<(), KeyStore::Error> {
        backend
            .key_store()
            .store(&self.public_key().to_bytes_with_prefix(), self)
    }

    /// Read the [`EncryptionKeyPair`] from the key store of the `backend`. This
    /// function is meant to read standalone keypairs, not ones that are
    /// already in use with an MLS group.
    ///
    /// Returns `None` if the keypair cannot be read from the store.
    pub(crate) fn read_from_key_store(
        backend: &impl OpenMlsCryptoProvider,
        encryption_key: &EncryptionKey,
    ) -> Option<EncryptionKeyPair> {
        backend
            .key_store()
            .read(&encryption_key.to_bytes_with_prefix())
    }

    /// Delete the [`EncryptionKeyPair`] from the key store of the `backend`.
    /// This function is meant to delete standalone keypairs, not ones that are
    /// already in use with an MLS group.
    ///
    /// Returns a key store error if access to the key store fails.
    pub(crate) fn delete_from_key_store<KeyStore: OpenMlsKeyStore>(
        &self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
    ) -> Result<(), KeyStore::Error> {
        backend
            .key_store()
            .delete::<Self>(&self.public_key().to_bytes_with_prefix())
    }

    pub(crate) fn public_key(&self) -> &EncryptionKey {
        &self.public_key
    }

    pub(crate) fn private_key(&self) -> &EncryptionPrivateKey {
        &self.private_key
    }

    pub(crate) fn random(
        backend: &impl OpenMlsCryptoProvider,
        config: CryptoConfig,
    ) -> Result<Self, LibraryError> {
        let ikm = Secret::random(config.ciphersuite, backend, config.version)
            .map_err(LibraryError::unexpected_crypto_error)?;
        Ok(backend
            .crypto()
            .derive_hpke_keypair(config.ciphersuite.hpke_config(), ikm.as_slice())
            .into())
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
        let private_bytes = hpke_keypair.private;
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

impl MlsEntity for EncryptionKeyPair {
    const ID: MlsEntityId = MlsEntityId::SignatureKeyPair;
}
