use std::fmt::Debug;

use openmls_traits::{
    crypto::OpenMlsCrypto,
    key_store::{MlsEntity, MlsEntityId, OpenMlsKeyStore},
    types::{Ciphersuite, HpkeCiphertext, HpkeKeyPair},
    OpenMlsProvider,
};
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

use crate::{
    ciphersuite::{hpke, HpkePrivateKey, HpkePublicKey, Secret},
    error::LibraryError,
    group::config::CryptoConfig,
    versions::ProtocolVersion,
};

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

    /// Encrypt to this HPKE public key.
    pub(crate) fn encrypt(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<HpkeCiphertext, LibraryError> {
        hpke::encrypt_with_label(
            self.as_slice(),
            "UpdatePathNode",
            context,
            plaintext,
            ciphersuite,
            crypto,
        )
        .map_err(|_| LibraryError::custom("Encryption failed. A serialization issue really"))
    }
}

#[derive(
    Clone, Serialize, Deserialize, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct EncryptionPrivateKey {
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
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        version: ProtocolVersion,
        ciphertext: &HpkeCiphertext,
        group_context: &[u8],
    ) -> Result<Secret, hpke::Error> {
        // ValSem203: Path secrets must decrypt correctly
        hpke::decrypt_with_label(
            &self.key,
            "UpdatePathNode",
            group_context,
            ciphertext,
            ciphersuite,
            crypto,
        )
        .map(|secret_bytes| Secret::from_slice(&secret_bytes, version, ciphersuite))
    }
}

#[cfg(test)]
impl EncryptionPrivateKey {
    pub(crate) fn key(&self) -> &HpkePrivateKey {
        &self.key
    }
}

impl From<HpkePublicKey> for EncryptionKey {
    fn from(key: HpkePublicKey) -> Self {
        Self { key }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct EncryptionKeyPair {
    public_key: EncryptionKey,
    private_key: EncryptionPrivateKey,
    dummy: Vec<u8>, // some new field
}

/// Current version of the encryption key pair.
pub(crate) const ENCRYPTION_KEY_PAIR_VERSION: u16 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct EncryptionKeyPairv1 {
    public_key: EncryptionKey,
    private_key: EncryptionPrivateKey,
}

const ENCRYPTION_KEY_LABEL: &[u8; 19] = b"leaf_encryption_key";

impl EncryptionKeyPair {
    /// Write the [`EncryptionKeyPair`] to the key store of the `provider`. This
    /// function is meant to store standalone keypairs, not ones that are
    /// already in use with an MLS group.
    ///
    /// Returns a key store error if access to the key store fails.
    pub(crate) fn write_to_key_store<KeyStore: OpenMlsKeyStore>(
        &self,
        store: &KeyStore,
    ) -> Result<(), KeyStore::Error> {
        store.store(&self.public_key().to_bytes_with_prefix(), self)
    }

    /// Read the [`EncryptionKeyPair`] from the key store of the `provider`. This
    /// function is meant to read standalone keypairs, not ones that are
    /// already in use with an MLS group.
    ///
    /// Returns `None` if the keypair cannot be read from the store.
    pub(crate) fn read_from_key_store(
        store: &impl OpenMlsKeyStore,
        encryption_key: &EncryptionKey,
    ) -> Option<EncryptionKeyPair> {
        store.read(&encryption_key.to_bytes_with_prefix())
    }

    pub(crate) fn read_vec_from_key_store(
        store: &impl OpenMlsKeyStore,
        id: &[u8],
    ) -> Option<Vec<EncryptionKeyPair>> {
        store.read(id)
    }

    /// Delete the [`EncryptionKeyPair`] from the key store of the `provider`.
    /// This function is meant to delete standalone keypairs, not ones that are
    /// already in use with an MLS group.
    ///
    /// Returns a key store error if access to the key store fails.
    pub(crate) fn delete_from_key_store<KeyStore: OpenMlsKeyStore>(
        &self,
        store: &KeyStore,
    ) -> Result<(), KeyStore::Error> {
        store.delete::<ENCRYPTION_KEY_PAIR_VERSION, Self>(&self.public_key().to_bytes_with_prefix())
    }

    pub(crate) fn delete_vec_from_key_store<KeyStore: OpenMlsKeyStore>(
        store: &KeyStore,
        id: &[u8],
    ) -> Result<(), KeyStore::Error> {
        store.delete::<ENCRYPTION_KEY_PAIR_VERSION, Vec<Self>>(id)
    }

    pub(crate) fn public_key(&self) -> &EncryptionKey {
        &self.public_key
    }

    pub(crate) fn private_key(&self) -> &EncryptionPrivateKey {
        &self.private_key
    }

    pub(crate) fn random(
        provider: &impl OpenMlsProvider,
        config: CryptoConfig,
    ) -> Result<Self, LibraryError> {
        let ikm = Secret::random(config.ciphersuite, provider.rand(), config.version)
            .map_err(LibraryError::unexpected_crypto_error)?;
        Ok(provider
            .crypto()
            .derive_hpke_keypair(config.ciphersuite.hpke_config(), ikm.as_slice())
            .into())
    }
}

#[cfg(feature = "test-utils")]
pub mod test_utils {
    use super::*;

    pub fn read_keys_from_key_store(
        provider: &impl OpenMlsProvider,
        encryption_key: &EncryptionKey,
    ) -> HpkeKeyPair {
        let keys =
            EncryptionKeyPair::read_from_key_store(provider.key_store(), encryption_key).unwrap();

        HpkeKeyPair {
            private: keys.private_key.key,
            public: keys.public_key.key.as_slice().to_vec(),
        }
    }

    pub fn write_keys_from_key_store(provider: &impl OpenMlsProvider, encryption_key: HpkeKeyPair) {
        let keypair = EncryptionKeyPair::from(encryption_key);

        keypair.write_to_key_store(provider.key_store()).unwrap();
    }
}

#[cfg(test)]
impl EncryptionKeyPair {
    /// Build a key pair from raw bytes for testing.
    pub(crate) fn from_raw(public_key: Vec<u8>, private_key: Vec<u8>) -> Self {
        Self {
            public_key: EncryptionKey {
                key: public_key.into(),
            },
            private_key: EncryptionPrivateKey {
                key: private_key.into(),
            },
            dummy: vec![1, 2, 3],
        }
    }
}

impl From<(HpkePublicKey, HpkePrivateKey)> for EncryptionKeyPair {
    fn from((public_key, private_key): (HpkePublicKey, HpkePrivateKey)) -> Self {
        Self {
            public_key: public_key.into(),
            private_key: private_key.into(),
            dummy: vec![1, 2, 3],
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
            dummy: vec![1, 2, 3],
        }
    }
}

impl From<(EncryptionKey, EncryptionPrivateKey)> for EncryptionKeyPair {
    fn from((public_key, private_key): (EncryptionKey, EncryptionPrivateKey)) -> Self {
        Self {
            public_key,
            private_key,
            dummy: vec![1, 2, 3],
        }
    }
}

impl MlsEntity<ENCRYPTION_KEY_PAIR_VERSION> for EncryptionKeyPair {
    const ID: MlsEntityId = MlsEntityId::EncryptionKeyPair;
}

impl MlsEntity<1> for EncryptionKeyPairv1 {
    const ID: MlsEntityId = MlsEntityId::EncryptionKeyPair;
}

impl From<EncryptionKeyPairv1> for EncryptionKeyPair {
    fn from(value: EncryptionKeyPairv1) -> Self {
        Self {
            public_key: value.public_key,
            private_key: value.private_key,
            dummy: vec![1, 2, 3],
        }
    }
}

#[cfg(test)]
mod tests {
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::{types::Ciphersuite, OpenMlsProvider};
    use rstest::rstest;
    use rstest_reuse::{self, *};

    use crate::{group::config::CryptoConfig, versions::ProtocolVersion};

    use super::EncryptionKeyPair;

    #[apply(ciphersuites_and_providers)]
    fn persistence(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
        let config = CryptoConfig {
            ciphersuite,
            version: ProtocolVersion::Mls10,
        };

        // Generate a new key pair
        let kp = EncryptionKeyPair::random(provider, config).unwrap();

        // Store it
        kp.write_to_key_store(provider.key_store()).unwrap();

        // Read it again
        let read_kp =
            EncryptionKeyPair::read_from_key_store(provider.key_store(), &kp.public_key).unwrap();

        // Ensure it's the correct one
        assert_eq!(kp, read_kp);

        // Delete it
        kp.delete_from_key_store(provider.key_store()).unwrap();

        // It should be gone now
        let e = EncryptionKeyPair::read_from_key_store(provider.key_store(), &kp.public_key);
        assert!(e.is_none());
    }
}
