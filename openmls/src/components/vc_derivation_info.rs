use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{Ciphersuite, HpkePrivateKey},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tls_codec::{DeserializeBytes, Serialize as _, TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::{
    binary_tree::LeafNodeIndex, ciphersuite::Secret, group::MlsGroup, key_packages::InitKey,
    messages::PathSecret, storage::StorageProvider, treesync::EncryptionKey,
};

/// Component ID under which the virtual-clients derivation info is carried in
/// the leaf node's `app_data_dictionary` extension.
///
/// `0xFFFF` is a placeholder until the IETF draft is assigned an IANA value.
pub const VC_COMPONENT_ID: u16 = 0xFFFF;

const EPOCH_ID_LABEL: &str = "Epoch ID";
const BASE_SECRET_LABEL: &str = "Base Secret";
const ENCRYPTION_KEY_LABEL: &str = "Encryption Key";
const INIT_KEY_LABEL: &str = "Init Key";
const PATH_GENERATION_LABEL: &str = "Path Generation";
const OPERATION_SECRET_LABEL: &str = "operation secret";

/// Errors that can occur while processing virtual-clients derivation info.
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum VirtualClientsError {
    /// The leaf node in the path doesn't carry an `app_data_dictionary`
    /// extension.
    #[error("App data dictionary extension is missing from the leaf node.")]
    MissingAppDataDictionary,
    /// The `app_data_dictionary` extension doesn't contain a virtual-clients
    /// entry.
    #[error("Virtual-clients derivation info is missing from the app data dictionary.")]
    MissingDerivationInfo,
    /// The derivation-info bytes failed to deserialize.
    #[error("Failed to deserialize derivation info.")]
    DerivationInfoMalformed,
    /// AEAD decryption of the encrypted epoch info failed (wrong key,
    /// tampered ciphertext, or mismatched AAD).
    #[error("Failed to decrypt epoch info.")]
    EpochInfoDecryptionFailed,
    /// The serialized epoch info failed to deserialize after decryption.
    #[error("Failed to deserialize epoch info.")]
    EpochInfoMalformed,
    /// The leaf index in the decrypted epoch info doesn't match the local
    /// own-leaf index.
    #[error("Epoch info leaf index does not match own leaf index.")]
    LeafIndexMismatch,
    /// No virtual-clients epoch encryption key was stored for this epoch.
    #[error("No virtual-clients epoch encryption key for this epoch.")]
    MissingEpochEncryptionKey,
    /// No virtual-clients epoch base secret was stored for this epoch.
    #[error("No virtual-clients epoch base secret for this epoch.")]
    MissingEpochBaseSecret,
    /// Loading a virtual-clients secret from the storage provider failed.
    #[error("Failed to load virtual-clients secret from storage: {0}")]
    StorageError(String),
    /// The leaf encryption key in the path does not match the key derived
    /// from the path secret.
    #[error("Leaf encryption key from path does not match the derived key.")]
    EncryptionKeyMismatch,
    /// Exporting the virtual-clients epoch secret from the group failed.
    #[error("Failed to export virtual-clients secret from group.")]
    SafeExportFailed,
    /// A cryptographic operation failed during virtual-clients processing.
    #[error("Cryptographic operation failed.")]
    CryptoError,
    /// Random byte generation failed.
    #[error("Random byte generation failed.")]
    RandError,
    /// Serializing a virtual-clients structure failed.
    #[error("Failed to serialize virtual-clients structure.")]
    SerializationError,
}

#[derive(Debug, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub(crate) struct DerivationInfo {
    epoch_id: EpochId,
    ciphertext: EncryptedEpochInfo,
}

impl DerivationInfo {
    pub(crate) fn epoch_id(&self) -> &EpochId {
        &self.epoch_id
    }

    pub(crate) fn decrypt(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        key: &EpochEncryptionKey,
    ) -> Result<EpochInfoTbe, VirtualClientsError> {
        self.ciphertext
            .decrypt(crypto, ciphersuite, key, &self.epoch_id)
    }
}

pub(crate) struct EmulatorEpochSecret(Secret);

impl EmulatorEpochSecret {
    /// Build the per-epoch emulator secret from the group's safe-export
    /// interface. The returned `Self` is the input to `derive_vc_secrets`,
    /// which produces the actual stored encryption key, base secret, and
    /// epoch id.
    pub(crate) fn derive(
        crypto: &impl OpenMlsCrypto,
        storage: &impl StorageProvider,
        group: &mut MlsGroup,
    ) -> Result<Self, VirtualClientsError> {
        let secret_bytes = group
            .safe_export_secret(crypto, storage, VC_COMPONENT_ID)
            .map_err(|_| VirtualClientsError::SafeExportFailed)?;
        Ok(Self(Secret::from_slice(&secret_bytes)))
    }

    pub(crate) fn derive_vc_secrets(
        self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<(EpochId, EpochBaseSecret, EpochEncryptionKey), VirtualClientsError> {
        let epoch_id = self
            .0
            .derive_secret(crypto, ciphersuite, EPOCH_ID_LABEL)
            .map_err(|_| VirtualClientsError::CryptoError)?;
        let base_secret = self
            .0
            .derive_secret(crypto, ciphersuite, BASE_SECRET_LABEL)
            .map_err(|_| VirtualClientsError::CryptoError)?;
        // The encryption key is used directly as an AEAD key, so derive it
        // to the AEAD key length (not the hash length); otherwise the AEAD
        // backend rejects it for ciphersuites where the AEAD key is shorter
        // than the hash output (e.g. AES-128-GCM under SHA-256).
        let encryption_key = self
            .0
            .kdf_expand_label(
                crypto,
                ciphersuite,
                ENCRYPTION_KEY_LABEL,
                &[],
                ciphersuite.aead_key_length(),
            )
            .map_err(|_| VirtualClientsError::CryptoError)?;
        Ok((
            EpochId(epoch_id.as_slice().to_vec()),
            EpochBaseSecret(base_secret),
            EpochEncryptionKey(encryption_key),
        ))
    }
}

#[derive(Debug, Serialize, Deserialize, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub(crate) struct EpochId(Vec<u8>);

#[derive(Serialize, Deserialize)]
pub(crate) struct EpochEncryptionKey(Secret);

#[derive(Serialize, Deserialize)]
pub(crate) struct EpochBaseSecret(Secret);

impl EpochBaseSecret {
    pub(crate) fn derive_operation_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<OperationSecret, VirtualClientsError> {
        // TODO: Replace this with a PPRF invocation.
        let operation_secret = self
            .0
            .derive_secret(crypto, ciphersuite, OPERATION_SECRET_LABEL)
            .map_err(|_| VirtualClientsError::CryptoError)?;
        Ok(OperationSecret(operation_secret))
    }
}

pub(crate) struct OperationSecret(Secret);

impl OperationSecret {
    pub(crate) fn derive_encryption_key_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<EncryptionKeySecret, VirtualClientsError> {
        let encryption_key_secret = self
            .0
            .derive_secret(crypto, ciphersuite, ENCRYPTION_KEY_LABEL)
            .map_err(|_| VirtualClientsError::CryptoError)?;
        Ok(EncryptionKeySecret(encryption_key_secret))
    }

    pub(crate) fn derive_init_key_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<InitKeySecret, VirtualClientsError> {
        let init_key_secret = self
            .0
            .derive_secret(crypto, ciphersuite, INIT_KEY_LABEL)
            .map_err(|_| VirtualClientsError::CryptoError)?;
        Ok(InitKeySecret(init_key_secret))
    }

    pub(crate) fn derive_path_generation_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<PathGenerationSecret, VirtualClientsError> {
        let path_generation_secret = self
            .0
            .derive_secret(crypto, ciphersuite, PATH_GENERATION_LABEL)
            .map_err(|_| VirtualClientsError::CryptoError)?;
        Ok(PathGenerationSecret(path_generation_secret))
    }
}

pub(crate) struct EncryptionKeySecret(Secret);

impl EncryptionKeySecret {
    pub(crate) fn generate_encryption_key_pair(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<(EncryptionKey, HpkePrivateKey), VirtualClientsError> {
        let hpke_config = ciphersuite.hpke_config();
        let key_pair = crypto
            .derive_hpke_keypair(hpke_config, self.0.as_slice())
            .map_err(|_| VirtualClientsError::CryptoError)?;
        Ok((EncryptionKey::from(key_pair.public), key_pair.private))
    }
}

pub(crate) struct InitKeySecret(Secret);

impl InitKeySecret {
    pub(crate) fn generate_init_key_pair(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<(InitKey, HpkePrivateKey), VirtualClientsError> {
        let hpke_config = ciphersuite.hpke_config();
        let key_pair = crypto
            .derive_hpke_keypair(hpke_config, self.0.as_slice())
            .map_err(|_| VirtualClientsError::CryptoError)?;
        Ok((InitKey::from(key_pair.public), key_pair.private))
    }
}

pub(crate) struct PathGenerationSecret(Secret);

impl From<PathGenerationSecret> for PathSecret {
    fn from(value: PathGenerationSecret) -> Self {
        value.0.into()
    }
}

#[derive(Debug, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub(crate) struct EncryptedEpochInfo {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl EncryptedEpochInfo {
    pub fn decrypt(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        key: &EpochEncryptionKey,
        epoch_id: &EpochId,
    ) -> Result<EpochInfoTbe, VirtualClientsError> {
        let plaintext = crypto
            .aead_decrypt(
                ciphersuite.aead_algorithm(),
                key.0.as_slice(),
                self.ciphertext.as_slice(),
                self.nonce.as_slice(),
                epoch_id.0.as_slice(),
            )
            .map_err(|_| VirtualClientsError::EpochInfoDecryptionFailed)?;
        EpochInfoTbe::tls_deserialize_exact_bytes(&plaintext)
            .map_err(|_| VirtualClientsError::EpochInfoMalformed)
    }
}

#[derive(Debug, PartialEq, Eq, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub(crate) struct EpochInfoTbe {
    pub leaf_index: LeafNodeIndex,
    pub random: Vec<u8>,
}

impl EpochInfoTbe {
    pub fn encrypt(
        &self,
        crypto: &impl OpenMlsCrypto,
        rand: &impl OpenMlsRand,
        ciphersuite: Ciphersuite,
        key: &EpochEncryptionKey,
        epoch_id: &EpochId,
    ) -> Result<EncryptedEpochInfo, VirtualClientsError> {
        let nonce = rand
            .random_vec(ciphersuite.aead_nonce_length())
            .map_err(|_| VirtualClientsError::RandError)?;
        let payload = self
            .tls_serialize_detached()
            .map_err(|_| VirtualClientsError::SerializationError)?;
        let ciphertext = crypto
            .aead_encrypt(
                ciphersuite.aead_algorithm(),
                key.0.as_slice(),
                payload.as_slice(),
                nonce.as_slice(),
                epoch_id.0.as_slice(),
            )
            .map_err(|_| VirtualClientsError::CryptoError)?;
        Ok(EncryptedEpochInfo { nonce, ciphertext })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::OpenMlsProvider;

    /// Round-trip an `EpochInfoTbe` through `encrypt` ↔ `decrypt`. Catches
    /// any disagreement between the two methods on the AAD/key/nonce layout
    /// and any silent regression in the AEAD wrapping.
    #[test]
    fn epoch_info_tbe_roundtrip() {
        let provider = OpenMlsRustCrypto::default();
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let key = EpochEncryptionKey(Secret::from_slice(
            &provider
                .rand()
                .random_vec(ciphersuite.aead_key_length())
                .expect("randomness"),
        ));
        let epoch_id = EpochId(
            provider
                .rand()
                .random_vec(16)
                .expect("randomness"),
        );
        let original = EpochInfoTbe {
            leaf_index: LeafNodeIndex::new(7),
            random: provider
                .rand()
                .random_vec(32)
                .expect("randomness"),
        };
        let encrypted = original
            .encrypt(provider.crypto(), provider.rand(), ciphersuite, &key, &epoch_id)
            .expect("encrypt");
        let decrypted = encrypted
            .decrypt(provider.crypto(), ciphersuite, &key, &epoch_id)
            .expect("decrypt");
        assert_eq!(original, decrypted);
    }
}
