use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{Ciphersuite, CryptoError, HpkePrivateKey},
};
use tls_codec::{DeserializeBytes, Serialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::{
    binary_tree::LeafNodeIndex, ciphersuite::Secret, group::MlsGroup, key_packages::InitKey,
    messages::PathSecret, storage::StorageProvider, treesync::EncryptionKey,
};

pub const VC_COMPONENT_ID: u16 = 0xFFFF;

const EPOCH_ID_LABEL: &str = "Epoch ID";
const BASE_SECRET_LABEL: &str = "Base Secret";
const ENCRYPTION_KEY_LABEL: &str = "Encryption Key";
const INIT_KEY_LABEL: &str = "Init Key";
const PATH_GENERATION_LABEL: &str = "Path Generation";
const SIGNATURE_KEY_LABEL: &str = "Signature Key";

#[derive(Debug, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub(crate) struct DerivationInfo {
    epoch_id: EpochId,
    ciphertext: EncryptedEpochInfo,
}

impl DerivationInfo {
    pub(crate) fn decrypt(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        key: &EpochEncryptionKey,
    ) -> EpochInfoTbe {
        self.ciphertext
            .decrypt(crypto, ciphersuite, key, &self.epoch_id)
    }
}

pub(crate) struct EmulatorEpochSecret(Secret);

impl EmulatorEpochSecret {
    pub(crate) fn derive(
        crypto: &impl OpenMlsCrypto,
        storage: &impl StorageProvider,
        group: &mut MlsGroup,
    ) -> EpochEncryptionKey {
        let secret_bytes = group
            .safe_export_secret(crypto, storage, VC_COMPONENT_ID)
            .unwrap();

        EpochEncryptionKey(Secret::from_slice(&secret_bytes))
    }

    pub(crate) fn derive_vc_secrets(
        self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> (EpochId, EpochBaseSecret, EpochEncryptionKey) {
        let epoch_id = self
            .0
            .derive_secret(crypto, ciphersuite, EPOCH_ID_LABEL)
            .unwrap();
        let base_secret = self
            .0
            .derive_secret(crypto, ciphersuite, BASE_SECRET_LABEL)
            .unwrap();
        let encryption_key = self
            .0
            .derive_secret(crypto, ciphersuite, ENCRYPTION_KEY_LABEL)
            .unwrap();
        (
            EpochId(epoch_id.as_slice().to_vec()),
            EpochBaseSecret(base_secret),
            EpochEncryptionKey(encryption_key),
        )
    }
}

#[derive(Debug, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub(crate) struct EpochId(Vec<u8>);

pub(crate) struct EpochEncryptionKey(Secret);

pub(crate) struct EpochBaseSecret(Secret);

impl EpochBaseSecret {
    pub(crate) fn derive_operation_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> OperationSecret {
        // TODO: Replace this with a PPRF invocation
        let operation_secret = self
            .0
            .derive_secret(crypto, ciphersuite, "operation secret")
            .unwrap();
        OperationSecret(operation_secret)
    }
}

pub(crate) struct OperationSecret(Secret);

impl OperationSecret {
    pub(crate) fn derive_signature_key_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> SignatureKeySecret {
        let signature_key_secret = self
            .0
            .derive_secret(crypto, ciphersuite, SIGNATURE_KEY_LABEL)
            .unwrap();
        SignatureKeySecret(signature_key_secret)
    }

    pub(crate) fn derive_encryption_key_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> EncryptionKeySecret {
        let encryption_key_secret = self
            .0
            .derive_secret(crypto, ciphersuite, ENCRYPTION_KEY_LABEL)
            .unwrap();
        EncryptionKeySecret(encryption_key_secret)
    }

    pub(crate) fn derive_init_key_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> InitKeySecret {
        let init_key_secret = self
            .0
            .derive_secret(crypto, ciphersuite, INIT_KEY_LABEL)
            .unwrap();
        InitKeySecret(init_key_secret)
    }

    pub(crate) fn derive_path_generation_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> PathGenerationSecret {
        let path_generation_secret = self
            .0
            .derive_secret(crypto, ciphersuite, PATH_GENERATION_LABEL)
            .unwrap();
        PathGenerationSecret(path_generation_secret)
    }
}

pub(crate) struct SignatureKeySecret(Secret);

pub(crate) struct EncryptionKeySecret(Secret);

impl EncryptionKeySecret {
    pub(crate) fn generate_encryption_key_pair(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> (EncryptionKey, HpkePrivateKey) {
        let hpke_config = ciphersuite.hpke_config();
        let key_pair = crypto
            .derive_hpke_keypair(hpke_config, self.0.as_slice())
            .unwrap();
        (EncryptionKey::from(key_pair.public), key_pair.private)
    }
}

pub(crate) struct InitKeySecret(Secret);

impl InitKeySecret {
    pub(crate) fn generate_init_key_pair(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> (InitKey, HpkePrivateKey) {
        let hpke_config = ciphersuite.hpke_config();
        let key_pair = crypto
            .derive_hpke_keypair(hpke_config, self.0.as_slice())
            .unwrap();
        (InitKey::from(key_pair.public), key_pair.private)
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
    ) -> EpochInfoTbe {
        let plaintext = crypto
            .aead_decrypt(
                ciphersuite.aead_algorithm(),
                key.0.as_slice(),
                self.ciphertext.as_slice(),
                self.nonce.as_slice(),
                epoch_id.0.as_slice(),
            )
            .map_err(|_| CryptoError::CryptoLibraryError)
            .unwrap();
        EpochInfoTbe::tls_deserialize_exact_bytes(&plaintext).unwrap()
    }
}

#[derive(Debug, TlsSize, TlsSerialize, TlsDeserializeBytes)]
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
    ) -> EncryptedEpochInfo {
        let nonce = rand.random_vec(ciphersuite.aead_nonce_length()).unwrap();
        let payload = self.tls_serialize_detached().unwrap();
        let ciphertext = crypto
            .aead_encrypt(
                ciphersuite.aead_algorithm(),
                key.0.as_slice(),
                payload.as_slice(),
                nonce.as_slice(),
                epoch_id.0.as_slice(),
            )
            .unwrap();
        EncryptedEpochInfo { nonce, ciphertext }
    }
}
