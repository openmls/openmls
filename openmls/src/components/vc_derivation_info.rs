use openmls_traits::{
    crypto::OpenMlsCrypto, random::OpenMlsRand, storage::StorageProvider as _, types::Ciphersuite,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tls_codec::{DeserializeBytes, Serialize as _, TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::{
    binary_tree::{array_representation::TreeSize, LeafNodeIndex},
    ciphersuite::Secret,
    messages::PathSecret,
    schedule::pprf::{Pprf, PprfError, Prefix256},
    storage::OpenMlsProvider,
    treesync::node::encryption_keys::EncryptionKeyPair,
};

/// Component ID under which the virtual-clients derivation info is carried in
/// the leaf node's `app_data_dictionary` extension.
///
/// `0xFFFF` is a placeholder until the IETF draft is assigned an IANA value.
pub const VC_COMPONENT_ID: u16 = 0xFFFF;

// Operation-secret child labels (per draft PR #13). Each child is derived
// from the per-commit operation secret produced by evaluating the per-epoch
// PPRF on the per-commit input. Only `Encryption Key` and `Path Generation`
// are wired up at the moment; the remaining ones are reserved so that
// `key_package` / `application` derivation can be added without churning
// the constants.
const ENCRYPTION_KEY_LABEL: &str = "Encryption Key";
const PATH_GENERATION_LABEL: &str = "Path Generation";
#[allow(dead_code)] // reserved for KeyPackage/Application operation types
const SIGNATURE_KEY_LABEL: &str = "Signature Key";
#[allow(dead_code)] // reserved for KeyPackage/Application operation types
const INIT_KEY_LABEL: &str = "Init Key";
#[allow(dead_code)] // reserved for KeyPackage/Application operation types
const REUSE_GUARD_LABEL: &str = "Reuse Guard";

// Per-emulation-epoch labels. The spec (draft PR #13) calls the PPRF
// root secret "Base Secret" and the AEAD key "Encryption Key"; the AEAD
// label collides with the operation-secret child label above, so we keep
// "vc epoch_encryption_key" locally to disambiguate the two contexts in
// code while matching `Epoch ID` / `Base Secret` exactly.
const EPOCH_ID_LABEL: &str = "Epoch ID";
const EPOCH_ENCRYPTION_KEY_LABEL: &str = "vc epoch_encryption_key";
const EPOCH_SECRET_LABEL: &str = "Base Secret";

/// PPRF instance keyed on a 32-byte input. One of these is registered per
/// emulation-group epoch via [`register_vc_emulation_epoch`].
pub(crate) type VcPprf = Pprf<Prefix256>;

/// Per-commit virtual-clients material that the application supplies to
/// [`CommitBuilder::vc_emulation`] when sending a commit on a virtual-
/// clients group.
///
/// The PPRF and the per-epoch AEAD key live in the storage provider — the
/// application registers them once per emulation epoch via
/// [`register_vc_emulation_epoch`]. Per commit, the application picks
/// which emulation epoch to use (`epoch_id`) and supplies its own leaf
/// index in the *emulation* group (`emulation_leaf_index`). The library
/// generates the per-commit `random` bytes itself, hashes
/// `(emulation_leaf_index, random)` to produce the PPRF input, evaluates
/// the PPRF, and persists the punctured state.
///
/// [`CommitBuilder::vc_emulation`]: crate::group::CommitBuilder::vc_emulation
#[derive(Debug)]
pub struct VcEmulation {
    /// Identifier of the emulation epoch whose registered PPRF + AEAD key
    /// the library should use for this commit.
    pub epoch_id: EpochId,
    /// The sender's leaf index in the *emulation* group. Hashed alongside
    /// the per-commit random bytes to form the PPRF input.
    pub emulation_leaf_index: LeafNodeIndex,
}

/// Errors that can occur while processing virtual-clients derivation info.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum VirtualClientsError {
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
    /// No virtual-clients epoch encryption key was registered for this epoch.
    #[error("No virtual-clients epoch encryption key for this epoch.")]
    MissingEpochEncryptionKey,
    /// No virtual-clients PPRF was registered for this epoch.
    #[error("No virtual-clients PPRF for this epoch.")]
    MissingPprf,
    /// Loading or storing virtual-clients state via the storage provider
    /// failed.
    #[error("Virtual-clients storage error: {0}")]
    StorageError(String),
    /// The leaf encryption key in the path does not match the key derived
    /// from the path secret.
    #[error("Leaf encryption key from path does not match the derived key.")]
    EncryptionKeyMismatch,
    /// PPRF evaluation failed (e.g. the input was already punctured or
    /// out of bounds).
    #[error("PPRF evaluation failed: {0}")]
    PprfError(#[from] PprfError),
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

/// Per-emulation-epoch root secret supplied by the application.
///
/// Per the spec, this is generated externally by the emulation group when
/// it enters a new epoch (typically derived from the emulation group's
/// epoch authenticator / exporter). [`register_vc_emulation_epoch`]
/// derives the [`EpochId`], [`EpochEncryptionKey`], and the PPRF root
/// from this single input.
#[derive(Serialize, Deserialize)]
pub struct EmulatorEpochSecret(Secret);

impl std::fmt::Debug for EmulatorEpochSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmulatorEpochSecret")
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl EmulatorEpochSecret {
    /// Construct an `EmulatorEpochSecret` from raw bytes. Bytes are typically
    /// the output of the emulation group's epoch exporter (or any
    /// equivalent freshly-rotated per-epoch secret).
    pub fn new(bytes: &[u8]) -> Self {
        Self(Secret::from_slice(bytes))
    }

    fn derive_epoch_id(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<EpochId, VirtualClientsError> {
        let secret = self
            .0
            .derive_secret(crypto, ciphersuite, EPOCH_ID_LABEL)
            .map_err(|_| VirtualClientsError::CryptoError)?;
        Ok(EpochId(secret.as_slice().to_vec()))
    }

    fn derive_epoch_encryption_key(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<EpochEncryptionKey, VirtualClientsError> {
        let secret = self
            .0
            .kdf_expand_label(
                crypto,
                ciphersuite,
                EPOCH_ENCRYPTION_KEY_LABEL,
                &[],
                ciphersuite.aead_key_length(),
            )
            .map_err(|_| VirtualClientsError::CryptoError)?;
        Ok(EpochEncryptionKey(secret))
    }

    fn derive_epoch_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<Secret, VirtualClientsError> {
        self.0
            .derive_secret(crypto, ciphersuite, EPOCH_SECRET_LABEL)
            .map_err(|_| VirtualClientsError::CryptoError)
    }
}

/// Register a new virtual-clients emulation epoch.
///
/// Derives the epoch identifier, AEAD key, and PPRF root from the supplied
/// `emulator_epoch_secret`, instantiates a [`VcPprf`] and persists both
/// the PPRF and the AEAD key in the storage provider keyed on the derived
/// `EpochId`. Returns the `EpochId` so the caller can reference this
/// emulation epoch on subsequent virtual-clients commits.
///
/// Each virtual client (sender or receiver) calls this independently with
/// the same `emulator_epoch_secret` (shared via the emulation group's
/// exporter) and obtains the same `EpochId` deterministically.
pub fn register_vc_emulation_epoch<Provider: OpenMlsProvider>(
    provider: &Provider,
    ciphersuite: Ciphersuite,
    emulator_epoch_secret: EmulatorEpochSecret,
) -> Result<EpochId, VirtualClientsError> {
    let crypto = provider.crypto();
    let epoch_id = emulator_epoch_secret.derive_epoch_id(crypto, ciphersuite)?;
    let epoch_encryption_key =
        emulator_epoch_secret.derive_epoch_encryption_key(crypto, ciphersuite)?;
    let epoch_secret = emulator_epoch_secret.derive_epoch_secret(crypto, ciphersuite)?;

    // The PPRF tree's logical capacity is `2^256` (set by `Prefix256`'s
    // depth). `TreeSize` is informational metadata stored alongside the
    // root and is capped at `u32`; the actual input space is determined
    // by the prefix, not by `width`. We pass a safely representable
    // placeholder that doesn't overflow `TreeSize::new`'s internal
    // doubling.
    let pprf = VcPprf::new_with_size(epoch_secret, TreeSize::from_leaf_count(u16::MAX as u32));

    provider
        .storage()
        .write_vc_pprf(&epoch_id, &pprf)
        .map_err(|e| VirtualClientsError::StorageError(format!("{e}")))?;
    provider
        .storage()
        .write_vc_epoch_encryption_key(&epoch_id, &epoch_encryption_key)
        .map_err(|e| VirtualClientsError::StorageError(format!("{e}")))?;

    Ok(epoch_id)
}

#[derive(Debug, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub(crate) struct DerivationInfo {
    epoch_id: EpochId,
    ciphertext: EncryptedEpochInfo,
}

impl DerivationInfo {
    pub(crate) fn new(epoch_id: EpochId, ciphertext: EncryptedEpochInfo) -> Self {
        Self {
            epoch_id,
            ciphertext,
        }
    }

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

/// Identifier of an emulation epoch's registered virtual-clients state.
/// Derived deterministically from the application-supplied
/// `emulator_epoch_secret` by [`register_vc_emulation_epoch`].
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSize, TlsSerialize, TlsDeserializeBytes,
)]
pub struct EpochId(Vec<u8>);

/// AEAD key used by the sender to wrap the [`EpochInfoTbe`] in the leaf's
/// `app_data_dictionary` entry, and by the receiver to unwrap it. Its
/// length is exactly [`Ciphersuite::aead_key_length`] for the group's
/// ciphersuite. Derived from `emulator_epoch_secret` by
/// [`register_vc_emulation_epoch`].
#[derive(Serialize, Deserialize)]
pub struct EpochEncryptionKey(Secret);

impl std::fmt::Debug for EpochEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochEncryptionKey")
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Per-commit secret produced by evaluating the per-epoch PPRF on the
/// per-commit hash input. Sender and receiver derive the same value by
/// evaluating the same registered PPRF on the same input.
#[derive(Serialize, Deserialize)]
pub(crate) struct OperationSecret(Secret);

impl From<Secret> for OperationSecret {
    fn from(secret: Secret) -> Self {
        Self(secret)
    }
}

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
    ) -> Result<EncryptionKeyPair, VirtualClientsError> {
        let hpke_config = ciphersuite.hpke_config();
        let key_pair = crypto
            .derive_hpke_keypair(hpke_config, self.0.as_slice())
            .map_err(|_| VirtualClientsError::CryptoError)?;
        Ok(EncryptionKeyPair::from(key_pair))
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

/// What virtual-clients operation this per-commit input is being derived
/// for, per draft PR #11. Mixed into the PPRF input via TLS-serialized
/// [`EpochInfoTbe`] so that secrets derived for different operations
/// cannot collide even if the other fields happen to match.
///
/// Only `LeafNode` is wired into a sender path today (see `apply_vc_emulation`
/// in the commit builder); `KeyPackage` and `Application` are reserved
/// variants that future code paths will emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TlsSize, TlsSerialize, TlsDeserializeBytes)]
#[repr(u8)]
pub(crate) enum VirtualClientOperationType {
    LeafNode = 1,
    #[allow(dead_code)] // reserved
    KeyPackage = 2,
    #[allow(dead_code)] // reserved
    Application = 3,
}

/// Per-commit AEAD plaintext attached to the leaf via the VC component.
/// Per the spec, the same struct is hashed (under the group ciphersuite's
/// hash) to produce the PPRF input — see [`pprf_input`].
///
/// `leaf_index` is the *emulation*-group leaf index of the sending virtual
/// client, *not* the leaf index in the group that carries this commit.
#[derive(Debug, PartialEq, Eq, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub(crate) struct EpochInfoTbe {
    pub operation_type: VirtualClientOperationType,
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

/// Compute the 32-byte PPRF input as `Hash(tls_serialize(epoch_info))`,
/// truncating to 32 bytes when the ciphersuite's hash is wider (the
/// PPRF's `Prefix256` indexes into the first 256 bits).
pub(crate) fn pprf_input(
    crypto: &impl OpenMlsCrypto,
    ciphersuite: Ciphersuite,
    epoch_info: &EpochInfoTbe,
) -> Result<[u8; 32], VirtualClientsError> {
    let serialized = epoch_info
        .tls_serialize_detached()
        .map_err(|_| VirtualClientsError::SerializationError)?;
    let hash = crypto
        .hash(ciphersuite.hash_algorithm(), &serialized)
        .map_err(|_| VirtualClientsError::CryptoError)?;
    if hash.len() < 32 {
        return Err(VirtualClientsError::CryptoError);
    }
    let mut input = [0u8; 32];
    input.copy_from_slice(&hash[..32]);
    Ok(input)
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
        let emulator = EmulatorEpochSecret::new(
            &provider
                .rand()
                .random_vec(ciphersuite.hash_length())
                .expect("randomness"),
        );
        let key = emulator
            .derive_epoch_encryption_key(provider.crypto(), ciphersuite)
            .expect("derive ek");
        let epoch_id = emulator
            .derive_epoch_id(provider.crypto(), ciphersuite)
            .expect("derive epoch id");
        let original = EpochInfoTbe {
            operation_type: VirtualClientOperationType::LeafNode,
            leaf_index: LeafNodeIndex::new(7),
            random: provider.rand().random_vec(32).expect("randomness"),
        };
        let encrypted = original
            .encrypt(provider.crypto(), provider.rand(), ciphersuite, &key, &epoch_id)
            .expect("encrypt");
        let decrypted = encrypted
            .decrypt(provider.crypto(), ciphersuite, &key, &epoch_id)
            .expect("decrypt");
        assert_eq!(original, decrypted);
    }

    /// Two `EpochInfoTbe`s with identical `(leaf_index, random)` but
    /// different `operation_type` must produce different PPRF inputs;
    /// otherwise, sharing a PPRF across operation contexts would be
    /// unsafe.
    #[test]
    fn pprf_input_changes_with_operation_type() {
        let provider = OpenMlsRustCrypto::default();
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let leaf_node = EpochInfoTbe {
            operation_type: VirtualClientOperationType::LeafNode,
            leaf_index: LeafNodeIndex::new(3),
            random: vec![0xAA; 32],
        };
        let key_package = EpochInfoTbe {
            operation_type: VirtualClientOperationType::KeyPackage,
            leaf_index: LeafNodeIndex::new(3),
            random: vec![0xAA; 32],
        };
        let application = EpochInfoTbe {
            operation_type: VirtualClientOperationType::Application,
            leaf_index: LeafNodeIndex::new(3),
            random: vec![0xAA; 32],
        };
        let in_leaf = pprf_input(provider.crypto(), ciphersuite, &leaf_node).unwrap();
        let in_kp = pprf_input(provider.crypto(), ciphersuite, &key_package).unwrap();
        let in_app = pprf_input(provider.crypto(), ciphersuite, &application).unwrap();
        assert_ne!(in_leaf, in_kp);
        assert_ne!(in_leaf, in_app);
        assert_ne!(in_kp, in_app);
    }
}
