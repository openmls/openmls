use openmls_traits::{crypto::OpenMlsCrypto, random::OpenMlsRand, types::Ciphersuite};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tls_codec::{DeserializeBytes, Serialize as _, TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::{
    binary_tree::{array_representation::TreeSize, LeafNodeIndex},
    ciphersuite::Secret,
    messages::PathSecret,
    schedule::pprf::{Pprf, PprfError, Prefix256},
    treesync::node::encryption_keys::EncryptionKeyPair,
};

/// Component ID under which the virtual-clients derivation info is carried in
/// the leaf node's `app_data_dictionary` extension.
///
/// `0xFFFF` is a placeholder until the IETF draft is assigned an IANA value.
pub const VC_COMPONENT_ID: u16 = 0xFFFF;

// Operation-secret child labels. Each child is derived from the per-commit
// operation secret produced by evaluating the per-epoch PPRF on the per-commit
// input. Only `Encryption Key` and `Path Generation` are wired up at the
// moment; the remaining ones are reserved so that `key_package` / `application`
// derivation can be added without churning the constants.
const ENCRYPTION_KEY_LABEL: &str = "Encryption Key";
const PATH_GENERATION_LABEL: &str = "Path Generation";
#[allow(dead_code)] // reserved for KeyPackage/Application operation types
const SIGNATURE_KEY_LABEL: &str = "Signature Key";
#[allow(dead_code)] // reserved for KeyPackage/Application operation types
const INIT_KEY_LABEL: &str = "Init Key";

const EPOCH_ID_LABEL: &str = "Epoch ID";
const EPOCH_ENCRYPTION_KEY_LABEL: &str = "Encryption Key";
const EPOCH_SECRET_LABEL: &str = "Base Secret";
/// `DeriveSecret` label for [`ReuseGuardSecret`].
const REUSE_GUARD_LABEL: &str = "Reuse Guard";
/// `ExpandWithLabel` label for the 16-byte FF1 PRP key derived from a
/// [`ReuseGuardSecret`] (mls-virtual-clients draft, Reuse Guard section).
const REUSE_GUARD_PRP_KEY_LABEL: &str = "reuse guard";
/// FF1 PRP key length in bytes (AES-128).
const PRP_KEY_LEN: usize = 16;

/// PPRF instance keyed on a 32-byte input. One of these is registered per
/// emulation-group epoch by
/// [`MlsGroup::register_vc_emulation_epoch`](crate::group::MlsGroup::register_vc_emulation_epoch).
pub(crate) type VcPprf = Pprf<Prefix256>;

/// Per-commit virtual-clients material that the application supplies to
/// [`CommitBuilder::vc_emulation`] when sending a commit on a virtual-clients
/// group.
///
/// The PPRF, per-epoch AEAD key, and the registering client's
/// emulation-group leaf index live in the storage provider — the
/// application registers them once per emulation epoch via
/// [`MlsGroup::register_vc_emulation_epoch`], which sources the
/// per-emulation-epoch root secret from the emulation group's
/// `safe_export_secret(VC_COMPONENT_ID)`. When creating a commit, the
/// application supplies just the `epoch_id`; the library hashes
/// `(stored leaf_index, fresh random)` to produce the PPRF input,
/// evaluates the PPRF, and persists the punctured state.
///
/// The leaf carrying a VC commit must declare
/// [`ExtensionType::AppDataDictionary`](crate::extensions::ExtensionType::AppDataDictionary)
/// in its capabilities and must include an `AppComponents` entry (component
/// id `1`) listing [`VC_COMPONENT_ID`] in its `AppDataDictionary` extension;
/// otherwise the sender pre-check rejects the commit with
/// `VirtualClientsError::AppDataDictionaryNotSupported` or
/// `VirtualClientsError::VcComponentNotListed`.
///
/// [`CommitBuilder::vc_emulation`]: crate::group::CommitBuilder::vc_emulation
/// [`MlsGroup::register_vc_emulation_epoch`]: crate::group::MlsGroup::register_vc_emulation_epoch
#[derive(Debug)]
pub struct VcEmulation {
    /// Identifier of the emulation epoch whose registered PPRF + AEAD key
    /// the library should use for this commit.
    pub epoch_id: EpochId,
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
    /// No virtual-clients epoch encryption key was registered for this epoch.
    #[error("No virtual-clients epoch encryption key for this epoch.")]
    MissingEpochEncryptionKey,
    /// No virtual-clients PPRF was registered for this epoch.
    #[error("No virtual-clients PPRF for this epoch.")]
    MissingPprf,
    /// No virtual-clients `EmulationEpochState` was registered for this
    /// epoch, or it has been deleted.
    #[error("No virtual-clients emulation-epoch state for this epoch.")]
    MissingEmulationEpochState,
    /// Loading or storing virtual-clients state via the storage provider
    /// failed.
    #[error("Virtual-clients storage error")]
    StorageError,
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
    /// TLS encoding/decoding of a virtual-clients structure failed. Covers
    /// both serialization on the sender side and deserialization of the
    /// decrypted `EpochInfoTbe` on the receiver side.
    #[error("TLS codec error: {0}")]
    Tls(#[from] tls_codec::Error),
    /// The leaf carrying (or about to carry) a VC derivation-info entry
    /// does not declare `AppDataDictionary` in its capabilities.
    #[error("Leaf does not declare AppDataDictionary support in its capabilities.")]
    AppDataDictionaryNotSupported,
    /// The leaf's `AppDataDictionary` extension is missing the
    /// `AppComponents` entry, or that entry does not list
    /// [`VC_COMPONENT_ID`].
    #[error("Leaf's AppComponents entry does not list the virtual-clients component id.")]
    VcComponentNotListed,
}

/// Per-emulation-epoch root secret. Sourced internally by
/// [`MlsGroup::register_vc_emulation_epoch`] from the emulation group's
/// `safe_export_secret(VC_COMPONENT_ID)`.
///
/// [`MlsGroup::register_vc_emulation_epoch`]: crate::group::MlsGroup::register_vc_emulation_epoch
#[derive(Serialize, Deserialize)]
pub(crate) struct EmulatorEpochSecret(Secret);

impl std::fmt::Debug for EmulatorEpochSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmulatorEpochSecret")
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl EmulatorEpochSecret {
    /// Construct an `EmulatorEpochSecret` from raw bytes. Bytes are
    /// expected to be the output of the emulation group's
    /// `safe_export_secret(VC_COMPONENT_ID)`.
    pub(crate) fn new(bytes: &[u8]) -> Self {
        Self(Secret::from_slice(bytes))
    }

    pub(crate) fn derive_epoch_id(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<EpochId, VirtualClientsError> {
        let secret = self
            .0
            .derive_secret(crypto, ciphersuite, EPOCH_ID_LABEL)
            .map_err(|e| {
                log::error!("vc: derive epoch id failed: {e:?}");
                VirtualClientsError::CryptoError
            })?;
        Ok(EpochId(secret.as_slice().to_vec()))
    }

    pub(crate) fn derive_epoch_encryption_key(
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
            .map_err(|e| {
                log::error!("vc: derive epoch encryption key failed: {e:?}");
                VirtualClientsError::CryptoError
            })?;
        Ok(EpochEncryptionKey(secret))
    }

    pub(crate) fn derive_epoch_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<Secret, VirtualClientsError> {
        self.0
            .derive_secret(crypto, ciphersuite, EPOCH_SECRET_LABEL)
            .map_err(|e| {
                log::error!("vc: derive epoch base secret failed: {e:?}");
                VirtualClientsError::CryptoError
            })
    }

    /// Derive the per-emulation-epoch [`ReuseGuardSecret`].
    pub(crate) fn derive_reuse_guard_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<ReuseGuardSecret, VirtualClientsError> {
        let secret = self
            .0
            .derive_secret(crypto, ciphersuite, REUSE_GUARD_LABEL)
            .map_err(|e| {
                log::error!("vc: derive reuse-guard secret failed: {e:?}");
                VirtualClientsError::CryptoError
            })?;
        Ok(ReuseGuardSecret(secret))
    }
}

/// Per-emulation-epoch secret used to derive the FF1 PRP key for
/// `reuse_guard` values sent by this virtual client. Derived from
/// [`EmulatorEpochSecret`] via [`EmulatorEpochSecret::derive_reuse_guard_secret`].
#[derive(Serialize, Deserialize)]
pub(crate) struct ReuseGuardSecret(Secret);

impl std::fmt::Debug for ReuseGuardSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReuseGuardSecret")
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl ReuseGuardSecret {
    /// Test-only constructor from raw bytes.
    #[cfg(test)]
    pub(crate) fn from_secret_for_tests(secret: Secret) -> Self {
        Self(secret)
    }

    /// Derive the 16-byte FF1 PRP key for a single application message:
    ///
    /// ```text
    /// prp_key = ExpandWithLabel(reuse_guard_secret, "reuse guard",
    ///                           key_schedule_nonce, 16)
    /// ```
    ///
    /// `ciphersuite` is the emulation group's ciphersuite, stored on
    /// [`EmulationEpochState`].
    pub(crate) fn derive_prp_key(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        key_schedule_nonce: &[u8],
    ) -> Result<[u8; PRP_KEY_LEN], VirtualClientsError> {
        let key = self
            .0
            .kdf_expand_label(
                crypto,
                ciphersuite,
                REUSE_GUARD_PRP_KEY_LABEL,
                key_schedule_nonce,
                PRP_KEY_LEN,
            )
            .map_err(|e| {
                log::error!("vc: derive reuse-guard PRP key failed: {e:?}");
                VirtualClientsError::CryptoError
            })?;
        key.as_slice().try_into().map_err(|_| {
            log::error!("vc: derived PRP key has unexpected length (expected {PRP_KEY_LEN})");
            VirtualClientsError::CryptoError
        })
    }
}

/// Build the per-emulation-epoch [`VcPprf`] root from the emulator epoch
/// secret. Used by [`MlsGroup::register_vc_emulation_epoch`] together with
/// the derived [`EpochId`] / [`EpochEncryptionKey`].
///
/// The PPRF tree's logical capacity is `2^256` (set by `Prefix256`'s
/// depth). `TreeSize` is informational metadata stored alongside the
/// root and is capped at `u32`; the actual input space is determined by
/// the prefix, not by `width`, so we pass a safely representable
/// placeholder.
///
/// [`MlsGroup::register_vc_emulation_epoch`]: crate::group::MlsGroup::register_vc_emulation_epoch
pub(crate) fn build_vc_pprf(epoch_secret: Secret) -> VcPprf {
    VcPprf::new_with_size(epoch_secret, TreeSize::from_leaf_count(u16::MAX as u32))
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
/// Derived deterministically from the emulation group's
/// `safe_export_secret(VC_COMPONENT_ID)` by
/// [`MlsGroup::register_vc_emulation_epoch`].
///
/// [`MlsGroup::register_vc_emulation_epoch`]: crate::group::MlsGroup::register_vc_emulation_epoch
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSize, TlsSerialize, TlsDeserializeBytes,
)]
pub struct EpochId(Vec<u8>);

/// AEAD key used by the sender to wrap the [`EpochInfoTbe`] in the leaf's
/// `app_data_dictionary` entry, and by the receiver to unwrap it. Its
/// length is exactly [`Ciphersuite::aead_key_length`] for the group's
/// ciphersuite. Derived from the emulation group's
/// `safe_export_secret(VC_COMPONENT_ID)` by
/// [`MlsGroup::register_vc_emulation_epoch`].
///
/// [`MlsGroup::register_vc_emulation_epoch`]: crate::group::MlsGroup::register_vc_emulation_epoch
#[derive(Serialize, Deserialize)]
pub(crate) struct EpochEncryptionKey(Secret);

impl std::fmt::Debug for EpochEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochEncryptionKey")
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Per-emulation-epoch state persisted by
/// [`MlsGroup::register_vc_emulation_epoch`] alongside the per-epoch PPRF,
/// keyed by [`EpochId`]. Bundles everything the library needs to emit a VC
/// commit for this epoch and to XOR application message nonces with
/// deterministic reuse guards.
///
/// [`MlsGroup::register_vc_emulation_epoch`]:
///     crate::group::MlsGroup::register_vc_emulation_epoch
#[derive(Debug, Serialize, Deserialize)]
pub struct EmulationEpochState {
    /// The registering client's leaf index in the emulation group at
    /// registration time. Hashed into `EpochInfoTbe` and used as the
    /// sender's `leaf_index_e` in the reuse-guard derivation.
    pub(crate) leaf_index: LeafNodeIndex,
    pub(crate) epoch_encryption_key: EpochEncryptionKey,
    pub(crate) reuse_guard_secret: ReuseGuardSecret,
    /// Number of leaves `N_e` in the emulation group at registration time.
    pub(crate) emulation_group_size: TreeSize,
    /// Ciphersuite of the emulation group at registration time. Used by
    /// the reuse-guard derivation.
    pub(crate) emulation_ciphersuite: Ciphersuite,
}

impl EmulationEpochState {
    pub(crate) fn new(
        leaf_index: LeafNodeIndex,
        epoch_encryption_key: EpochEncryptionKey,
        reuse_guard_secret: ReuseGuardSecret,
        emulation_group_size: TreeSize,
        emulation_ciphersuite: Ciphersuite,
    ) -> Self {
        Self {
            leaf_index,
            epoch_encryption_key,
            reuse_guard_secret,
            emulation_group_size,
            emulation_ciphersuite,
        }
    }

    /// Consume the state and return only the fields needed by the
    /// commit-builder / commit-processing paths.
    pub(crate) fn into_parts(self) -> (LeafNodeIndex, EpochEncryptionKey) {
        (self.leaf_index, self.epoch_encryption_key)
    }

    /// Borrow the per-message inputs the framing layer needs to derive
    /// the PRP key and pick `x` for a reuse guard.
    #[allow(dead_code)] // wired up in framing in a later commit
    pub(crate) fn reuse_guard_inputs(
        &self,
    ) -> (&ReuseGuardSecret, Ciphersuite, TreeSize, LeafNodeIndex) {
        (
            &self.reuse_guard_secret,
            self.emulation_ciphersuite,
            self.emulation_group_size,
            self.leaf_index,
        )
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
            .map_err(|e| {
                log::error!("vc: derive encryption-key secret failed: {e:?}");
                VirtualClientsError::CryptoError
            })?;
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
            .map_err(|e| {
                log::error!("vc: derive path-generation secret failed: {e:?}");
                VirtualClientsError::CryptoError
            })?;
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
            .map_err(|e| {
                log::error!("vc: derive HPKE keypair failed: {e:?}");
                VirtualClientsError::CryptoError
            })?;
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
            .map_err(|e| {
                log::error!("vc: aead decrypt epoch info failed: {e:?}");
                VirtualClientsError::EpochInfoDecryptionFailed
            })?;
        Ok(EpochInfoTbe::tls_deserialize_exact_bytes(&plaintext)?)
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
            .map_err(|e| {
                log::error!("vc: aead nonce randomness failed: {e:?}");
                VirtualClientsError::RandError
            })?;
        let payload = self.tls_serialize_detached()?;
        let ciphertext = crypto
            .aead_encrypt(
                ciphersuite.aead_algorithm(),
                key.0.as_slice(),
                payload.as_slice(),
                nonce.as_slice(),
                epoch_id.0.as_slice(),
            )
            .map_err(|e| {
                log::error!("vc: aead encrypt epoch info failed: {e:?}");
                VirtualClientsError::CryptoError
            })?;
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
    let serialized = epoch_info.tls_serialize_detached()?;
    let hash = crypto
        .hash(ciphersuite.hash_algorithm(), &serialized)
        .map_err(|e| {
            log::error!("vc: pprf input hash failed: {e:?}");
            VirtualClientsError::CryptoError
        })?;
    if hash.len() < 32 {
        log::error!(
            "vc: pprf input hash too short: got {} bytes, need 32",
            hash.len()
        );
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
            .encrypt(
                provider.crypto(),
                provider.rand(),
                ciphersuite,
                &key,
                &epoch_id,
            )
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
