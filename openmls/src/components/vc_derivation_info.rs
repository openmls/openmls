use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, CryptoError},
    OpenMlsProvider,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tls_codec::{
    DeserializeBytes, Serialize as _, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes,
};

use crate::{
    binary_tree::{array_representation::TreeSize, LeafNodeIndex},
    ciphersuite::{hash_ref::KeyPackageRef, Secret},
    messages::PathSecret,
    treesync::node::encryption_keys::EncryptionKeyPair,
};

/// Component ID under which the virtual-clients derivation info is carried in
/// the leaf node's `app_data_dictionary` extension.
///
/// `0x0006` is the value the draft suggests for IANA registration, which is
/// still pending.
pub const VC_COMPONENT_ID: u16 = 0x0006;

// Operation-secret child labels. Each child is derived from the per-operation
// secret produced by the per-epoch operation secret tree. `Encryption Key`
// and `Path Generation` cover the `leaf_node` commit path, and `Init Key`
// covers the `key_package` operation path. The spec also defines a
// `Signature Key` child, which together with the operation paths that consume
// it is deferred to a follow-up PR.
const ENCRYPTION_KEY_LABEL: &str = "Encryption Key";
const PATH_GENERATION_LABEL: &str = "Path Generation";
const INIT_KEY_LABEL: &str = "Init Key";
/// `ExpandWithLabel` label for the per-KeyPackage seed secret derived from a
/// `key_package` operation secret (mls-virtual-clients draft, batch KeyPackage
/// derivation). One operation secret covers a batch of KeyPackages, and each
/// KeyPackage's seed is expanded from it using the KeyPackage's index as the
/// context.
const KEY_PACKAGE_SEED_LABEL: &str = "key package seed";

/// `ExpandWithLabel` label for the [`DerivationInfoTbe`] AEAD key derived
/// from the per-epoch [`EpochEncryptionKey`].
const DERIVATION_INFO_KEY_LABEL: &str = "key";
/// `ExpandWithLabel` label for the [`DerivationInfoTbe`] AEAD nonce derived
/// from the per-epoch [`EpochEncryptionKey`].
const DERIVATION_INFO_NONCE_LABEL: &str = "nonce";

const EPOCH_ID_LABEL: &str = "Epoch ID";
const EPOCH_ENCRYPTION_KEY_LABEL: &str = "Encryption Key";
const EPOCH_BASE_SECRET_LABEL: &str = "Base Secret";
/// `DeriveSecret` label for [`ReuseGuardSecret`].
const REUSE_GUARD_LABEL: &str = "Reuse Guard";
/// `DeriveSecret` label for [`GenerationIdSecret`].
const GENERATION_ID_LABEL: &str = "Generation ID Secret";
/// `ExpandWithLabel` label for the 16-byte FF1 PRP key derived from a
/// [`ReuseGuardSecret`] (mls-virtual-clients draft, Reuse Guard section).
const REUSE_GUARD_PRP_KEY_LABEL: &str = "reuse guard";
/// FF1 PRP key length in bytes (AES-128).
const PRP_KEY_LEN: usize = 16;

/// Errors that can occur while processing virtual-clients derivation info.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum VirtualClientsError {
    /// The derivation-info bytes failed to deserialize.
    #[error("Failed to deserialize derivation info.")]
    DerivationInfoMalformed,
    /// AEAD decryption of the encrypted derivation info failed (wrong key,
    /// tampered ciphertext, or mismatched AAD).
    #[error("Failed to decrypt derivation info.")]
    DerivationInfoDecryptionFailed,
    /// No virtual-clients operation secret tree was registered for this
    /// epoch.
    #[error("No virtual-clients operation secret tree for this epoch.")]
    MissingOperationTree,
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
    /// A cryptographic operation failed during virtual-clients processing.
    #[error("Cryptographic operation failed.")]
    CryptoError(#[from] CryptoError),
    /// Hash function produced output of unexpected length.
    #[error(
        "Hash function produced output of length {actual_length}, expected {expected_length}."
    )]
    HashOutputLengthMismatch {
        /// The number of bytes in the hash output.
        actual_length: usize,
        /// The required number of bytes in the hash output.
        expected_length: usize,
    },
    /// TLS encoding/decoding of a virtual-clients structure failed. Covers
    /// both serialization on the sender side and deserialization of the
    /// decrypted `DerivationInfoTbe` on the receiver side.
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
    /// The requested leaf index lies outside the operation secret tree.
    #[error("Leaf index is outside the operation secret tree.")]
    IndexOutOfBounds,
    /// The operation secret for the requested generation was already derived
    /// and deleted for forward secrecy.
    #[error("The operation secret for this generation was already consumed.")]
    OperationGenerationConsumed,
    /// The requested operation generation lies too far beyond the current
    /// ratchet head (see `MAXIMUM_FORWARD_DISTANCE` in the operation secret
    /// tree).
    #[error("The requested operation generation is too far beyond the ratchet head.")]
    OperationGenerationTooDistant,
    /// An operation ratchet has reached the maximum generation.
    #[error("Operation ratchet generation has reached `u32::MAX`.")]
    OperationRatchetTooLong,
    /// An unrecoverable error has occurred due to a bug in the
    /// implementation.
    #[error("An unrecoverable error has occurred due to a bug in the implementation.")]
    LibraryError,
    /// The `KeyPackageUpload` lists the same `key_package_index` more than
    /// once. Each batch index must appear at most once.
    #[error("KeyPackageUpload contains a duplicate key_package_index: {0}.")]
    DuplicateKeyPackageIndex(u32),
    /// The `KeyPackageUpload` lists the same [`KeyPackageRef`] more than once.
    /// Each KeyPackage reference must appear at most once.
    #[error("KeyPackageUpload contains a duplicate KeyPackageRef.")]
    DuplicateKeyPackageRef,
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
        let secret = self.0.derive_secret(crypto, ciphersuite, EPOCH_ID_LABEL)?;
        Ok(EpochId(secret.as_slice().to_vec().into()))
    }

    /// Derive the per-epoch [`EpochEncryptionKey`]. The key is a KDF
    /// secret (the per-leaf AEAD key and nonce are expanded from it), so
    /// it is derived at the KDF's hash length.
    pub(crate) fn derive_epoch_encryption_key(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<EpochEncryptionKey, VirtualClientsError> {
        let secret = self
            .0
            .derive_secret(crypto, ciphersuite, EPOCH_ENCRYPTION_KEY_LABEL)?;
        Ok(EpochEncryptionKey(secret))
    }

    pub(crate) fn derive_epoch_base_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<Secret, VirtualClientsError> {
        Ok(self
            .0
            .derive_secret(crypto, ciphersuite, EPOCH_BASE_SECRET_LABEL)?)
    }

    /// Derive the per-emulation-epoch [`ReuseGuardSecret`].
    pub(crate) fn derive_reuse_guard_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<ReuseGuardSecret, VirtualClientsError> {
        let secret = self
            .0
            .derive_secret(crypto, ciphersuite, REUSE_GUARD_LABEL)?;
        Ok(ReuseGuardSecret(secret))
    }

    /// Derive the per-emulation-epoch [`GenerationIdSecret`].
    pub(crate) fn derive_generation_id_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<GenerationIdSecret, VirtualClientsError> {
        let secret = self
            .0
            .derive_secret(crypto, ciphersuite, GENERATION_ID_LABEL)?;
        Ok(GenerationIdSecret(secret))
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
        let key = self.0.kdf_expand_label(
            crypto,
            ciphersuite,
            REUSE_GUARD_PRP_KEY_LABEL,
            key_schedule_nonce,
            PRP_KEY_LEN,
        )?;
        key.as_slice()
            .try_into()
            .map_err(|_| VirtualClientsError::HashOutputLengthMismatch {
                actual_length: key.as_slice().len(),
                expected_length: PRP_KEY_LEN,
            })
    }
}

/// Per-emulation-epoch secret used to derive generation IDs for DS
/// collision detection (mls-virtual-clients draft, "Coordinating ratchet
/// generations with the DS" section). Derived from [`EmulatorEpochSecret`]
/// via [`EmulatorEpochSecret::derive_generation_id_secret`].
///
/// Derived and persisted now so the per-epoch state is complete, but not yet
/// consumed: the `generation_id` derivation and its `PrivateMessageContext`
/// input land in a follow-up PR. It is stored here so older emulation epochs
/// remain usable once that path exists.
#[derive(Serialize, Deserialize)]
pub(crate) struct GenerationIdSecret(Secret);

impl std::fmt::Debug for GenerationIdSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerationIdSecret")
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// The virtual-clients derivation info carried in the leaf node's
/// `app_data_dictionary` extension under [`VC_COMPONENT_ID`]
/// (mls-virtual-clients draft):
///
/// ```text
/// struct {
///   opaque epoch_id<V>;
///   opaque ciphertext<V>;
/// } DerivationInfo
/// ```
///
/// `ciphertext` is the AEAD-wrapped [`DerivationInfoTbe`], encrypted in the
/// emulation group's ciphersuite with key and nonce derived from the
/// per-epoch [`EpochEncryptionKey`] and the carrying leaf's serialized
/// `encryption_key`, with `epoch_id` as AAD.
#[derive(Debug, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub(crate) struct DerivationInfo {
    epoch_id: EpochId,
    ciphertext: VLBytes,
}

impl DerivationInfo {
    /// Encrypt `tbe` under the per-epoch AEAD key, binding it to the leaf
    /// that carries the resulting derivation info via the leaf's serialized
    /// `encryption_key` (the key/nonce derivation context) and to
    /// `epoch_id` (the AAD).
    pub(crate) fn encrypt(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        key: &EpochEncryptionKey,
        epoch_id: EpochId,
        leaf_encryption_key: &[u8],
        tbe: &DerivationInfoTbe,
    ) -> Result<Self, VirtualClientsError> {
        let (aead_key, aead_nonce) =
            key.derive_key_nonce(crypto, ciphersuite, leaf_encryption_key)?;
        let payload = tbe.tls_serialize_detached()?;
        let ciphertext = crypto.aead_encrypt(
            ciphersuite.aead_algorithm(),
            aead_key.as_slice(),
            payload.as_slice(),
            aead_nonce.as_slice(),
            epoch_id.0.as_slice(),
        )?;
        Ok(Self {
            epoch_id,
            ciphertext: ciphertext.into(),
        })
    }

    pub(crate) fn epoch_id(&self) -> &EpochId {
        &self.epoch_id
    }

    /// Decrypt the wrapped [`DerivationInfoTbe`]. `leaf_encryption_key` is
    /// the serialized `encryption_key` of the leaf node that carries this
    /// derivation info.
    pub(crate) fn decrypt(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        key: &EpochEncryptionKey,
        leaf_encryption_key: &[u8],
        operation_type: VirtualClientOperationType,
    ) -> Result<DerivationInfoTbe, VirtualClientsError> {
        let (aead_key, aead_nonce) =
            key.derive_key_nonce(crypto, ciphersuite, leaf_encryption_key)?;
        let plaintext = crypto
            .aead_decrypt(
                ciphersuite.aead_algorithm(),
                aead_key.as_slice(),
                self.ciphertext.as_slice(),
                aead_nonce.as_slice(),
                self.epoch_id.0.as_slice(),
            )
            .map_err(|e| {
                log::error!("vc: aead decrypt derivation info failed: {e:?}");
                VirtualClientsError::DerivationInfoDecryptionFailed
            })?;
        DerivationInfoTbe::deserialize_for_operation(&plaintext, operation_type)
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
pub struct EpochId(VLBytes);

/// Wire struct a virtual client hands to a sibling so the sibling can fetch
/// and process the matching KeyPackage (mls-virtual-clients draft):
///
/// ```text
/// struct {
///   opaque key_package_ref<V>;
///   uint32 key_package_index;
/// } KeyPackageInfo
/// ```
///
/// `key_package_ref` is the [`KeyPackageRef`] (a [`HashReference`]) of the
/// KeyPackage built by [`KeyPackageBuilder::build_vc_batch`]. `key_package_index`
/// is the KeyPackage's position within the `key_package` operation batch: one
/// operation secret covers the whole batch and each KeyPackage's seed is
/// derived from it under this index.
///
/// [`HashReference`]: crate::ciphersuite::hash_ref::HashReference
/// [`KeyPackageBuilder::build_vc_batch`]: crate::key_packages::KeyPackageBuilder::build_vc_batch
#[derive(Debug, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub struct KeyPackageInfo {
    /// Hash reference of the virtual client's KeyPackage.
    pub key_package_ref: KeyPackageRef,
    /// Position of this KeyPackage within the operation batch.
    pub key_package_index: u32,
}

/// Wire struct a virtual client uploads to a sibling so the sibling learns
/// about the KeyPackages the virtual client published for an emulation epoch
/// (mls-virtual-clients draft):
///
/// ```text
/// struct {
///   opaque epoch_id<V>;
///   uint32 leaf_index;
///   uint32 generation;
///   KeyPackageInfo key_package_info<V>;
/// } KeyPackageUpload
/// ```
///
/// `epoch_id` identifies the emulation epoch the KeyPackages belong to.
/// `leaf_index` is the uploading client's emulation-group leaf index at that
/// epoch. The receiver stores this leaf index: the KeyPackage operation
/// secret was allocated from the uploader's per-leaf ratchet, so a sibling
/// rederiving the KeyPackage material must walk that same leaf's ratchet, not
/// its own. `generation` is the single `key_package` operation generation
/// consumed for the whole batch. `key_package_info` carries one
/// [`KeyPackageInfo`] per uploaded KeyPackage, each with its index within the
/// batch.
#[derive(Debug, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub struct KeyPackageUpload {
    /// Emulation epoch the uploaded KeyPackages belong to.
    pub epoch_id: EpochId,
    /// Uploading client's emulation-group leaf index at that epoch.
    pub leaf_index: LeafNodeIndex,
    /// Operation-ratchet generation consumed for the whole batch.
    pub generation: u32,
    /// One entry per uploaded KeyPackage.
    pub key_package_info: Vec<KeyPackageInfo>,
}

/// Per-`KeyPackageRef` material a sibling retains when it processes a
/// [`KeyPackageUpload`]. It captures what the Welcome path needs to later
/// rederive the KeyPackage's init and leaf-encryption keys without touching
/// the operation tree: the per-KeyPackage seed secret, plus the emulation
/// epoch, leaf index, generation, and batch index used to validate the leaf
/// found in the ratchet tree.
///
/// The seed is pinned here at upload-processing time so the Welcome path stays
/// independent of the operation tree's bounded out-of-order tolerance: a batch
/// can hold more KeyPackages than that tolerance, and Welcomes can arrive in
/// any order, yet every seed remains available because the single batch
/// generation is consumed once and each seed is stored alongside its index.
#[derive(Debug, Serialize, Deserialize)]
pub struct RetainedKeyPackageMaterial {
    /// Emulation epoch the KeyPackage belongs to.
    pub epoch_id: EpochId,
    /// Uploader's emulation-group leaf index, identifying the operation
    /// ratchet the batch generation was allocated from.
    pub leaf_index: LeafNodeIndex,
    /// Operation-ratchet generation consumed for the whole batch.
    pub generation: u32,
    /// Position of this KeyPackage within the batch.
    pub key_package_index: u32,
    /// Per-KeyPackage seed secret from which the init and leaf-encryption keys
    /// are derived at Welcome time.
    pub key_package_seed_secret: KeyPackageSeedSecret,
}

/// Reject a batch whose [`KeyPackageInfo`] entries are not all distinct.
///
/// Returns [`VirtualClientsError::DuplicateKeyPackageIndex`] if any
/// `key_package_index` repeats, and
/// [`VirtualClientsError::DuplicateKeyPackageRef`] if any `key_package_ref`
/// repeats. A duplicate index would map two KeyPackages onto the same
/// per-index seed, and a duplicate reference would have the second upload
/// entry overwrite the first's retained material, so both are rejected before
/// any state is loaded or any operation generation is consumed.
fn validate_key_package_infos(infos: &[KeyPackageInfo]) -> Result<(), VirtualClientsError> {
    let mut seen_indices = std::collections::BTreeSet::new();
    let mut seen_refs = std::collections::BTreeSet::new();
    for info in infos {
        if !seen_indices.insert(info.key_package_index) {
            return Err(VirtualClientsError::DuplicateKeyPackageIndex(
                info.key_package_index,
            ));
        }
        if !seen_refs.insert(&info.key_package_ref) {
            return Err(VirtualClientsError::DuplicateKeyPackageRef);
        }
    }
    Ok(())
}

/// Build a [`KeyPackageUpload`] for `epoch_id` from a batch's `generation` and
/// its [`KeyPackageInfo`] entries, filling `leaf_index` from the
/// [`EmulationEpochState`] stored for that epoch.
///
/// The virtual client calls this after building a batch of KeyPackages with
/// [`KeyPackageBuilder::build_vc_batch`] to assemble the message it hands to
/// its sibling. `generation` is the single `key_package` operation generation
/// the batch consumed.
///
/// Returns [`VirtualClientsError::MissingEmulationEpochState`] if no state is
/// registered for `epoch_id`.
///
/// [`KeyPackageBuilder::build_vc_batch`]: crate::key_packages::KeyPackageBuilder::build_vc_batch
pub fn assemble_vc_key_package_upload<Storage: crate::storage::StorageProvider>(
    storage: &Storage,
    epoch_id: EpochId,
    generation: u32,
    key_package_info: Vec<KeyPackageInfo>,
) -> Result<KeyPackageUpload, VirtualClientsError> {
    validate_key_package_infos(&key_package_info)?;
    let state: EmulationEpochState = storage
        .vc_emulation_epoch_state(&epoch_id)
        .map_err(|e| {
            log::error!("vc: load emulation epoch state in assemble upload failed: {e:?}");
            VirtualClientsError::StorageError
        })?
        .ok_or(VirtualClientsError::MissingEmulationEpochState)?;
    Ok(KeyPackageUpload {
        epoch_id,
        leaf_index: state.leaf_index,
        generation,
        key_package_info,
    })
}

/// Process a [`KeyPackageUpload`] received from a sibling virtual client.
///
/// Derives the batch's single `key_package` operation secret once from the
/// uploader's leaf ratchet at `(epoch_id, leaf_index, generation)`, then
/// stores the advanced operation tree and one [`RetainedKeyPackageMaterial`]
/// per [`KeyPackageInfo`] (keyed by the info's [`KeyPackageRef`]) in a single
/// atomic batch write.
///
/// The operation secret and the per-index seeds are derived under the
/// emulation ciphersuite (the operation tree's ciphersuite). The init and
/// leaf-encryption keys are later derived from each seed under the KeyPackage's
/// own ciphersuite at Welcome time. The operation secret is dropped once all
/// seeds are derived. The batch generation is consumed in the tree exactly
/// once.
pub fn process_vc_key_package_upload<Provider: OpenMlsProvider>(
    provider: &Provider,
    upload: &KeyPackageUpload,
) -> Result<(), VirtualClientsError> {
    use crate::components::vc_operation_tree::OperationSecretTree;
    use openmls_traits::storage::StorageProvider as _;

    validate_key_package_infos(&upload.key_package_info)?;

    let storage = provider.storage();
    let crypto = provider.crypto();

    let state: EmulationEpochState = storage
        .vc_emulation_epoch_state(&upload.epoch_id)
        .map_err(|e| {
            log::error!("vc: load emulation epoch state in process upload failed: {e:?}");
            VirtualClientsError::StorageError
        })?
        .ok_or(VirtualClientsError::MissingEmulationEpochState)?;
    let mut operation_tree: OperationSecretTree = storage
        .vc_operation_tree(&upload.epoch_id)
        .map_err(|e| {
            log::error!("vc: load operation tree in process upload failed: {e:?}");
            VirtualClientsError::StorageError
        })?
        .ok_or(VirtualClientsError::MissingOperationTree)?;
    let emulation_ciphersuite = state.emulation_ciphersuite;

    // The KeyPackage operation context is empty, matching `build_vc_batch`.
    let operation_secret = operation_tree.derive_operation_secret(
        crypto,
        emulation_ciphersuite,
        &upload.epoch_id,
        upload.leaf_index,
        VirtualClientOperationType::KeyPackage,
        upload.generation,
        b"",
    )?;

    let mut materials = Vec::with_capacity(upload.key_package_info.len());
    for info in &upload.key_package_info {
        let key_package_seed_secret = operation_secret.derive_key_package_seed_secret(
            crypto,
            emulation_ciphersuite,
            info.key_package_index,
        )?;
        let material = RetainedKeyPackageMaterial {
            epoch_id: upload.epoch_id.clone(),
            leaf_index: upload.leaf_index,
            generation: upload.generation,
            key_package_index: info.key_package_index,
            key_package_seed_secret,
        };
        materials.push((info.key_package_ref.clone(), material));
    }

    storage
        .write_retained_key_package_material_batch(&upload.epoch_id, &operation_tree, &materials)
        .map_err(|e| {
            log::error!("vc: persist batch key package material in process upload failed: {e:?}");
            VirtualClientsError::StorageError
        })?;
    Ok(())
}

/// Material a sibling emulator derives to join a higher-level group via a
/// virtual client's KeyPackage.
///
/// Carried from the first Welcome stage (where the init private key decrypts
/// the group secrets, before the ratchet tree is available) into staging
/// (where the derived `encryption_keypair` becomes the joiner's leaf keypair
/// and the recorded `(epoch_id, leaf_index, generation, key_package_index)`
/// validate the leaf found in the tree). The keys are derived from the
/// per-KeyPackage seed pinned in [`RetainedKeyPackageMaterial`], not by
/// re-walking the operation tree.
#[derive(Debug)]
pub(crate) struct VcWelcomeMaterial {
    /// The [`KeyPackageRef`] the welcome's encrypted group secrets addressed.
    pub(crate) key_package_ref: KeyPackageRef,
    /// Emulation epoch the KeyPackage belongs to.
    pub(crate) epoch_id: EpochId,
    /// Uploader's emulation-group leaf index, identifying the operation
    /// ratchet the batch generation was allocated from.
    pub(crate) leaf_index: LeafNodeIndex,
    /// Operation-ratchet generation consumed for the whole batch.
    pub(crate) generation: u32,
    /// Position of this KeyPackage within the batch.
    pub(crate) key_package_index: u32,
    /// Init private key derived from the seed, used to decrypt the encrypted
    /// group secrets.
    pub(crate) init_private_key: openmls_traits::types::HpkePrivateKey,
    /// Leaf encryption keypair derived from the seed, used as the joiner's
    /// leaf keypair.
    pub(crate) encryption_keypair: EncryptionKeyPair,
}

/// Per-higher-level-group record of which emulation-group epoch produced the
/// virtual-client LeafNode that was active at each recent epoch of that
/// group.
///
/// Reuse guards must be resolved with the emulation epoch that was bound at
/// the higher-level epoch a message was sent in, not the latest one: a
/// delayed PrivateMessage from a past higher-level epoch has to be
/// deprotected with the state that was active then. Entries are written at
/// commit merge and retained for as many past epochs as the group's message
/// secrets store keeps, since a binding is only useful while the matching
/// message secrets still exist.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct VcEmulationBindings {
    // In order of insertion, oldest at the front.
    bindings: std::collections::VecDeque<(crate::group::GroupEpoch, EpochId)>,
}

impl VcEmulationBindings {
    /// Look up the emulation epoch bound at the given higher-level epoch.
    pub fn get(&self, epoch: crate::group::GroupEpoch) -> Option<&EpochId> {
        for (bound_epoch, epoch_id) in &self.bindings {
            if *bound_epoch == epoch {
                return Some(epoch_id);
            }
        }
        None
    }

    /// Record `epoch_id` as the binding for `epoch`, keeping at most
    /// `max_entries` entries by dropping the oldest ones.
    pub(crate) fn insert(
        &mut self,
        epoch: crate::group::GroupEpoch,
        epoch_id: EpochId,
        max_entries: usize,
    ) {
        self.bindings
            .retain(|(bound_epoch, _)| *bound_epoch != epoch);
        self.bindings.push_back((epoch, epoch_id));
        while self.bindings.len() > max_entries {
            self.bindings.pop_front();
        }
    }
}

/// Per-epoch secret from which the sender derives the AEAD key and nonce
/// that wrap the [`DerivationInfoTbe`] in the leaf's `app_data_dictionary`
/// entry, and the receiver the same pair to unwrap it:
///
/// ```text
/// derivation_info_key = ExpandWithLabel(epoch_encryption_key, "key",
///                                       encryption_key, AEAD.Nk)
/// derivation_info_nonce = ExpandWithLabel(epoch_encryption_key, "nonce",
///                                         encryption_key, AEAD.Nn)
/// ```
///
/// where `encryption_key` is the serialized `encryption_key` field of the
/// LeafNode carrying the derivation info. Every operation produces a fresh
/// leaf encryption key, so each wrap uses a distinct key-nonce pair.
/// Derived from the emulation group's `safe_export_secret(VC_COMPONENT_ID)`
/// by [`MlsGroup::register_vc_emulation_epoch`].
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

impl EpochEncryptionKey {
    /// Derive the AEAD key and nonce for one [`DerivationInfoTbe`] wrap,
    /// using the serialized `encryption_key` of the carrying leaf as the
    /// `ExpandWithLabel` context.
    fn derive_key_nonce(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        leaf_encryption_key: &[u8],
    ) -> Result<(Secret, Secret), VirtualClientsError> {
        let key = self.0.kdf_expand_label(
            crypto,
            ciphersuite,
            DERIVATION_INFO_KEY_LABEL,
            leaf_encryption_key,
            ciphersuite.aead_key_length(),
        )?;
        let nonce = self.0.kdf_expand_label(
            crypto,
            ciphersuite,
            DERIVATION_INFO_NONCE_LABEL,
            leaf_encryption_key,
            ciphersuite.aead_nonce_length(),
        )?;
        Ok((key, nonce))
    }
}

/// Per-emulation-epoch state persisted by
/// [`MlsGroup::register_vc_emulation_epoch`] alongside the per-epoch
/// operation secret tree, keyed by [`EpochId`]. Bundles everything the
/// library needs to emit a VC commit for this epoch and to XOR application
/// message nonces with deterministic reuse guards.
///
/// [`MlsGroup::register_vc_emulation_epoch`]:
///     crate::group::MlsGroup::register_vc_emulation_epoch
#[derive(Debug, Serialize, Deserialize)]
pub struct EmulationEpochState {
    /// The registering client's leaf index in the emulation group at
    /// registration time. Sent in `DerivationInfoTbe` and used as the
    /// sender's `leaf_index_e` in the reuse-guard derivation.
    pub(crate) leaf_index: LeafNodeIndex,
    pub(crate) epoch_encryption_key: EpochEncryptionKey,
    pub(crate) reuse_guard_secret: ReuseGuardSecret,
    /// Stored now but not yet read. The generation-ID derivation that
    /// consumes it is deferred to a follow-up PR (see [`GenerationIdSecret`]).
    pub(crate) generation_id_secret: GenerationIdSecret,
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
        generation_id_secret: GenerationIdSecret,
        emulation_group_size: TreeSize,
        emulation_ciphersuite: Ciphersuite,
    ) -> Self {
        Self {
            leaf_index,
            epoch_encryption_key,
            reuse_guard_secret,
            generation_id_secret,
            emulation_group_size,
            emulation_ciphersuite,
        }
    }

    /// Consume the state and return the fields needed by the
    /// commit-builder / commit-processing paths.
    pub(crate) fn into_parts(self) -> (LeafNodeIndex, EpochEncryptionKey, Ciphersuite) {
        (
            self.leaf_index,
            self.epoch_encryption_key,
            self.emulation_ciphersuite,
        )
    }

    /// Borrow the per-message inputs the framing layer needs to derive
    /// the PRP key and pick `x` for a reuse guard.
    pub(crate) fn reuse_guard_inputs(&self) -> crate::framing::EmulatorReuseGuardCtx<'_> {
        crate::framing::EmulatorReuseGuardCtx {
            reuse_guard_secret: &self.reuse_guard_secret,
            emulation_ciphersuite: self.emulation_ciphersuite,
            emulation_group_size: self.emulation_group_size,
            emulation_leaf_index: self.leaf_index,
        }
    }
}

/// Per-operation secret from which the material for a single virtual-clients
/// operation (commit path, key package, application message) is derived.
/// Produced by the per-epoch Virtual Client Operation Secret Tree
/// ([`OperationSecretTree`]). Sender and receiver derive the same value
/// from the same per-epoch state.
///
/// [`OperationSecretTree`]: crate::components::vc_operation_tree::OperationSecretTree
#[derive(Serialize, Deserialize)]
pub struct OperationSecret(Secret);

impl std::fmt::Debug for OperationSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperationSecret")
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl From<Secret> for OperationSecret {
    fn from(secret: Secret) -> Self {
        Self(secret)
    }
}

impl OperationSecret {
    /// Test-only accessor for comparing derived operation secrets.
    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub(crate) fn derive_encryption_key_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<EncryptionKeySecret, VirtualClientsError> {
        let encryption_key_secret =
            self.0
                .derive_secret(crypto, ciphersuite, ENCRYPTION_KEY_LABEL)?;
        Ok(EncryptionKeySecret(encryption_key_secret))
    }

    pub(crate) fn derive_path_generation_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<PathGenerationSecret, VirtualClientsError> {
        let path_generation_secret =
            self.0
                .derive_secret(crypto, ciphersuite, PATH_GENERATION_LABEL)?;
        Ok(PathGenerationSecret(path_generation_secret))
    }

    /// Derive the per-KeyPackage seed secret for the KeyPackage at
    /// `key_package_index` within this operation's batch:
    ///
    /// ```text
    /// key_package_seed_secret = ExpandWithLabel(operation_secret,
    ///                                           "key package seed",
    ///                                           KeyPackageSeedContext, Kdf.Nh)
    /// ```
    ///
    /// The KeyPackage's init and leaf-encryption keys are then derived from the
    /// returned [`KeyPackageSeedSecret`], not from the operation secret
    /// directly, so a single `key_package` operation secret can cover a batch
    /// of KeyPackages with distinct key material.
    pub(crate) fn derive_key_package_seed_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        key_package_index: u32,
    ) -> Result<KeyPackageSeedSecret, VirtualClientsError> {
        let context = KeyPackageSeedContext { key_package_index }.tls_serialize_detached()?;
        let seed = self.0.kdf_expand_label(
            crypto,
            ciphersuite,
            KEY_PACKAGE_SEED_LABEL,
            &context,
            ciphersuite.hash_length(),
        )?;
        Ok(KeyPackageSeedSecret(seed))
    }
}

/// `ExpandWithLabel` context for [`OperationSecret::derive_key_package_seed_secret`]
/// (mls-virtual-clients draft):
///
/// ```text
/// struct {
///   uint32 key_package_index;
/// } KeyPackageSeedContext
/// ```
///
/// Only ever serialized as a derivation context, never parsed back, so it
/// needs serialization only.
#[derive(Debug, TlsSize, TlsSerialize)]
struct KeyPackageSeedContext {
    key_package_index: u32,
}

/// Per-KeyPackage seed secret from which a single KeyPackage's init and
/// leaf-encryption keys are derived. Produced by
/// `OperationSecret::derive_key_package_seed_secret` for one index within a
/// `key_package` operation's batch. Persisted in [`RetainedKeyPackageMaterial`]
/// so the Welcome path can rederive the keys without re-walking the operation
/// tree.
#[derive(Serialize, Deserialize)]
pub struct KeyPackageSeedSecret(Secret);

impl std::fmt::Debug for KeyPackageSeedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPackageSeedSecret")
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl KeyPackageSeedSecret {
    pub(crate) fn derive_init_key_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<InitKeySecret, VirtualClientsError> {
        let init_key_secret = self.0.derive_secret(crypto, ciphersuite, INIT_KEY_LABEL)?;
        Ok(InitKeySecret(init_key_secret))
    }

    pub(crate) fn derive_encryption_key_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<EncryptionKeySecret, VirtualClientsError> {
        let encryption_key_secret =
            self.0
                .derive_secret(crypto, ciphersuite, ENCRYPTION_KEY_LABEL)?;
        Ok(EncryptionKeySecret(encryption_key_secret))
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
        let key_pair = crypto.derive_hpke_keypair(hpke_config, self.0.as_slice())?;
        Ok(EncryptionKeyPair::from(key_pair))
    }
}

pub(crate) struct InitKeySecret(Secret);

impl InitKeySecret {
    pub(crate) fn generate_init_key_pair(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<openmls_traits::types::HpkeKeyPair, VirtualClientsError> {
        let hpke_config = ciphersuite.hpke_config();
        let key_pair = crypto.derive_hpke_keypair(hpke_config, self.0.as_slice())?;
        Ok(key_pair)
    }
}

pub(crate) struct PathGenerationSecret(Secret);

impl From<PathGenerationSecret> for PathSecret {
    fn from(value: PathGenerationSecret) -> Self {
        value.0.into()
    }
}

/// What virtual-clients operation a per-operation secret is being derived
/// for (mls-virtual-clients draft `VirtualClientOperationType`). Mixed into
/// the `OperationContext` of every operation-secret derivation so that
/// secrets derived for different operations cannot collide even if the other
/// fields happen to match.
///
/// The operation type does not travel on the wire. Receivers infer it from
/// the carrying LeafNode's `leaf_node_source`: `key_package` maps to
/// [`KeyPackage`](Self::KeyPackage), `update` and `commit` map to
/// [`LeafNode`](Self::LeafNode).
///
/// Only `LeafNode` is wired into a sender path today (see `apply_vc_emulation`
/// in the commit builder). `KeyPackage` and `Application` are reserved
/// variants that a follow-up PR will emit, once the KeyPackage and
/// application-message operation paths exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TlsSize, TlsSerialize, TlsDeserializeBytes)]
#[repr(u8)]
pub enum VirtualClientOperationType {
    /// Derivation of KeyPackage material for the virtual client.
    KeyPackage = 1,
    /// Derivation of LeafNode material for the virtual client (e.g. the
    /// leaf carried by a commit).
    LeafNode = 2,
    /// Derivation of application-message material for the virtual client.
    Application = 3,
}

/// AEAD plaintext attached to the leaf via the VC component
/// (mls-virtual-clients draft):
///
/// ```text
/// struct {
///   uint32 leaf_index;
///   uint32 generation;
///   select (LeafNode.leaf_node_source) {
///     case key_package:  uint32 key_package_index;
///     case update:
///     case commit:       struct{};
///   };
/// } DerivationInfoTBE
/// ```
///
/// `leaf_index` is the *emulation*-group leaf index of the sending virtual
/// client, *not* the leaf index in the group that carries this commit.
/// `generation` is the operation-ratchet generation the sender consumed for
/// this operation. `key_package_index`, present only for the `KeyPackage`
/// variant, is the KeyPackage's position within its `key_package` operation
/// batch.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DerivationInfoTbe {
    /// Carried by `update` and `commit` leaves. No `key_package_index`.
    LeafNode {
        leaf_index: LeafNodeIndex,
        generation: u32,
    },
    /// Carried by `key_package` leaves. Adds the position within the batch.
    KeyPackage {
        leaf_index: LeafNodeIndex,
        generation: u32,
        key_package_index: u32,
    },
}

impl DerivationInfoTbe {
    /// The emulation-group leaf index of the sending virtual client.
    pub(crate) fn leaf_index(&self) -> LeafNodeIndex {
        match self {
            Self::LeafNode { leaf_index, .. } | Self::KeyPackage { leaf_index, .. } => *leaf_index,
        }
    }

    /// The operation-ratchet generation the sender consumed.
    pub(crate) fn generation(&self) -> u32 {
        match self {
            Self::LeafNode { generation, .. } | Self::KeyPackage { generation, .. } => *generation,
        }
    }

    /// Serialize the variant's fields in order, with no variant tag, matching
    /// the `DerivationInfoTBE` select. The TLS derive macros cannot express a
    /// tagless select, so this codec is written by hand.
    fn tls_serialize_detached(&self) -> Result<Vec<u8>, tls_codec::Error> {
        let mut out = Vec::new();
        match self {
            Self::LeafNode {
                leaf_index,
                generation,
            } => {
                leaf_index.tls_serialize(&mut out)?;
                generation.tls_serialize(&mut out)?;
            }
            Self::KeyPackage {
                leaf_index,
                generation,
                key_package_index,
            } => {
                leaf_index.tls_serialize(&mut out)?;
                generation.tls_serialize(&mut out)?;
                key_package_index.tls_serialize(&mut out)?;
            }
        }
        Ok(out)
    }

    /// Deserialize the tagless select for the given operation type. The
    /// operation type stands in for the carrying leaf's `leaf_node_source`:
    /// [`KeyPackage`](VirtualClientOperationType::KeyPackage) parses the
    /// `KeyPackage` variant, [`LeafNode`](VirtualClientOperationType::LeafNode)
    /// the `LeafNode` variant. The plaintext must be consumed exactly.
    fn deserialize_for_operation(
        bytes: &[u8],
        operation_type: VirtualClientOperationType,
    ) -> Result<Self, VirtualClientsError> {
        let (leaf_index, rest) = LeafNodeIndex::tls_deserialize_bytes(bytes)?;
        let (generation, rest) = u32::tls_deserialize_bytes(rest)?;
        let tbe = match operation_type {
            VirtualClientOperationType::KeyPackage => {
                let (key_package_index, rest) = u32::tls_deserialize_bytes(rest)?;
                if !rest.is_empty() {
                    return Err(VirtualClientsError::DerivationInfoMalformed);
                }
                Self::KeyPackage {
                    leaf_index,
                    generation,
                    key_package_index,
                }
            }
            VirtualClientOperationType::LeafNode => {
                if !rest.is_empty() {
                    return Err(VirtualClientsError::DerivationInfoMalformed);
                }
                Self::LeafNode {
                    leaf_index,
                    generation,
                }
            }
            VirtualClientOperationType::Application => {
                return Err(VirtualClientsError::DerivationInfoMalformed);
            }
        };
        Ok(tbe)
    }
}

/// Verify that the effective leaf about to carry a VC derivation-info entry
/// declares `AppDataDictionary` and lists [`VC_COMPONENT_ID`] in its
/// `AppComponents` entry, and return the resolved `AppDataDictionary`.
///
/// `caller_capabilities` and `caller_extensions` are the leaf parameters the
/// caller supplied for this operation. `current_leaf` is the leaf being
/// replaced, or `None` when there is none (a fresh KeyPackage, or an external
/// commit). The caller's `AppDataDictionary` is merged over the current
/// leaf's, with the caller winning on duplicate component ids, so injecting
/// the VC derivation-info preserves the `AppComponents` entry across
/// operations.
pub(crate) fn resolve_vc_leaf_dictionary(
    caller_capabilities: Option<&crate::treesync::node::leaf_node::Capabilities>,
    caller_extensions: Option<
        &crate::extensions::Extensions<crate::treesync::node::leaf_node::LeafNode>,
    >,
    current_leaf: Option<&crate::treesync::node::leaf_node::LeafNode>,
) -> Result<crate::extensions::AppDataDictionary, VirtualClientsError> {
    use crate::{
        component::{ComponentId, ComponentType},
        extensions::ExtensionType,
    };
    use tls_codec::DeserializeBytes as _;

    let supports_app_data_dictionary = match caller_capabilities {
        Some(c) => c.extensions().contains(&ExtensionType::AppDataDictionary),
        None => current_leaf
            .map(|leaf| {
                leaf.capabilities()
                    .extensions()
                    .contains(&ExtensionType::AppDataDictionary)
            })
            .unwrap_or(false),
    };
    if !supports_app_data_dictionary {
        return Err(VirtualClientsError::AppDataDictionaryNotSupported);
    }

    let mut resolved_dictionary = current_leaf
        .and_then(|leaf| leaf.extensions().app_data_dictionary())
        .map(|ext| ext.dictionary().clone())
        .unwrap_or_default();
    if let Some(caller_dict) = caller_extensions.and_then(|exts| exts.app_data_dictionary()) {
        for entry in caller_dict.dictionary().entries() {
            resolved_dictionary.insert(entry.id(), entry.data().to_vec());
        }
    }

    let app_components_bytes = resolved_dictionary
        .get(&ComponentId::from(ComponentType::AppComponents))
        .map(<[u8]>::to_vec);
    let Some(app_components_bytes) = app_components_bytes else {
        return Err(VirtualClientsError::VcComponentNotListed);
    };

    // The AppComponents body is `ComponentID supported_components<V>`, i.e.
    // a TLS-encoded variable-length vector of u16.
    let supported_components = Vec::<u16>::tls_deserialize_exact_bytes(&app_components_bytes)
        .map_err(|e| {
            log::error!("vc: AppComponents body failed to deserialize: {e:?}");
            VirtualClientsError::VcComponentNotListed
        })?;
    if !supported_components.contains(&VC_COMPONENT_ID) {
        return Err(VirtualClientsError::VcComponentNotListed);
    }

    Ok(resolved_dictionary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_rust_crypto::{MemoryStorage, OpenMlsRustCrypto};
    use openmls_traits::{
        random::OpenMlsRand,
        storage::{StorageProvider, CURRENT_VERSION},
        OpenMlsProvider,
    };

    const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    /// Register a full `EmulationEpochState` and a matching
    /// `OperationSecretTree` for a fresh epoch, returning the derived
    /// `EpochId` and the leaf index it was registered with.
    fn register_epoch_state(provider: &OpenMlsRustCrypto, leaf_index: LeafNodeIndex) -> EpochId {
        use crate::components::vc_operation_tree::OperationSecretTree;

        let emulator = EmulatorEpochSecret::new(
            &provider
                .rand()
                .random_vec(CIPHERSUITE.hash_length())
                .expect("randomness"),
        );
        let epoch_id = emulator
            .derive_epoch_id(provider.crypto(), CIPHERSUITE)
            .expect("derive epoch id");
        let epoch_encryption_key = emulator
            .derive_epoch_encryption_key(provider.crypto(), CIPHERSUITE)
            .expect("derive epoch encryption key");
        let reuse_guard_secret = emulator
            .derive_reuse_guard_secret(provider.crypto(), CIPHERSUITE)
            .expect("derive reuse guard secret");
        let generation_id_secret = emulator
            .derive_generation_id_secret(provider.crypto(), CIPHERSUITE)
            .expect("derive generation id secret");
        let epoch_base_secret = emulator
            .derive_epoch_base_secret(provider.crypto(), CIPHERSUITE)
            .expect("derive epoch base secret");
        let emulation_group_size = TreeSize::new(2);
        let state = EmulationEpochState::new(
            leaf_index,
            epoch_encryption_key,
            reuse_guard_secret,
            generation_id_secret,
            emulation_group_size,
            CIPHERSUITE,
        );
        <MemoryStorage as StorageProvider<CURRENT_VERSION>>::write_vc_emulation_epoch_state(
            provider.storage(),
            &epoch_id,
            &state,
        )
        .expect("write emulation epoch state");
        let operation_tree = OperationSecretTree::new(epoch_base_secret, emulation_group_size);
        <MemoryStorage as StorageProvider<CURRENT_VERSION>>::write_vc_operation_tree(
            provider.storage(),
            &epoch_id,
            &operation_tree,
        )
        .expect("write operation tree");
        epoch_id
    }

    /// The assembly helper fills `leaf_index` from the registered
    /// `EmulationEpochState` for the epoch.
    #[test]
    fn assemble_upload_reads_leaf_index_from_state() {
        let provider = OpenMlsRustCrypto::default();
        let leaf_index = LeafNodeIndex::new(5);
        let epoch_id = register_epoch_state(&provider, leaf_index);
        let infos = vec![
            KeyPackageInfo {
                key_package_ref: KeyPackageRef::from_slice(b"kp-ref-a"),
                key_package_index: 0,
            },
            KeyPackageInfo {
                key_package_ref: KeyPackageRef::from_slice(b"kp-ref-b"),
                key_package_index: 1,
            },
        ];

        let upload = assemble_vc_key_package_upload(provider.storage(), epoch_id.clone(), 4, infos)
            .expect("assemble upload");

        assert_eq!(upload.epoch_id, epoch_id);
        assert_eq!(upload.leaf_index, leaf_index);
        assert_eq!(upload.generation, 4);
        assert_eq!(upload.key_package_info.len(), 2);
    }

    /// Assembling for an unregistered epoch fails with
    /// `MissingEmulationEpochState`.
    #[test]
    fn assemble_upload_without_state_fails() {
        let provider = OpenMlsRustCrypto::default();
        let epoch_id = EpochId(b"unregistered-epoch".to_vec().into());
        let err = assemble_vc_key_package_upload(provider.storage(), epoch_id, 0, Vec::new())
            .expect_err("assemble must fail without registered state");
        assert_eq!(err, VirtualClientsError::MissingEmulationEpochState);
    }

    /// `process_vc_key_package_upload` stores one material entry per info,
    /// readable back via `retained_key_package_material` keyed by the
    /// KeyPackage reference, each carrying its own batch index.
    #[test]
    fn process_upload_stores_records() {
        let provider = OpenMlsRustCrypto::default();
        let leaf_index = LeafNodeIndex::new(0);
        let epoch_id = register_epoch_state(&provider, leaf_index);
        let ref_a = KeyPackageRef::from_slice(b"kp-ref-a");
        let ref_b = KeyPackageRef::from_slice(b"kp-ref-b");
        let upload = KeyPackageUpload {
            epoch_id: epoch_id.clone(),
            leaf_index,
            generation: 0,
            key_package_info: vec![
                KeyPackageInfo {
                    key_package_ref: ref_a.clone(),
                    key_package_index: 0,
                },
                KeyPackageInfo {
                    key_package_ref: ref_b.clone(),
                    key_package_index: 1,
                },
            ],
        };

        process_vc_key_package_upload(&provider, &upload).expect("process upload");

        let material_a: RetainedKeyPackageMaterial = <MemoryStorage as StorageProvider<
            CURRENT_VERSION,
        >>::retained_key_package_material(
            provider.storage(), &ref_a
        )
        .expect("read material a")
        .expect("material a present");
        assert_eq!(material_a.epoch_id, epoch_id);
        assert_eq!(material_a.leaf_index, leaf_index);
        assert_eq!(material_a.generation, 0);
        assert_eq!(material_a.key_package_index, 0);

        let material_b: RetainedKeyPackageMaterial = <MemoryStorage as StorageProvider<
            CURRENT_VERSION,
        >>::retained_key_package_material(
            provider.storage(), &ref_b
        )
        .expect("read material b")
        .expect("material b present");
        assert_eq!(material_b.epoch_id, epoch_id);
        assert_eq!(material_b.leaf_index, leaf_index);
        assert_eq!(material_b.generation, 0);
        assert_eq!(material_b.key_package_index, 1);
    }

    /// `delete_key_package` removes the associated retained VC material.
    #[test]
    fn delete_key_package_removes_vc_record() {
        let provider = OpenMlsRustCrypto::default();
        let leaf_index = LeafNodeIndex::new(0);
        let epoch_id = register_epoch_state(&provider, leaf_index);
        let kp_ref = KeyPackageRef::from_slice(b"kp-ref");
        let upload = KeyPackageUpload {
            epoch_id,
            leaf_index,
            generation: 0,
            key_package_info: vec![KeyPackageInfo {
                key_package_ref: kp_ref.clone(),
                key_package_index: 0,
            }],
        };
        process_vc_key_package_upload(&provider, &upload).expect("process upload");

        let present: Option<RetainedKeyPackageMaterial> = <MemoryStorage as StorageProvider<
            CURRENT_VERSION,
        >>::retained_key_package_material(
            provider.storage(), &kp_ref
        )
        .expect("read material");
        assert!(present.is_some());

        <MemoryStorage as StorageProvider<CURRENT_VERSION>>::delete_key_package(
            provider.storage(),
            &kp_ref,
        )
        .expect("delete key package");

        let after: Option<RetainedKeyPackageMaterial> = <MemoryStorage as StorageProvider<
            CURRENT_VERSION,
        >>::retained_key_package_material(
            provider.storage(), &kp_ref
        )
        .expect("read material after delete");
        assert!(after.is_none());
    }

    fn setup_key_and_epoch_id(provider: &OpenMlsRustCrypto) -> (EpochEncryptionKey, EpochId) {
        let emulator = EmulatorEpochSecret::new(
            &provider
                .rand()
                .random_vec(CIPHERSUITE.hash_length())
                .expect("randomness"),
        );
        let key = emulator
            .derive_epoch_encryption_key(provider.crypto(), CIPHERSUITE)
            .expect("derive ek");
        let epoch_id = emulator
            .derive_epoch_id(provider.crypto(), CIPHERSUITE)
            .expect("derive epoch id");
        (key, epoch_id)
    }

    /// Round-trip both `DerivationInfoTbe` variants through `encrypt` and
    /// `decrypt`. Catches any disagreement between the two methods on the
    /// derived key/nonce, the AAD, or the tagless TLS layout of the
    /// plaintext, and confirms each variant decodes only under its own
    /// operation type.
    #[test]
    fn derivation_info_tbe_roundtrip() {
        let provider = OpenMlsRustCrypto::default();
        let (key, epoch_id) = setup_key_and_epoch_id(&provider);
        let leaf_encryption_key = provider.rand().random_vec(32).expect("randomness");

        let key_package_tbe = DerivationInfoTbe::KeyPackage {
            leaf_index: LeafNodeIndex::new(7),
            generation: 3,
            key_package_index: 5,
        };
        let leaf_node_tbe = DerivationInfoTbe::LeafNode {
            leaf_index: LeafNodeIndex::new(7),
            generation: 3,
        };

        // The leaf_node form omits the trailing key_package_index, so its
        // plaintext is exactly four bytes shorter.
        let key_package_bytes = key_package_tbe
            .tls_serialize_detached()
            .expect("serialize key package tbe");
        let leaf_node_bytes = leaf_node_tbe
            .tls_serialize_detached()
            .expect("serialize leaf node tbe");
        assert_eq!(key_package_bytes.len(), leaf_node_bytes.len() + 4);

        for (original, operation_type) in [
            (key_package_tbe, VirtualClientOperationType::KeyPackage),
            (leaf_node_tbe, VirtualClientOperationType::LeafNode),
        ] {
            let derivation_info = DerivationInfo::encrypt(
                provider.crypto(),
                CIPHERSUITE,
                &key,
                epoch_id.clone(),
                &leaf_encryption_key,
                &original,
            )
            .expect("encrypt");
            assert_eq!(derivation_info.epoch_id(), &epoch_id);
            let decrypted = derivation_info
                .decrypt(
                    provider.crypto(),
                    CIPHERSUITE,
                    &key,
                    &leaf_encryption_key,
                    operation_type,
                )
                .expect("decrypt");
            assert_eq!(original, decrypted);
        }
    }

    /// Decryption must fail when the leaf encryption key used as the
    /// key/nonce derivation context does not match the one used for
    /// encryption. This is what binds the derivation info to the leaf
    /// that carries it.
    #[test]
    fn decryption_fails_with_wrong_leaf_encryption_key() {
        let provider = OpenMlsRustCrypto::default();
        let (key, epoch_id) = setup_key_and_epoch_id(&provider);
        let leaf_encryption_key = provider.rand().random_vec(32).expect("randomness");
        let tbe = DerivationInfoTbe::LeafNode {
            leaf_index: LeafNodeIndex::new(1),
            generation: 0,
        };
        let derivation_info = DerivationInfo::encrypt(
            provider.crypto(),
            CIPHERSUITE,
            &key,
            epoch_id,
            &leaf_encryption_key,
            &tbe,
        )
        .expect("encrypt");
        let other_leaf_encryption_key = provider.rand().random_vec(32).expect("randomness");
        let err = derivation_info
            .decrypt(
                provider.crypto(),
                CIPHERSUITE,
                &key,
                &other_leaf_encryption_key,
                VirtualClientOperationType::LeafNode,
            )
            .expect_err("decryption with the wrong context must fail");
        assert_eq!(err, VirtualClientsError::DerivationInfoDecryptionFailed);
    }

    /// The per-KeyPackage seed secret is deterministic for a given index,
    /// distinct across indices, and the init and encryption keys derived from
    /// one seed are separated from each other.
    #[test]
    fn key_package_seed_derivation_is_indexed_and_label_separated() {
        let provider = OpenMlsRustCrypto::default();
        let operation_secret = OperationSecret::from(Secret::from_slice(
            &provider
                .rand()
                .random_vec(CIPHERSUITE.hash_length())
                .expect("randomness"),
        ));

        let seed_zero = operation_secret
            .derive_key_package_seed_secret(provider.crypto(), CIPHERSUITE, 0)
            .expect("derive seed 0");
        let seed_zero_again = operation_secret
            .derive_key_package_seed_secret(provider.crypto(), CIPHERSUITE, 0)
            .expect("derive seed 0 again");
        let seed_one = operation_secret
            .derive_key_package_seed_secret(provider.crypto(), CIPHERSUITE, 1)
            .expect("derive seed 1");

        let init_zero = seed_zero
            .derive_init_key_secret(provider.crypto(), CIPHERSUITE)
            .expect("derive init key 0")
            .generate_init_key_pair(provider.crypto(), CIPHERSUITE)
            .expect("generate init pair 0");
        let init_zero_again = seed_zero_again
            .derive_init_key_secret(provider.crypto(), CIPHERSUITE)
            .expect("derive init key 0 again")
            .generate_init_key_pair(provider.crypto(), CIPHERSUITE)
            .expect("generate init pair 0 again");
        let init_one = seed_one
            .derive_init_key_secret(provider.crypto(), CIPHERSUITE)
            .expect("derive init key 1")
            .generate_init_key_pair(provider.crypto(), CIPHERSUITE)
            .expect("generate init pair 1");

        // Same index derives deterministically.
        assert_eq!(init_zero.public, init_zero_again.public);
        // Different indices derive distinct seeds, hence distinct init keys.
        assert_ne!(init_zero.public, init_one.public);

        // Init and encryption keys from one seed are label-separated.
        let encryption_zero = seed_zero
            .derive_encryption_key_secret(provider.crypto(), CIPHERSUITE)
            .expect("derive encryption key 0")
            .generate_encryption_key_pair(provider.crypto(), CIPHERSUITE)
            .expect("generate encryption pair 0");
        assert_ne!(
            init_zero.public.as_slice(),
            encryption_zero.public_key().as_slice()
        );
    }

    /// A repeated `key_package_index` is rejected with
    /// `DuplicateKeyPackageIndex` carrying the offending index.
    #[test]
    fn validate_rejects_duplicate_index() {
        let infos = vec![
            KeyPackageInfo {
                key_package_ref: KeyPackageRef::from_slice(b"kp-ref-a"),
                key_package_index: 2,
            },
            KeyPackageInfo {
                key_package_ref: KeyPackageRef::from_slice(b"kp-ref-b"),
                key_package_index: 2,
            },
        ];
        let err = validate_key_package_infos(&infos).expect_err("duplicate index must be rejected");
        assert_eq!(err, VirtualClientsError::DuplicateKeyPackageIndex(2));
    }

    /// A repeated `KeyPackageRef` is rejected with `DuplicateKeyPackageRef`.
    #[test]
    fn validate_rejects_duplicate_ref() {
        let infos = vec![
            KeyPackageInfo {
                key_package_ref: KeyPackageRef::from_slice(b"kp-ref-a"),
                key_package_index: 0,
            },
            KeyPackageInfo {
                key_package_ref: KeyPackageRef::from_slice(b"kp-ref-a"),
                key_package_index: 1,
            },
        ];
        let err = validate_key_package_infos(&infos).expect_err("duplicate ref must be rejected");
        assert_eq!(err, VirtualClientsError::DuplicateKeyPackageRef);
    }

    /// A batch with distinct indices and references passes validation.
    #[test]
    fn validate_accepts_distinct_infos() {
        let infos = vec![
            KeyPackageInfo {
                key_package_ref: KeyPackageRef::from_slice(b"kp-ref-a"),
                key_package_index: 0,
            },
            KeyPackageInfo {
                key_package_ref: KeyPackageRef::from_slice(b"kp-ref-b"),
                key_package_index: 1,
            },
        ];
        validate_key_package_infos(&infos).expect("distinct infos must pass");
    }

    /// A malformed upload is rejected before the batch generation is consumed,
    /// so a later valid upload reusing the same generation still succeeds and
    /// stores its retained material.
    #[test]
    fn process_upload_rejects_malformed_without_consuming_generation() {
        let provider = OpenMlsRustCrypto::default();
        let leaf_index = LeafNodeIndex::new(0);
        let epoch_id = register_epoch_state(&provider, leaf_index);
        let ref_a = KeyPackageRef::from_slice(b"kp-ref-a");
        let ref_b = KeyPackageRef::from_slice(b"kp-ref-b");

        let malformed = KeyPackageUpload {
            epoch_id: epoch_id.clone(),
            leaf_index,
            generation: 0,
            key_package_info: vec![
                KeyPackageInfo {
                    key_package_ref: ref_a.clone(),
                    key_package_index: 0,
                },
                KeyPackageInfo {
                    key_package_ref: ref_b.clone(),
                    key_package_index: 0,
                },
            ],
        };
        let err = process_vc_key_package_upload(&provider, &malformed)
            .expect_err("malformed upload must be rejected");
        assert_eq!(err, VirtualClientsError::DuplicateKeyPackageIndex(0));

        let valid = KeyPackageUpload {
            epoch_id: epoch_id.clone(),
            leaf_index,
            generation: 0,
            key_package_info: vec![
                KeyPackageInfo {
                    key_package_ref: ref_a.clone(),
                    key_package_index: 0,
                },
                KeyPackageInfo {
                    key_package_ref: ref_b.clone(),
                    key_package_index: 1,
                },
            ],
        };
        process_vc_key_package_upload(&provider, &valid)
            .expect("valid upload reusing the same generation must succeed");

        let material_a: RetainedKeyPackageMaterial = <MemoryStorage as StorageProvider<
            CURRENT_VERSION,
        >>::retained_key_package_material(
            provider.storage(), &ref_a
        )
        .expect("read material a")
        .expect("material a present");
        assert_eq!(material_a.epoch_id, epoch_id);
        assert_eq!(material_a.generation, 0);
        assert_eq!(material_a.key_package_index, 0);

        let material_b: RetainedKeyPackageMaterial = <MemoryStorage as StorageProvider<
            CURRENT_VERSION,
        >>::retained_key_package_material(
            provider.storage(), &ref_b
        )
        .expect("read material b")
        .expect("material b present");
        assert_eq!(material_b.key_package_index, 1);
    }
}
