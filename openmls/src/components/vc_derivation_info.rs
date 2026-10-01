use std::collections::{BTreeSet, VecDeque};
#[cfg(not(target_arch = "wasm32"))]
use std::time::SystemTime;

use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, CryptoError},
    OpenMlsProvider,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tls_codec::{
    DeserializeBytes, SecretVLByteVec, Serialize as _, Size as _, TlsDeserializeBytes,
    TlsSerialize, TlsSize, VLByteSlice, VLByteVec,
};
#[cfg(target_arch = "wasm32")]
use web_time::SystemTime;

use crate::{
    binary_tree::{array_representation::TreeSize, LeafNodeIndex},
    ciphersuite::{hash_ref::KeyPackageRef, Secret},
    components::vc_operation_tree::OperationSecretTree,
    group::{
        mls_group::errors::RegisterVcDerivationEpochError, GroupEpoch, GroupId,
        VcDerivationEpochRetentionPolicy,
    },
    key_packages::InitKey,
    messages::PathSecret,
    schedule::application_export_tree::{ApplicationExportTree, ApplicationExportTreeError},
    treesync::node::encryption_keys::EncryptionKeyPair,
};

/// Component ID under which the virtual-clients derivation info is carried in
/// the leaf node's `app_data_dictionary` extension.
///
/// `0x667A` is the temporary, random value until the draft is further along the
/// publication process.
pub const VC_COMPONENT_ID: u16 = 0x667A;

// Operation-secret child labels. Each child is derived from the per-operation
// secret produced by the per-epoch operation secret tree. `Encryption Key`
// and `Path Generation` cover the `leaf_node` commit path, and `Init Key`
// covers the `key_package` operation path. The spec also defines a
// `Signature Key` child, which together with the operation paths that consume
// it is deferred to a follow-up PR.
const ENCRYPTION_KEY_LABEL: &str = "Encryption Key";
const PATH_GENERATION_LABEL: &str = "Path Generation";
const INIT_KEY_LABEL: &str = "Init Key";
/// `ImportSecret` label for the per-KeyPackage seed secret derived from a
/// `key_package` operation secret (mls-virtual-clients draft, batch KeyPackage
/// derivation). One operation secret covers a batch of KeyPackages, and each
/// KeyPackage's seed is imported from it using the KeyPackage's ciphersuite
/// and index as the context.
const KEY_PACKAGE_SEED_LABEL: &str = "vc key package seed";
/// `ImportSecret` label for `target_operation_secret` of a `leaf_node`:
/// imports operation secret into the higher-level group's ciphersuite.
const TARGET_OPERATION_LABEL: &str = "vc target operation";
/// `DeriveSecret` label for the epoch-0 `epoch_secret` a group creator derives
/// from its KeyPackage seed secret (mls-virtual-clients draft, group creation).
const GROUP_CREATION_LABEL: &str = "Group Creation";

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
/// `ExpandWithLabel` label for a [`GenerationId`] derived from a
/// [`GenerationIdSecret`] over a serialized [`PrivateMessageContext`]
/// (mls-virtual-clients draft, generation-ID section).
const GENERATION_ID_EXPAND_LABEL: &str = "generation id";
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
    /// No virtual-clients `VcDerivationEpochState` was registered for this
    /// epoch, or it has been deleted.
    #[error("No virtual-clients derivation-epoch state for this epoch.")]
    MissingDerivationEpochState,
    /// No derivation epoch is registered for the group a new virtual-client
    /// operation was resolved against. The operation requires that group to be
    /// an emulation group with a registered derivation epoch.
    #[error("No derivation epoch is registered for the group.")]
    NoDerivationEpoch,
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
    /// The coordinates of a sibling's operation name the calling client's own
    /// leaf index.
    #[error("The operation coordinates name the caller's own leaf index.")]
    OwnLeafIndex,
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

/// Per-derivation-epoch root secret. Sourced internally from the emulation
/// group's `safe_export_secret(VC_COMPONENT_ID)` when a derivation epoch is
/// registered.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct EmulatorEpochSecret(Secret);

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

    /// Derive the per-derivation-epoch [`ReuseGuardSecret`].
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

    /// Derive the per-derivation-epoch [`GenerationIdSecret`].
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

/// Per-derivation-epoch secret used to derive the FF1 PRP key for
/// `reuse_guard` values sent by this virtual client. Derived from
/// [`EmulatorEpochSecret`] via [`EmulatorEpochSecret::derive_reuse_guard_secret`].
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ReuseGuardSecret(Secret);

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
    /// [`VcDerivationEpochState`].
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

/// Per-derivation-epoch secret used to derive generation IDs for DS
/// collision detection (mls-virtual-clients draft, "Coordinating ratchet
/// generations with the DS" section). Derived from [`EmulatorEpochSecret`]
/// via [`EmulatorEpochSecret::derive_generation_id_secret`].
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct GenerationIdSecret(Secret);

impl GenerationIdSecret {
    /// Derive the [`GenerationId`] for a message sent with the given
    /// [`PrivateMessageContext`]:
    ///
    /// ```text
    /// generation_id = ExpandWithLabel(generation_id_secret, "generation id",
    ///                                 PrivateMessageContext, Kdf.Nh)
    /// ```
    ///
    /// `ciphersuite` is the emulation group's ciphersuite, the same one the
    /// `generation_id_secret` was derived under.
    fn derive_generation_id(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        context: &PrivateMessageContext<'_>,
    ) -> Result<GenerationId, VirtualClientsError> {
        let context_bytes = context.tls_serialize_detached()?;
        let generation_id = self.0.kdf_expand_label(
            crypto,
            ciphersuite,
            GENERATION_ID_EXPAND_LABEL,
            &context_bytes,
            ciphersuite.hash_length(),
        )?;
        Ok(GenerationId(generation_id.as_slice().to_vec().into()))
    }
}

/// Which ratchet a `PrivateMessageContext` refers to
/// (mls-virtual-clients draft `RatchetType`):
///
/// ```text
/// enum {
///   reserved(0),
///   application(1),
///   handshake(2),
///   (255)
/// } RatchetType
/// ```
///
/// [`Application`](Self::Application) covers application messages, and
/// [`Handshake`](Self::Handshake) covers proposals and commits framed as
/// PrivateMessages in a higher-level group. Both draw a generation ID from
/// their respective per-leaf ratchet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TlsSize, TlsSerialize)]
#[repr(u8)]
pub enum RatchetType {
    /// The per-leaf application-message ratchet.
    Application = 1,
    /// The per-leaf handshake-message ratchet.
    Handshake = 2,
}

/// Context a [`GenerationId`] is derived over (mls-virtual-clients draft):
///
/// ```text
/// struct {
///   opaque group_id<V>;
///   uint64 epoch;
///   uint32 generation;
///   RatchetType ratchet_type;
/// } PrivateMessageContext
/// ```
///
/// `group_id` and `epoch` identify the higher-level group and its epoch at
/// the time the message is sent, `generation` is the ratchet generation used
/// for encryption, and `ratchet_type` distinguishes the application and
/// handshake ratchets. Only ever serialized as a derivation context, never
/// parsed back, so it borrows its `group_id` and needs serialization only.
#[derive(Debug, TlsSize, TlsSerialize)]
pub(crate) struct PrivateMessageContext<'a> {
    group_id: VLByteSlice<'a>,
    epoch: u64,
    generation: u32,
    ratchet_type: RatchetType,
}

/// A per-message generation ID a virtual client attaches to a fanned-out
/// PrivateMessage so a strongly-consistent DS can detect generation
/// collisions between siblings, per higher-level group, per higher-level
/// group epoch, and per ratchet type (mls-virtual-clients draft).
///
/// Derived from the derivation epoch's `GenerationIdSecret` over a
/// `PrivateMessageContext`. The value is opaque to the application: it is
/// produced by [`MlsGroup::create_unconfirmed_message`] and handed to the DS,
/// which compares it for equality across siblings.
///
/// [`MlsGroup::create_unconfirmed_message`]: crate::group::MlsGroup::create_unconfirmed_message
#[derive(Debug, Clone, PartialEq, Eq, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub struct GenerationId(VLByteVec);

impl GenerationId {
    /// The raw generation-ID bytes the application hands to the DS.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
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
    ciphertext: VLByteVec,
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

/// Identifier of a derivation epoch's registered virtual-clients state.
/// Derived deterministically from the emulation group's
/// `safe_export_secret(VC_COMPONENT_ID)`, so every emulator client of a virtual
/// client arrives at the same value for a given derivation epoch.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    TlsSize,
    TlsSerialize,
    TlsDeserializeBytes,
)]
pub struct EpochId(VLByteVec);

impl EpochId {
    /// Create an epoch ID from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes.into())
    }

    /// The raw epoch-ID bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Wire struct a virtual client hands to a sibling so the sibling can fetch
/// and process the matching KeyPackage (mls-virtual-clients draft):
///
/// ```text
/// struct {
///   opaque key_package_ref<V>;
///   CipherSuite cipher_suite;
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
#[derive(Debug, PartialEq, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub struct KeyPackageInfo {
    /// Hash reference of the virtual client's KeyPackage.
    pub key_package_ref: KeyPackageRef,
    /// Ciphersuite of the virtual client's KeyPackage.
    pub cipher_suite: Ciphersuite,
    /// Position of this KeyPackage within the operation batch.
    pub key_package_index: u32,
}

/// Wire struct a virtual client uploads to a sibling so the sibling learns
/// about the KeyPackages the virtual client published for a derivation epoch
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
/// `epoch_id` identifies the derivation epoch the KeyPackages belong to.
/// `leaf_index` is the uploading client's emulation-group leaf index at that
/// epoch. The receiver stores this leaf index: the KeyPackage operation
/// secret was allocated from the uploader's per-leaf ratchet, so a sibling
/// rederiving the KeyPackage material must walk that same leaf's ratchet, not
/// its own. `generation` is the single `key_package` operation generation
/// consumed for the whole batch. `key_package_info` carries one
/// [`KeyPackageInfo`] per uploaded KeyPackage, each with its index within the
/// batch.
#[derive(Debug, PartialEq, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub struct KeyPackageUpload {
    /// Derivation epoch the uploaded KeyPackages belong to.
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
/// the operation tree: the per-KeyPackage seed secret, plus the derivation
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
    /// Derivation epoch the KeyPackage belongs to.
    pub epoch_id: EpochId,
    /// Uploader's emulation-group leaf index, identifying the operation
    /// ratchet the batch generation was allocated from.
    pub leaf_index: LeafNodeIndex,
    /// Operation-ratchet generation consumed for the whole batch.
    pub generation: u32,
    /// Ciphersuite of the KeyPackage.
    pub key_package_ciphersuite: Ciphersuite,
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
    let mut seen_indices = BTreeSet::new();
    let mut seen_refs = BTreeSet::new();
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
/// [`VcDerivationEpochState`] stored for that epoch.
///
/// The virtual client calls this after building a batch of KeyPackages with
/// [`KeyPackageBuilder::build_vc_batch`] to assemble the message it hands to
/// its sibling. `generation` is the single `key_package` operation generation
/// the batch consumed.
///
/// This describes a completed operation rather than starting a new one, so it
/// takes the epoch explicitly. Pass the `epoch_id` and `generation` the batch
/// reports, not a freshly resolved epoch: the emulation group may have moved on
/// to a newer derivation epoch since the batch was built.
///
/// Returns [`VirtualClientsError::MissingDerivationEpochState`] if no state is
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
    let state: VcDerivationEpochState = storage
        .vc_derivation_epoch_state(&epoch_id)
        .map_err(|e| {
            log::error!("vc: load derivation epoch state in assemble upload failed: {e:?}");
            VirtualClientsError::StorageError
        })?
        .ok_or(VirtualClientsError::MissingDerivationEpochState)?;
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
/// The batch operation secret is derived under the emulation ciphersuite (the
/// operation tree's ciphersuite). Each per-KeyPackage seed is imported from
/// it into the ciphersuite the upload names for this KeyPackage. The init and
/// leaf-encryption keys are later derived from each seed under the same
/// ciphersuite at Welcome time. The operation secret is dropped once all seeds
/// are derived. The batch generation is consumed in the tree exactly once.
pub fn process_vc_key_package_upload<Provider: OpenMlsProvider>(
    provider: &Provider,
    upload: &KeyPackageUpload,
) -> Result<(), VirtualClientsError> {
    use crate::components::vc_operation_tree::OperationSecretTree;
    use openmls_traits::storage::StorageProvider as _;

    validate_key_package_infos(&upload.key_package_info)?;

    let storage = provider.storage();
    let crypto = provider.crypto();

    let state: VcDerivationEpochState = storage
        .vc_derivation_epoch_state(&upload.epoch_id)
        .map_err(|e| {
            log::error!("vc: load derivation epoch state in process upload failed: {e:?}");
            VirtualClientsError::StorageError
        })?
        .ok_or(VirtualClientsError::MissingDerivationEpochState)?;
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
            info.cipher_suite,
            info.key_package_index,
        )?;
        let material = RetainedKeyPackageMaterial {
            epoch_id: upload.epoch_id.clone(),
            leaf_index: upload.leaf_index,
            generation: upload.generation,
            key_package_ciphersuite: info.cipher_suite,
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
    /// Derivation epoch the KeyPackage belongs to.
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
    /// Init key the welcome encrypted group secrets are encrypted with.
    pub(crate) init_key: InitKey,
    /// Leaf encryption keypair derived from the seed, used as the joiner's
    /// leaf keypair.
    pub(crate) encryption_keypair: EncryptionKeyPair,
}

/// One registration in an emulation group's log of derivation epochs, stored
/// as its own row keyed by `(group_id, epoch_id)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VcDerivationEpochLogEntry {
    /// Position of this entry in the group's log, starting at 0.
    pub(crate) sequence: u64,
    /// The emulation group's own epoch at registration time.
    pub(crate) group_epoch: GroupEpoch,
    /// The derivation epoch id derived by that registration.
    pub(crate) epoch_id: EpochId,
    /// When the registration happened, in local wall-clock time.
    pub(crate) registered_at: SystemTime,
}

impl VcDerivationEpochLogEntry {
    /// Convert a [`RegisteredVcDerivationEpoch`] into a log entry. The record
    /// was its group's only registration, so the entry takes sequence 0.
    pub fn from_legacy_record(
        group_epoch: GroupEpoch,
        epoch_id: EpochId,
        registered_at: SystemTime,
    ) -> Self {
        Self {
            sequence: 0,
            group_epoch,
            epoch_id,
            registered_at,
        }
    }

    /// The derivation epoch this entry registered.
    pub fn epoch_id(&self) -> &EpochId {
        &self.epoch_id
    }
}

/// Per-emulation-group log of the derivation epochs the group registered, in
/// registration order with the newest at the back. The newest entry is the
/// derivation epoch all new virtual-client operations of the group resolve to,
/// which may be older than the group's current epoch.
#[derive(Debug, Default)]
pub(crate) struct VcDerivationEpochLog {
    // In registration order, oldest at the front.
    entries: VecDeque<VcDerivationEpochLogEntry>,
}

impl VcDerivationEpochLog {
    /// Reconstruct the log of `group_id` from its stored entries. The log is
    /// empty for a group that never registered a derivation epoch.
    pub(crate) fn load<Storage: crate::storage::StorageProvider>(
        storage: &Storage,
        group_id: &GroupId,
    ) -> Result<Self, Storage::Error> {
        let mut entries: Vec<VcDerivationEpochLogEntry> =
            storage.vc_derivation_epoch_log_entries(group_id)?;
        entries.sort_unstable_by_key(|entry| entry.sequence);
        // Entries are keyed by their epoch id in storage, so a duplicate id
        // cannot come from storage. It would mean two registrations derived
        // the same id, which the exporter derivation excludes.
        debug_assert!(
            entries
                .iter()
                .map(|entry| &entry.epoch_id)
                .collect::<BTreeSet<_>>()
                .len()
                == entries.len(),
            "duplicate derivation epoch id in log"
        );
        Ok(Self {
            entries: entries.into(),
        })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The newest logged registration, or `None` if the log is empty.
    pub(crate) fn newest(&self) -> Option<&VcDerivationEpochLogEntry> {
        self.entries.back()
    }

    /// Append a registration of `epoch_id` for `group_epoch`, timestamped now
    /// and sequenced after the current newest entry. Returns a clone of the
    /// appended entry for the caller to persist.
    fn push(&mut self, group_epoch: GroupEpoch, epoch_id: EpochId) -> VcDerivationEpochLogEntry {
        let sequence = self
            .entries
            .back()
            .map_or(0, |entry| entry.sequence.saturating_add(1));
        let entry = VcDerivationEpochLogEntry {
            sequence,
            group_epoch,
            epoch_id,
            registered_at: SystemTime::now(),
        };
        self.entries.push_back(entry.clone());
        entry
    }

    /// Drop the oldest entries until at most `max_entries` are left, and return
    /// the epochs of the dropped entries. Never drops the newest entry, so the
    /// group keeps a derivation epoch to operate on.
    pub(crate) fn shrink_to(&mut self, max_entries: usize) -> Vec<EpochId> {
        let excess = self.entries.len().saturating_sub(max_entries.max(1));
        self.drop_oldest(excess)
    }

    /// Drop every entry superseded before `cutoff` and return the epochs of
    /// the dropped entries. An entry is superseded when its successor is
    /// registered, so entry `i` goes when entry `i + 1` was registered before
    /// `cutoff`. The newest entry has no successor and never drops.
    pub(crate) fn drop_superseded_before(&mut self, cutoff: SystemTime) -> Vec<EpochId> {
        let count = self
            .entries
            .iter()
            .skip(1)
            .rposition(|successor| successor.registered_at < cutoff)
            .map_or(0, |index| index + 1);
        self.drop_oldest(count)
    }

    /// Drop the `count` oldest entries, keeping the newest one regardless, and
    /// return their epochs. Each epoch appears in at most one entry.
    fn drop_oldest(&mut self, count: usize) -> Vec<EpochId> {
        let droppable = self.entries.len().saturating_sub(1);
        self.entries
            .drain(0..count.min(droppable))
            .map(|entry| entry.epoch_id)
            .collect()
    }
}

/// Registration record of the storage layout that preceded the
/// derivation-epoch log. Only for decoding stored records and converting them
/// with [`VcDerivationEpochLogEntry::from_legacy_record`].
#[deprecated(
    since = "0.9.0",
    note = "migration-only: decode pre-log registration records and convert them with \
            `VcDerivationEpochLogEntry::from_legacy_record`. Will be removed in 0.10.0."
)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegisteredVcDerivationEpoch {
    /// The emulation group's own epoch at registration time.
    pub group_epoch: GroupEpoch,
    /// The derivation epoch id derived by that registration.
    pub epoch_id: EpochId,
}

/// The newest derivation epoch registered for the emulation group
/// `emulation_group_id`, or `None` if none was registered yet.
///
/// Read from storage, so the result reflects the state at the time of the
/// call.
pub(crate) fn newest_vc_derivation_epoch<Storage: crate::storage::StorageProvider>(
    storage: &Storage,
    emulation_group_id: &GroupId,
) -> Result<Option<EpochId>, Storage::Error> {
    let entries: Vec<VcDerivationEpochLogEntry> =
        storage.vc_derivation_epoch_log_entries(emulation_group_id)?;
    Ok(entries
        .into_iter()
        .max_by_key(|entry| entry.sequence)
        .map(|entry| entry.epoch_id))
}

/// Resolve the derivation epoch a new virtual-client operation must use: the
/// newest one registered for the emulation group `emulation_group_id`.
///
/// The draft requires every new operation to use the newest derivation epoch of
/// the acting client's current emulation-group state, so the epoch is never a
/// parameter of an operation. An operation carried by a commit that itself
/// creates a new derivation epoch still resolves against the commit's input
/// state, because the new epoch is only registered when that commit is merged.
///
/// Returns [`VirtualClientsError::NoDerivationEpoch`] when no derivation epoch
/// is registered, which is the case for every group that is not an emulation
/// group.
pub(crate) fn require_newest_vc_derivation_epoch<Storage: crate::storage::StorageProvider>(
    storage: &Storage,
    emulation_group_id: &GroupId,
) -> Result<EpochId, VirtualClientsError> {
    newest_vc_derivation_epoch(storage, emulation_group_id)
        .map_err(|e| {
            log::error!("vc: load newest derivation epoch for a new operation failed: {e:?}");
            VirtualClientsError::StorageError
        })?
        .ok_or(VirtualClientsError::NoDerivationEpoch)
}

/// The emulation-group coordinates of the group epoch a derivation epoch is
/// registered for. All values describe the *target* epoch, which for a merge is
/// the epoch the commit moves the group into, not the one it is merged from.
pub(crate) struct VcDerivationEpochParams<'a> {
    /// Group id of the emulation group.
    pub(crate) group_id: &'a GroupId,
    /// Ciphersuite of the emulation group.
    pub(crate) ciphersuite: Ciphersuite,
    /// The emulation group's epoch this derivation epoch is sourced from.
    pub(crate) group_epoch: GroupEpoch,
    /// The registering client's own leaf index in the emulation group.
    pub(crate) own_leaf_index: LeafNodeIndex,
    /// Number of leaves in the emulation group's ratchet tree.
    pub(crate) tree_size: TreeSize,
    /// How many derivation epochs the group's log may keep.
    pub(crate) retention_policy: VcDerivationEpochRetentionPolicy,
}

impl<'a> VcDerivationEpochParams<'a> {
    /// Read the coordinates off the emulation group's public state. The caller
    /// supplies `own_leaf_index` and the retention policy, which the public
    /// state does not carry.
    ///
    /// For a merge, pass the state after the staged diff was merged, so the
    /// coordinates describe the epoch the commit moves the group into.
    pub(crate) fn for_public_group(
        public_group: &'a crate::group::PublicGroup,
        own_leaf_index: LeafNodeIndex,
        retention_policy: VcDerivationEpochRetentionPolicy,
    ) -> Self {
        Self {
            group_id: public_group.group_id(),
            ciphersuite: public_group.ciphersuite(),
            group_epoch: public_group.group_context().epoch(),
            own_leaf_index,
            tree_size: public_group.tree_size(),
            retention_policy,
        }
    }
}

/// Derive and persist the virtual-clients derivation-epoch state for one epoch
/// of an emulation group.
///
/// Sources the per-derivation-epoch root secret by puncturing `export_tree`
/// under [`VC_COMPONENT_ID`], derives the [`EpochId`], the AEAD key, the epoch
/// base secret and the reuse-guard and generation-id secrets, builds the
/// per-epoch operation secret tree (sized like the emulation group's ratchet
/// tree), and persists the tree, the per-epoch state and the appended
/// derivation-epoch log entry. Returns the derived [`EpochId`].
///
/// Appending to the log applies the group's retention policy (see
/// [`VcDerivationEpochRetentionPolicy`]), which may delete the state of older
/// derivation epochs.
///
/// The caller owns `export_tree` and is responsible for persisting it after
/// this call, so that the puncture is not lost. A `None` export tree fails with
/// [`RegisterVcDerivationEpochError::MissingApplicationExportTree`]: merging
/// without registering would silently keep the old derivation epoch active,
/// which breaks the post-compromise guarantees of a membership change.
///
/// A registration consumes the forward-secure exporter, so it can derive
/// state at most once per group epoch. A repeated call for an
/// already-registered group epoch returns the recorded [`EpochId`] and leaves
/// the persisted operation secret tree untouched. The repeat still punctures
/// `export_tree` when it is handed a fresh, unpunctured tree for that epoch,
/// as a retried Welcome join does. Without the puncture the caller would
/// persist a tree that can re-derive the consumed secret.
pub(crate) fn register_vc_derivation_epoch<
    Crypto: OpenMlsCrypto,
    Storage: crate::storage::StorageProvider,
>(
    crypto: &Crypto,
    storage: &Storage,
    export_tree: Option<&mut ApplicationExportTree>,
    params: VcDerivationEpochParams<'_>,
) -> Result<EpochId, RegisterVcDerivationEpochError<Storage::Error>> {
    let VcDerivationEpochParams {
        group_id,
        ciphersuite,
        group_epoch,
        own_leaf_index,
        tree_size,
        retention_policy,
    } = params;
    let export_tree =
        export_tree.ok_or(RegisterVcDerivationEpochError::MissingApplicationExportTree)?;

    let mut log = VcDerivationEpochLog::load(storage, group_id).map_err(|e| {
        log::error!("vc: load derivation epoch log before registration failed: {e:?}");
        RegisterVcDerivationEpochError::Storage(e)
    })?;

    // Puncture before consulting the log. A repeat for a registered epoch can
    // hold a fresh, unpunctured tree, and returning early on the log alone
    // would let the caller persist that tree with the consumed secret still
    // derivable.
    let bytes = match export_tree.safe_export_secret(crypto, ciphersuite, VC_COMPONENT_ID) {
        Ok(bytes) => bytes,
        Err(ApplicationExportTreeError::PuncturedInput) => {
            // The tree in hand is already consumed, so this is an in-process
            // repeat of a completed registration and the log must agree.
            if let Some(newest) = log.newest() {
                if newest.group_epoch == group_epoch {
                    return Ok(newest.epoch_id.clone());
                }
            }
            return Err(RegisterVcDerivationEpochError::ApplicationExportTree(
                ApplicationExportTreeError::PuncturedInput,
            ));
        }
        Err(e) => return Err(e.into()),
    };
    let emulator_epoch_secret = EmulatorEpochSecret::new(bytes.as_slice());
    let epoch_id = emulator_epoch_secret.derive_epoch_id(crypto, ciphersuite)?;
    if let Some(newest) = log.newest() {
        if newest.group_epoch == group_epoch && newest.epoch_id == epoch_id {
            // A retry with identical key material, for example a Welcome join
            // repeated because the first one committed but the application
            // crashed before recording its success. The per-epoch state is
            // already persisted, only the fresh tree needed puncturing.
            return Ok(newest.epoch_id.clone());
        }
    }
    let epoch_encryption_key =
        emulator_epoch_secret.derive_epoch_encryption_key(crypto, ciphersuite)?;
    let epoch_base_secret = emulator_epoch_secret.derive_epoch_base_secret(crypto, ciphersuite)?;
    let reuse_guard_secret =
        emulator_epoch_secret.derive_reuse_guard_secret(crypto, ciphersuite)?;
    let generation_id_secret =
        emulator_epoch_secret.derive_generation_id_secret(crypto, ciphersuite)?;
    let operation_tree = OperationSecretTree::new(epoch_base_secret, tree_size);
    let state = VcDerivationEpochState::new(
        own_leaf_index,
        epoch_encryption_key,
        reuse_guard_secret,
        generation_id_secret,
        tree_size,
        ciphersuite,
    );
    let entry = log.push(group_epoch, epoch_id.clone());
    let dropped = log.shrink_to(retention_policy.max_epochs().unwrap_or(usize::MAX));

    storage
        .write_vc_operation_tree(&epoch_id, &operation_tree)
        .map_err(|e| {
            log::error!("vc: persist operation tree at registration failed: {e:?}");
            RegisterVcDerivationEpochError::Storage(e)
        })?;
    storage
        .write_vc_derivation_epoch_state(&epoch_id, &state)
        .map_err(|e| {
            log::error!("vc: persist derivation epoch state at registration failed: {e:?}");
            RegisterVcDerivationEpochError::Storage(e)
        })?;
    storage
        .write_vc_derivation_epoch_log_entry(group_id, &epoch_id, &entry)
        .map_err(|e| {
            log::error!("vc: persist derivation epoch log entry at registration failed: {e:?}");
            RegisterVcDerivationEpochError::Storage(e)
        })?;
    if !dropped.is_empty() {
        storage
            .delete_vc_derivation_epoch_log_entries(group_id, &dropped)
            .map_err(|e| {
                log::error!("vc: prune derivation epoch log at registration failed: {e:?}");
                RegisterVcDerivationEpochError::Storage(e)
            })?;
    }
    // The sweep releases the epochs that just dropped out of the log, unless
    // something else still references them, and collects any orphans earlier
    // crashes left behind.
    storage
        .delete_unreferenced_vc_derivation_epoch_states::<EpochId>()
        .map_err(|e| {
            log::error!("vc: release pruned derivation epochs at registration failed: {e:?}");
            RegisterVcDerivationEpochError::Storage(e)
        })?;

    Ok(epoch_id)
}

/// The binding of one epoch of a higher-level group to the derivation epoch
/// whose virtual-client LeafNode was active at that epoch, stored as its own
/// row keyed by `(group_id, group_epoch)`.
///
/// Bindings are kept per group epoch because a delayed PrivateMessage from a
/// past higher-level epoch has to be deprotected with the derivation epoch
/// that was bound then. A group retains as many bindings as its message
/// secrets store keeps past epochs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VcEmulationBinding {
    /// The higher-level group's epoch this binding is stored for.
    pub(crate) group_epoch: GroupEpoch,
    /// The derivation epoch bound at that group epoch.
    pub(crate) epoch_id: EpochId,
}

impl VcEmulationBinding {
    /// Build the binding of `group_epoch` to `epoch_id` from one entry of a
    /// [`VcEmulationBindings`] record.
    pub fn from_legacy_record(group_epoch: GroupEpoch, epoch_id: EpochId) -> Self {
        Self {
            group_epoch,
            epoch_id,
        }
    }

    /// The derivation epoch this binding names.
    pub fn epoch_id(&self) -> &EpochId {
        &self.epoch_id
    }

    pub(crate) fn into_epoch_id(self) -> EpochId {
        self.epoch_id
    }
}

/// Per-group bindings record of the storage layout that preceded per-epoch
/// [`VcEmulationBinding`] rows. Only for decoding stored records and
/// converting their entries with [`VcEmulationBinding::from_legacy_record`].
#[deprecated(
    since = "0.9.0",
    note = "migration-only: decode pre-row bindings records and convert their entries with \
            `VcEmulationBinding::from_legacy_record`. Will be removed in 0.10.0."
)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VcEmulationBindings {
    // In order of insertion, oldest at the front.
    bindings: VecDeque<(GroupEpoch, EpochId)>,
}

#[allow(deprecated)]
impl VcEmulationBindings {
    /// The `(group_epoch, epoch_id)` pairs of the record, oldest first.
    pub fn into_entries(self) -> Vec<(GroupEpoch, EpochId)> {
        self.bindings.into()
    }
}

/// Bind `group_epoch` of the higher-level group `group_id` to `epoch_id`, then
/// prune the group's bindings to at most `max_entries` by deleting the ones
/// with the lowest group epochs. `max_entries` follows the group's
/// message-secrets retention, so bindings age out in lockstep with the message
/// secrets they are needed for.
pub(crate) fn write_vc_emulation_binding_with_pruning<Storage: crate::storage::StorageProvider>(
    storage: &Storage,
    group_id: &GroupId,
    group_epoch: GroupEpoch,
    epoch_id: EpochId,
    max_entries: usize,
) -> Result<(), Storage::Error> {
    let binding = VcEmulationBinding {
        group_epoch,
        epoch_id: epoch_id.clone(),
    };
    storage.write_vc_emulation_binding(group_id, &group_epoch, &epoch_id, &binding)?;
    let mut bindings: Vec<VcEmulationBinding> = storage.vc_emulation_bindings(group_id)?;
    if bindings.len() > max_entries {
        bindings.sort_unstable_by_key(|binding| binding.group_epoch.as_u64());
        let stale: Vec<GroupEpoch> = bindings[..bindings.len() - max_entries]
            .iter()
            .map(|binding| binding.group_epoch)
            .collect();
        storage.delete_vc_emulation_bindings(group_id, &stale)?;
    }
    Ok(())
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
/// when the derivation epoch is registered.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct EpochEncryptionKey(Secret);

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

/// Per-derivation-epoch state, persisted alongside the per-epoch operation
/// secret tree and keyed by [`EpochId`]. Bundles everything the library needs
/// to emit a VC commit for this epoch and to XOR application message nonces
/// with deterministic reuse guards.
///
/// This is the local storage encoding, not the draft's wire struct of the same
/// name. The draft's version carries the `epoch_id` and the operation secret
/// tree as fields, both of which are stored separately here and keyed by
/// [`EpochId`], and calls the leaf count `leaf_count` rather than
/// `emulation_group_size`.
#[derive(Debug, Serialize, Deserialize)]
pub struct VcDerivationEpochState {
    /// The registering client's leaf index in the emulation group at
    /// registration time. Sent in `DerivationInfoTbe` and used as the
    /// sender's `leaf_index_e` in the reuse-guard derivation.
    pub(crate) leaf_index: LeafNodeIndex,
    pub(crate) epoch_encryption_key: EpochEncryptionKey,
    pub(crate) reuse_guard_secret: ReuseGuardSecret,
    /// Used to derive the per-message [`GenerationId`] handed to the DS, via
    /// [`VcDerivationEpochState::derive_generation_id`].
    pub(crate) generation_id_secret: GenerationIdSecret,
    /// Number of leaves `N_e` in the emulation group at registration time.
    pub(crate) emulation_group_size: TreeSize,
    /// Ciphersuite of the emulation group at registration time. Used by
    /// the reuse-guard derivation.
    pub(crate) emulation_ciphersuite: Ciphersuite,
}

impl VcDerivationEpochState {
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

    /// Derive the [`GenerationId`] for an application message sent in
    /// `group_id` at `epoch` with ratchet `generation`. The
    /// [`PrivateMessageContext`] is assembled from these inputs and the
    /// derivation epoch's [`GenerationIdSecret`], using the emulation group's
    /// ciphersuite.
    pub(crate) fn derive_generation_id(
        &self,
        crypto: &impl OpenMlsCrypto,
        group_id: &GroupId,
        epoch: GroupEpoch,
        generation: u32,
        ratchet_type: RatchetType,
    ) -> Result<GenerationId, VirtualClientsError> {
        let context = PrivateMessageContext {
            group_id: VLByteSlice(group_id.as_slice()),
            epoch: epoch.as_u64(),
            generation,
            ratchet_type,
        };
        self.generation_id_secret
            .derive_generation_id(crypto, self.emulation_ciphersuite, &context)
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
#[derive(Debug, Serialize, Deserialize)]
pub struct OperationSecret(Secret);

impl From<Secret> for OperationSecret {
    fn from(secret: Secret) -> Self {
        Self(secret)
    }
}

/// Imports a secret from the emulation group's ciphersuite to the target ciphersuite.
///
/// The import MUST be performed even when the emulation group and target use the same ciphersuite.
fn import_secret(
    crypto: &impl OpenMlsCrypto,
    target_ciphersuite: Ciphersuite,
    source_secret: &Secret,
    label: &str,
    context: &[u8],
) -> Result<Secret, CryptoError> {
    let salt = Secret::from_slice(&[]);
    let target_prk = salt.hkdf_extract(crypto, target_ciphersuite, source_secret)?;
    target_prk.kdf_expand_label(
        crypto,
        target_ciphersuite,
        label,
        context,
        target_ciphersuite.hash_length(),
    )
}

impl OperationSecret {
    /// The raw operation secret bytes.
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Derive the `target_operation_secret` of a `leaf_node` operation: this
    /// operation secret imported into the higher-level group's ciphersuite:
    ///
    /// ```text
    /// target_operation_secret = ImportSecret(operation_secret,
    ///                                        "vc target operation",
    ///                                        TargetOperationContext)
    /// ```
    ///
    /// The context binds the target ciphersuite and the higher-level group's
    /// `group_id`, so one operation secret yields independent path material
    /// per target group. The commit path's encryption-key and path-generation
    /// secrets are derived from the returned [`TargetOperationSecret`], not
    /// from the operation secret directly. The committing emulator and the
    /// sibling recreating the commit derive the same value.
    pub(crate) fn derive_target_operation_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        target_ciphersuite: Ciphersuite,
        group_id: &GroupId,
    ) -> Result<TargetOperationSecret, VirtualClientsError> {
        let context = TargetOperationContext {
            cipher_suite: target_ciphersuite,
            group_id: VLByteSlice(group_id.as_slice()),
        }
        .tls_serialize_detached()?;
        let secret = import_secret(
            crypto,
            target_ciphersuite,
            &self.0,
            TARGET_OPERATION_LABEL,
            &context,
        )?;
        Ok(TargetOperationSecret(secret))
    }

    /// Derive the per-KeyPackage seed secret for the KeyPackage at
    /// `key_package_index` within this operation's batch:
    ///
    /// ```text
    /// key_package_seed_secret = ImportSecret(operation_secret,
    ///                                        "vc key package seed",
    ///                                        KeyPackageSeedContext)
    /// ```
    ///
    /// The KeyPackage's init and leaf-encryption keys are then derived from the
    /// returned [`KeyPackageSeedSecret`], not from the operation secret
    /// directly, so a single `key_package` operation secret can cover a batch
    /// of KeyPackages with distinct key material.
    pub(crate) fn derive_key_package_seed_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        target_ciphersuite: Ciphersuite,
        key_package_index: u32,
    ) -> Result<KeyPackageSeedSecret, VirtualClientsError> {
        let context = KeyPackageSeedContext {
            cipher_suite: target_ciphersuite,
            key_package_index,
        }
        .tls_serialize_detached()?;
        let seed = import_secret(
            crypto,
            target_ciphersuite,
            &self.0,
            KEY_PACKAGE_SEED_LABEL,
            &context,
        )?;
        Ok(KeyPackageSeedSecret(seed))
    }
}

/// `ExpandWithLabel` context for [`OperationSecret::derive_key_package_seed_secret`]
/// (mls-virtual-clients draft):
///
/// ```text
/// struct {
///   CipherSuite cipher_suite;
///   uint32 key_package_index;
/// } KeyPackageSeedContext
/// ```
///
/// Only ever serialized as a derivation context, never parsed back, so it
/// needs serialization only.
#[derive(Debug, TlsSize, TlsSerialize)]
struct KeyPackageSeedContext {
    cipher_suite: Ciphersuite,
    key_package_index: u32,
}

/// Per-KeyPackage seed secret from which a single KeyPackage's init and
/// leaf-encryption keys are derived. Produced by
/// `OperationSecret::derive_key_package_seed_secret` for one index within a
/// `key_package` operation's batch. Persisted in [`RetainedKeyPackageMaterial`]
/// so the Welcome path can rederive the keys without re-walking the operation
/// tree.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyPackageSeedSecret(Secret);

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

    /// Derive the epoch-0 `epoch_secret` for a virtual-client-created group:
    ///
    /// ```text
    /// epoch_secret = DeriveSecret(key_package_seed_secret, "Group Creation")
    /// ```
    ///
    /// `ciphersuite` is the created (higher-level) group's ciphersuite, under
    /// which the resulting `epoch_secret` seeds the epoch key schedule. Both
    /// the creator and a reconstructing sibling derive it from the same seed,
    /// so the epoch secret never travels on the wire.
    pub(crate) fn derive_group_creation_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<Secret, VirtualClientsError> {
        Ok(self
            .0
            .derive_secret(crypto, ciphersuite, GROUP_CREATION_LABEL)?)
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
/// The operation type does not travel on the wire. For the two operations
/// that produce a LeafNode, receivers infer it from that leaf's
/// `leaf_node_source`: `key_package` maps to [`KeyPackage`](Self::KeyPackage),
/// `update` and `commit` map to [`LeafNode`](Self::LeafNode).
///
/// [`Application`](Self::Application) secrets are not attached to a leaf. The
/// application takes them from the ratchet directly and publishes the
/// coordinates its siblings need, see the [`vc_application_secret`] module.
///
/// [`vc_application_secret`]: crate::components::vc_application_secret
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

/// The external init secret carried by an external-commit LeafNode's
/// `DerivationInfoTBE` (mls-virtual-clients draft):
///
/// ```text
/// struct { opaque init_secret<V>; } ExternalInitSecret;
/// ```
///
/// It is the `init_secret` produced by external initialization
/// ({{Section 8.3 of RFC9420}}). A sibling emulator client processing the
/// external commit uses it as the new epoch's external init secret instead of
/// decapsulating from the previous epoch's `external_secret`, which it may not
/// hold.
#[derive(Clone, PartialEq, Eq, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub(crate) struct ExternalInitSecret(SecretVLByteVec);

impl std::fmt::Debug for ExternalInitSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalInitSecret")
            .field("init_secret", &"<redacted>")
            .finish()
    }
}

impl ExternalInitSecret {
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec().into())
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// ```text
/// struct {
///   CipherSuite cipher_suite;
///   opaque group_id<V>;
/// } TargetOperationContext
/// ```
#[derive(Debug, TlsSize, TlsSerialize)]
struct TargetOperationContext<'a> {
    cipher_suite: Ciphersuite,
    group_id: VLByteSlice<'a>,
}

/// A leaf node operation secret imported into the higher-level group's ciphersuite.
///
/// Must be immediately deleted after the encryption key/path generation secrets are derived.
#[derive(Debug)]
pub(crate) struct TargetOperationSecret(Secret);

impl TargetOperationSecret {
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
}

/// What a receiver derives from a sibling virtual client's commit in order to
/// recreate it: the emulation `epoch_id` the commit binds to, the per-commit
/// `operation_secret` the path is rederived from, and, for an external commit,
/// the carried `external_init_secret` (`None` for a regular commit).
///
/// Produced by `MlsGroup::load_vc_commit_material` and threaded into commit
/// staging as a single `Option`: either all three are present (a sibling VC
/// commit) or none are.
#[derive(Debug)]
pub(crate) struct VcCommitMaterial {
    /// Derivation epoch the commit's derivation info references.
    pub(crate) epoch_id: EpochId,
    /// Per-commit operation secret the receiver rederives the path from.
    pub(crate) operation_secret: OperationSecret,
    /// External init secret carried by an external commit, `None` otherwise.
    pub(crate) external_init_secret: Option<ExternalInitSecret>,
}

/// AEAD plaintext attached to the leaf via the VC component
/// (mls-virtual-clients draft):
///
/// ```text
/// struct {
///   uint32 leaf_index;
///   uint32 generation;
///   select (LeafNode.leaf_node_source) {
///     case key_package: uint32 key_package_index;
///     case update:      struct{};
///     case commit:      optional<ExternalInitSecret> external_init_secret;
///   };
/// } DerivationInfoTBE
/// ```
///
/// `leaf_index` is the *emulation*-group leaf index of the sending virtual
/// client, *not* the leaf index in the group that carries this commit.
/// `generation` is the operation-ratchet generation the sender consumed for
/// this operation. `key_package_index`, present only for the `KeyPackage`
/// variant, is the KeyPackage's position within its `key_package` operation
/// batch. `external_init_secret`, present only for the commit variant, carries
/// the external init secret of an external commit (`Some`) and is absent
/// (`None`) for a regular commit.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DerivationInfoTbe {
    /// Carried by `update` and `commit` leaves. No `key_package_index`. The
    /// codec treats the `LeafNode` operation type as the `commit` case (the
    /// only LeafNode-source leaf emitted today). `update`-proposal leaves are
    /// deferred and would need their own (field-less) codec branch.
    LeafNode {
        leaf_index: LeafNodeIndex,
        generation: u32,
        /// `Some` for an external commit, `None` for a regular commit.
        external_init_secret: Option<ExternalInitSecret>,
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

    /// The external init secret carried by an external-commit LeafNode, if any.
    /// Always `None` for `KeyPackage` and for regular (non-external) commits.
    pub(crate) fn external_init_secret(&self) -> Option<&ExternalInitSecret> {
        match self {
            Self::LeafNode {
                external_init_secret,
                ..
            } => external_init_secret.as_ref(),
            Self::KeyPackage { .. } => None,
        }
    }

    /// Serialize the variant's fields in order, with no variant tag, matching
    /// the `DerivationInfoTBE` select. The TLS derive macros cannot express a
    /// tagless select, so this codec is written by hand.
    fn tls_serialize_detached(&self) -> Result<Vec<u8>, tls_codec::Error> {
        match self {
            Self::LeafNode {
                leaf_index,
                generation,
                external_init_secret,
            } => {
                let mut out = Vec::with_capacity(
                    leaf_index.tls_serialized_len()
                        + generation.tls_serialized_len()
                        + external_init_secret.tls_serialized_len(),
                );
                leaf_index.tls_serialize(&mut out)?;
                generation.tls_serialize(&mut out)?;
                external_init_secret.tls_serialize(&mut out)?;
                Ok(out)
            }
            Self::KeyPackage {
                leaf_index,
                generation,
                key_package_index,
            } => {
                let mut out = Vec::with_capacity(
                    leaf_index.tls_serialized_len()
                        + generation.tls_serialized_len()
                        + key_package_index.tls_serialized_len(),
                );
                leaf_index.tls_serialize(&mut out)?;
                generation.tls_serialize(&mut out)?;
                key_package_index.tls_serialize(&mut out)?;
                Ok(out)
            }
        }
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
        let (tbe, rest) = match operation_type {
            VirtualClientOperationType::KeyPackage => {
                let (key_package_index, rest) = u32::tls_deserialize_bytes(rest)?;
                (
                    Self::KeyPackage {
                        leaf_index,
                        generation,
                        key_package_index,
                    },
                    rest,
                )
            }
            // The `LeafNode` operation type is the `commit` case: it carries an
            // `optional<ExternalInitSecret>`. (`update`-proposal leaves are
            // deferred and would decode a field-less body instead.)
            VirtualClientOperationType::LeafNode => {
                let (external_init_secret, rest) =
                    Option::<ExternalInitSecret>::tls_deserialize_bytes(rest)?;
                (
                    Self::LeafNode {
                        leaf_index,
                        generation,
                        external_init_secret,
                    },
                    rest,
                )
            }
            VirtualClientOperationType::Application => {
                return Err(VirtualClientsError::DerivationInfoMalformed);
            }
        };
        if !rest.is_empty() {
            return Err(VirtualClientsError::DerivationInfoMalformed);
        }
        Ok(tbe)
    }
}

/// Load the [`VcDerivationEpochState`] and [`OperationSecretTree`] for `epoch_id`,
/// mapping a missing entry to the matching `Missing*` error. Callers convert the
/// returned [`VirtualClientsError`] into their own error type.
///
/// [`OperationSecretTree`]: crate::components::vc_operation_tree::OperationSecretTree
pub(crate) fn load_vc_epoch_state_and_tree<Provider: OpenMlsProvider>(
    provider: &Provider,
    epoch_id: &EpochId,
) -> Result<
    (
        VcDerivationEpochState,
        crate::components::vc_operation_tree::OperationSecretTree,
    ),
    VirtualClientsError,
> {
    use openmls_traits::storage::StorageProvider as _;

    let storage = provider.storage();
    let state = storage
        .vc_derivation_epoch_state(epoch_id)
        .map_err(|e| {
            log::error!("vc: load derivation epoch state failed: {e:?}");
            VirtualClientsError::StorageError
        })?
        .ok_or(VirtualClientsError::MissingDerivationEpochState)?;
    let operation_tree = storage
        .vc_operation_tree(epoch_id)
        .map_err(|e| {
            log::error!("vc: load operation tree failed: {e:?}");
            VirtualClientsError::StorageError
        })?
        .ok_or(VirtualClientsError::MissingOperationTree)?;
    Ok((state, operation_tree))
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

/// Merge a virtual-clients derivation-info blob into `resolved_dictionary`
/// under [`VC_COMPONENT_ID`] and build the resulting leaf-node extensions.
///
/// Every other component id in `resolved_dictionary` (notably `AppComponents`)
/// is preserved, as is every non-`AppDataDictionary` extension the caller
/// supplied in `caller_extensions`. The rebuilt dictionary replaces any
/// `AppDataDictionary` entry already in that list.
pub(crate) fn merge_vc_derivation_info(
    caller_extensions: Option<
        &crate::extensions::Extensions<crate::treesync::node::leaf_node::LeafNode>,
    >,
    mut resolved_dictionary: crate::extensions::AppDataDictionary,
    derivation_info_bytes: Vec<u8>,
) -> Result<
    crate::extensions::Extensions<crate::treesync::node::leaf_node::LeafNode>,
    crate::error::LibraryError,
> {
    use crate::extensions::{AppDataDictionaryExtension, Extension, Extensions};

    resolved_dictionary.insert(VC_COMPONENT_ID, derivation_info_bytes);
    let vc_extension =
        Extension::AppDataDictionary(AppDataDictionaryExtension::new(resolved_dictionary));

    let other_extensions = caller_extensions
        .map(|exts| {
            exts.iter()
                .filter(|ext| !matches!(ext, Extension::AppDataDictionary(_)))
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let new_extensions: Vec<Extension> = other_extensions
        .into_iter()
        .chain(std::iter::once(vc_extension))
        .collect();
    Extensions::from_vec(new_extensions)
        .map_err(|_| crate::error::LibraryError::custom("Failed to build VC leaf-node extensions"))
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

    /// Register a full `VcDerivationEpochState` and a matching
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
        let state = VcDerivationEpochState::new(
            leaf_index,
            epoch_encryption_key,
            reuse_guard_secret,
            generation_id_secret,
            emulation_group_size,
            CIPHERSUITE,
        );
        <MemoryStorage as StorageProvider<CURRENT_VERSION>>::write_vc_derivation_epoch_state(
            provider.storage(),
            &epoch_id,
            &state,
        )
        .expect("write derivation epoch state");
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
    /// `VcDerivationEpochState` for the epoch.
    #[test]
    fn assemble_upload_reads_leaf_index_from_state() {
        let provider = OpenMlsRustCrypto::default();
        let leaf_index = LeafNodeIndex::new(5);
        let epoch_id = register_epoch_state(&provider, leaf_index);
        let infos = vec![
            KeyPackageInfo {
                key_package_ref: KeyPackageRef::from_slice(b"kp-ref-a"),
                cipher_suite: CIPHERSUITE,
                key_package_index: 0,
            },
            KeyPackageInfo {
                key_package_ref: KeyPackageRef::from_slice(b"kp-ref-b"),
                cipher_suite: CIPHERSUITE,
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
    /// `MissingDerivationEpochState`.
    #[test]
    fn assemble_upload_without_state_fails() {
        let provider = OpenMlsRustCrypto::default();
        let epoch_id = EpochId(b"unregistered-epoch".to_vec().into());
        let err = assemble_vc_key_package_upload(provider.storage(), epoch_id, 0, Vec::new())
            .expect_err("assemble must fail without registered state");
        assert_eq!(err, VirtualClientsError::MissingDerivationEpochState);
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
                    cipher_suite: CIPHERSUITE,
                    key_package_index: 0,
                },
                KeyPackageInfo {
                    key_package_ref: ref_b.clone(),
                    cipher_suite: CIPHERSUITE,
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
        assert_eq!(material_a.key_package_ciphersuite, CIPHERSUITE);

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
        assert_eq!(material_b.key_package_ciphersuite, CIPHERSUITE);
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
                cipher_suite: CIPHERSUITE,
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
            external_init_secret: None,
        };
        let external_commit_tbe = DerivationInfoTbe::LeafNode {
            leaf_index: LeafNodeIndex::new(7),
            generation: 3,
            external_init_secret: Some(ExternalInitSecret::from_slice(b"external init secret")),
        };

        // The key_package form carries the trailing key_package_index (u32),
        // while the leaf_node (commit) form carries an absent
        // optional<ExternalInitSecret> (one presence octet).
        let key_package_bytes = key_package_tbe
            .tls_serialize_detached()
            .expect("serialize key package tbe");
        let leaf_node_bytes = leaf_node_tbe
            .tls_serialize_detached()
            .expect("serialize leaf node tbe");
        assert_eq!(key_package_bytes.len(), leaf_node_bytes.len() + 3);

        for (original, operation_type) in [
            (key_package_tbe, VirtualClientOperationType::KeyPackage),
            (leaf_node_tbe, VirtualClientOperationType::LeafNode),
            (external_commit_tbe, VirtualClientOperationType::LeafNode),
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

    /// Pin the serialized `DerivationInfoTBE` layout to the spec's select,
    /// byte for byte: `uint32 leaf_index`, `uint32 generation`, then the
    /// `key_package_index` (key_package case) or the
    /// `optional<ExternalInitSecret>` (commit case) with nothing trailing.
    /// Catches conventions drift that the roundtrip test cannot see.
    #[test]
    fn derivation_info_tbe_wire_format_matches_spec() {
        let absent = DerivationInfoTbe::LeafNode {
            leaf_index: LeafNodeIndex::new(7),
            generation: 3,
            external_init_secret: None,
        }
        .tls_serialize_detached()
        .expect("serialize");
        assert_eq!(
            absent,
            [0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x03, 0x00]
        );

        let present = DerivationInfoTbe::LeafNode {
            leaf_index: LeafNodeIndex::new(7),
            generation: 3,
            external_init_secret: Some(ExternalInitSecret::from_slice(b"init")),
        }
        .tls_serialize_detached()
        .expect("serialize");
        assert_eq!(
            present,
            [0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x03, 0x01, 0x04, b'i', b'n', b'i', b't']
        );

        let key_package = DerivationInfoTbe::KeyPackage {
            leaf_index: LeafNodeIndex::new(7),
            generation: 3,
            key_package_index: 5,
        }
        .tls_serialize_detached()
        .expect("serialize");
        assert_eq!(
            key_package,
            [0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05]
        );
    }

    /// The TBE plaintext must be consumed exactly. A trailing octet, which is
    /// what a peer implementing the superseded draft revision with its
    /// trailing `optional<GroupCreationSecret>` would produce, is rejected
    /// for both variants.
    #[test]
    fn derivation_info_tbe_rejects_trailing_data() {
        let variants = [
            (
                DerivationInfoTbe::LeafNode {
                    leaf_index: LeafNodeIndex::new(7),
                    generation: 3,
                    external_init_secret: None,
                },
                VirtualClientOperationType::LeafNode,
            ),
            (
                DerivationInfoTbe::KeyPackage {
                    leaf_index: LeafNodeIndex::new(7),
                    generation: 3,
                    key_package_index: 5,
                },
                VirtualClientOperationType::KeyPackage,
            ),
        ];
        for (tbe, operation_type) in variants {
            let mut bytes = tbe.tls_serialize_detached().expect("serialize");
            bytes.push(0x00);
            let result = DerivationInfoTbe::deserialize_for_operation(&bytes, operation_type);
            assert_eq!(result, Err(VirtualClientsError::DerivationInfoMalformed));
        }
    }

    /// Debug output of the TBE must not leak the carried init secret.
    #[test]
    fn external_init_secret_debug_is_redacted() {
        let tbe = DerivationInfoTbe::LeafNode {
            leaf_index: LeafNodeIndex::new(7),
            generation: 3,
            external_init_secret: Some(ExternalInitSecret::from_slice(b"very secret bytes")),
        };
        let debug = format!("{tbe:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret bytes"));
        assert!(!debug.to_lowercase().contains("76657279"));
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
            external_init_secret: None,
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

    /// The per-KeyPackage seed is imported into the target ciphersuite: the
    /// same operation secret and index yield different seeds for different
    /// target ciphersuites, because the target ciphersuite is bound into the
    /// `KeyPackageSeedContext` and the import runs under the target's KDF.
    #[test]
    fn key_package_seed_binds_target_ciphersuite() {
        let provider = OpenMlsRustCrypto::default();
        let operation_secret = OperationSecret::from(Secret::from_slice(
            &provider
                .rand()
                .random_vec(CIPHERSUITE.hash_length())
                .expect("randomness"),
        ));
        // Same KDF hash (SHA-256) as `CIPHERSUITE`, so the two seeds have
        // equal length and differ only through the ciphersuite binding.
        let other_ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

        let seed = operation_secret
            .derive_key_package_seed_secret(provider.crypto(), CIPHERSUITE, 0)
            .expect("derive seed");
        let seed_other_suite = operation_secret
            .derive_key_package_seed_secret(provider.crypto(), other_ciphersuite, 0)
            .expect("derive seed under other target ciphersuite");

        assert_ne!(seed.0.as_slice(), seed_other_suite.0.as_slice());
    }

    /// The `target_operation_secret` of a `leaf_node` operation is
    /// deterministic and binds both the target ciphersuite and the
    /// higher-level group's id; the encryption and path-generation secrets
    /// derived from it are label-separated.
    #[test]
    fn target_operation_secret_binds_ciphersuite_and_group_id() {
        let provider = OpenMlsRustCrypto::default();
        let operation_secret = OperationSecret::from(Secret::from_slice(
            &provider
                .rand()
                .random_vec(CIPHERSUITE.hash_length())
                .expect("randomness"),
        ));
        let group_id = GroupId::from_slice(b"group-a");
        let other_ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

        let target = operation_secret
            .derive_target_operation_secret(provider.crypto(), CIPHERSUITE, &group_id)
            .expect("derive target operation secret");
        let target_again = operation_secret
            .derive_target_operation_secret(provider.crypto(), CIPHERSUITE, &group_id)
            .expect("derive target operation secret again");
        let target_other_group = operation_secret
            .derive_target_operation_secret(
                provider.crypto(),
                CIPHERSUITE,
                &GroupId::from_slice(b"group-b"),
            )
            .expect("derive target operation secret for other group");
        let target_other_suite = operation_secret
            .derive_target_operation_secret(provider.crypto(), other_ciphersuite, &group_id)
            .expect("derive target operation secret under other target ciphersuite");

        // Same inputs derive deterministically.
        assert_eq!(target.0.as_slice(), target_again.0.as_slice());
        // A different group id or a different target ciphersuite derives a
        // distinct secret.
        assert_ne!(target.0.as_slice(), target_other_group.0.as_slice());
        assert_ne!(target.0.as_slice(), target_other_suite.0.as_slice());

        // Encryption and path-generation secrets from one target operation
        // secret are label-separated.
        let encryption_key_secret = target
            .derive_encryption_key_secret(provider.crypto(), CIPHERSUITE)
            .expect("derive encryption key secret");
        let path_generation_secret = target
            .derive_path_generation_secret(provider.crypto(), CIPHERSUITE)
            .expect("derive path generation secret");
        assert_ne!(
            encryption_key_secret.0.as_slice(),
            path_generation_secret.0.as_slice()
        );
    }

    /// The group-creation epoch secret is deterministic for a given seed,
    /// distinct across seeds, and label-separated from the encryption key
    /// secret derived from the same seed.
    #[test]
    fn group_creation_secret_derivation_is_deterministic_and_label_separated() {
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
        let seed_one = operation_secret
            .derive_key_package_seed_secret(provider.crypto(), CIPHERSUITE, 1)
            .expect("derive seed 1");

        let epoch_secret_zero = seed_zero
            .derive_group_creation_secret(provider.crypto(), CIPHERSUITE)
            .expect("derive group creation secret 0");
        let epoch_secret_zero_again = seed_zero
            .derive_group_creation_secret(provider.crypto(), CIPHERSUITE)
            .expect("derive group creation secret 0 again");
        let epoch_secret_one = seed_one
            .derive_group_creation_secret(provider.crypto(), CIPHERSUITE)
            .expect("derive group creation secret 1");

        // Same seed derives deterministically.
        assert_eq!(
            epoch_secret_zero.as_slice(),
            epoch_secret_zero_again.as_slice()
        );
        // Different seeds derive distinct epoch secrets.
        assert_ne!(epoch_secret_zero.as_slice(), epoch_secret_one.as_slice());

        // The epoch secret is label-separated from the encryption key secret
        // derived from the same seed.
        let encryption_key_secret = seed_zero
            .derive_encryption_key_secret(provider.crypto(), CIPHERSUITE)
            .expect("derive encryption key 0");
        assert_ne!(
            epoch_secret_zero.as_slice(),
            encryption_key_secret.0.as_slice()
        );
    }

    /// A repeated `key_package_index` is rejected with
    /// `DuplicateKeyPackageIndex` carrying the offending index.
    #[test]
    fn validate_rejects_duplicate_index() {
        let infos = vec![
            KeyPackageInfo {
                key_package_ref: KeyPackageRef::from_slice(b"kp-ref-a"),
                cipher_suite: CIPHERSUITE,
                key_package_index: 2,
            },
            KeyPackageInfo {
                key_package_ref: KeyPackageRef::from_slice(b"kp-ref-b"),
                cipher_suite: CIPHERSUITE,
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
                cipher_suite: CIPHERSUITE,
                key_package_index: 0,
            },
            KeyPackageInfo {
                key_package_ref: KeyPackageRef::from_slice(b"kp-ref-a"),
                cipher_suite: CIPHERSUITE,
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
                cipher_suite: CIPHERSUITE,
                key_package_index: 0,
            },
            KeyPackageInfo {
                key_package_ref: KeyPackageRef::from_slice(b"kp-ref-b"),
                cipher_suite: CIPHERSUITE,
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
                    cipher_suite: CIPHERSUITE,
                    key_package_index: 0,
                },
                KeyPackageInfo {
                    key_package_ref: ref_b.clone(),
                    cipher_suite: CIPHERSUITE,
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
                    cipher_suite: CIPHERSUITE,
                    key_package_index: 0,
                },
                KeyPackageInfo {
                    key_package_ref: ref_b.clone(),
                    cipher_suite: CIPHERSUITE,
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

    /// Build a `VcDerivationEpochState` from raw emulator-epoch-secret
    /// bytes, so two siblings sharing the same bytes can be compared.
    fn state_from_secret_bytes(
        provider: &OpenMlsRustCrypto,
        secret_bytes: &[u8],
        leaf_index: LeafNodeIndex,
    ) -> VcDerivationEpochState {
        let emulator = EmulatorEpochSecret::new(secret_bytes);
        let epoch_encryption_key = emulator
            .derive_epoch_encryption_key(provider.crypto(), CIPHERSUITE)
            .expect("derive epoch encryption key");
        let reuse_guard_secret = emulator
            .derive_reuse_guard_secret(provider.crypto(), CIPHERSUITE)
            .expect("derive reuse guard secret");
        let generation_id_secret = emulator
            .derive_generation_id_secret(provider.crypto(), CIPHERSUITE)
            .expect("derive generation id secret");
        VcDerivationEpochState::new(
            leaf_index,
            epoch_encryption_key,
            reuse_guard_secret,
            generation_id_secret,
            TreeSize::new(2),
            CIPHERSUITE,
        )
    }

    /// The generation ID is deterministic for fixed inputs, changes when any
    /// `PrivateMessageContext` field changes, and two siblings that share the
    /// same emulator epoch secret derive the same value (so a DS can compare
    /// them for equality across siblings).
    #[test]
    fn generation_id_is_deterministic_and_context_sensitive() {
        let provider = OpenMlsRustCrypto::default();
        let secret_bytes = provider
            .rand()
            .random_vec(CIPHERSUITE.hash_length())
            .expect("randomness");
        let state = state_from_secret_bytes(&provider, &secret_bytes, LeafNodeIndex::new(0));

        let group_id = GroupId::from_slice(b"higher-level-group");
        let epoch = GroupEpoch::from(7);
        let derive = |group_id: &GroupId, epoch, generation, ratchet_type| {
            state
                .derive_generation_id(provider.crypto(), group_id, epoch, generation, ratchet_type)
                .expect("derive generation id")
        };

        let base = derive(&group_id, epoch, 3, RatchetType::Application);
        // The generation ID is `Kdf.Nh` bytes long.
        assert_eq!(base.as_slice().len(), CIPHERSUITE.hash_length());
        // Deterministic for fixed inputs.
        assert_eq!(base, derive(&group_id, epoch, 3, RatchetType::Application));
        // Sensitive to the generation, the epoch, the group id, and the
        // ratchet type.
        assert_ne!(base, derive(&group_id, epoch, 4, RatchetType::Application));
        assert_ne!(
            base,
            derive(&group_id, GroupEpoch::from(8), 3, RatchetType::Application)
        );
        assert_ne!(
            base,
            derive(
                &GroupId::from_slice(b"other-group"),
                epoch,
                3,
                RatchetType::Application
            )
        );
        assert_ne!(base, derive(&group_id, epoch, 3, RatchetType::Handshake));

        // A sibling sharing the same emulator epoch secret derives the same
        // generation ID, even from a different leaf index: the leaf index is
        // not part of the PrivateMessageContext.
        let sibling = state_from_secret_bytes(&provider, &secret_bytes, LeafNodeIndex::new(5));
        let sibling_id = sibling
            .derive_generation_id(
                provider.crypto(),
                &group_id,
                epoch,
                3,
                RatchetType::Application,
            )
            .expect("sibling derive generation id");
        assert_eq!(base, sibling_id);
    }

    #[test]
    #[allow(deprecated)]
    fn legacy_registration_record_layout_is_frozen() {
        let record = RegisteredVcDerivationEpoch {
            group_epoch: GroupEpoch::from(7),
            epoch_id: EpochId::new(vec![1, 2, 3]),
        };
        let json = serde_json::to_string(&record).expect("serialize legacy record");
        assert_eq!(json, r#"{"group_epoch":7,"epoch_id":[1,2,3]}"#);
        let decoded: RegisteredVcDerivationEpoch =
            serde_json::from_str(&json).expect("deserialize legacy record");
        assert_eq!(decoded, record);
    }

    #[test]
    #[allow(deprecated)]
    fn legacy_bindings_record_layout_is_frozen() {
        let record = VcEmulationBindings {
            bindings: VecDeque::from([
                (GroupEpoch::from(7), EpochId::new(vec![1, 2, 3])),
                (GroupEpoch::from(8), EpochId::new(vec![4, 5, 6])),
            ]),
        };
        let json = serde_json::to_string(&record).expect("serialize legacy record");
        assert_eq!(json, r#"{"bindings":[[7,[1,2,3]],[8,[4,5,6]]]}"#);
        let decoded: VcEmulationBindings =
            serde_json::from_str(&json).expect("deserialize legacy record");
        assert_eq!(decoded, record);

        let entries = decoded.into_entries();
        assert_eq!(
            entries,
            vec![
                (GroupEpoch::from(7), EpochId::new(vec![1, 2, 3])),
                (GroupEpoch::from(8), EpochId::new(vec![4, 5, 6])),
            ]
        );
    }

    #[test]
    fn log_entry_layout_is_frozen() {
        let entry = VcDerivationEpochLogEntry {
            sequence: 2,
            group_epoch: GroupEpoch::from(7),
            epoch_id: EpochId::new(vec![1, 2, 3]),
            registered_at: SystemTime::UNIX_EPOCH + std::time::Duration::new(1_700_000_000, 42),
        };
        let json = serde_json::to_string(&entry).expect("serialize log entry");
        assert_eq!(
            json,
            r#"{"sequence":2,"group_epoch":7,"epoch_id":[1,2,3],"registered_at":{"secs_since_epoch":1700000000,"nanos_since_epoch":42}}"#
        );
        let decoded: VcDerivationEpochLogEntry =
            serde_json::from_str(&json).expect("deserialize log entry");
        assert_eq!(decoded, entry);
    }

    #[test]
    fn binding_layout_is_frozen() {
        let binding = VcEmulationBinding {
            group_epoch: GroupEpoch::from(7),
            epoch_id: EpochId::new(vec![1, 2, 3]),
        };
        let json = serde_json::to_string(&binding).expect("serialize binding");
        assert_eq!(json, r#"{"group_epoch":7,"epoch_id":[1,2,3]}"#);
        let decoded: VcEmulationBinding = serde_json::from_str(&json).expect("deserialize binding");
        assert_eq!(decoded, binding);
    }

    #[test]
    fn binding_from_legacy_record() {
        let epoch_id = EpochId::new(vec![4, 5, 6]);
        let binding = VcEmulationBinding::from_legacy_record(GroupEpoch::from(3), epoch_id.clone());
        assert_eq!(binding.group_epoch, GroupEpoch::from(3));
        assert_eq!(binding.epoch_id(), &epoch_id);
    }

    #[test]
    fn log_entry_from_legacy_record() {
        let epoch_id = EpochId::new(vec![4, 5, 6]);
        let registered_at = SystemTime::UNIX_EPOCH;
        let entry = VcDerivationEpochLogEntry::from_legacy_record(
            GroupEpoch::from(3),
            epoch_id.clone(),
            registered_at,
        );

        assert_eq!(entry.sequence, 0);
        assert_eq!(entry.group_epoch, GroupEpoch::from(3));
        assert_eq!(entry.epoch_id(), &epoch_id);
        assert_eq!(entry.registered_at, registered_at);

        // A log holding only the converted entry treats it as the newest one,
        // so neither pruning path drops it.
        let mut log = VcDerivationEpochLog {
            entries: VecDeque::from([entry]),
        };
        assert!(log.shrink_to(1).is_empty());
        assert!(log.drop_superseded_before(SystemTime::now()).is_empty());
        assert_eq!(
            log.newest().map(|entry| entry.epoch_id.clone()),
            Some(epoch_id)
        );
    }

    fn log_entry(
        group_epoch: u64,
        epoch_id: &EpochId,
        registered_at: SystemTime,
    ) -> VcDerivationEpochLogEntry {
        VcDerivationEpochLogEntry {
            sequence: group_epoch,
            group_epoch: GroupEpoch::from(group_epoch),
            epoch_id: epoch_id.clone(),
            registered_at,
        }
    }

    #[test]
    fn log_reconstruction_orders_by_sequence() {
        let provider = OpenMlsRustCrypto::default();
        let group_id = GroupId::from_slice(b"emulation-group");
        let first = log_entry(0, &EpochId::new(vec![1]), SystemTime::UNIX_EPOCH);
        let second = log_entry(1, &EpochId::new(vec![2]), SystemTime::UNIX_EPOCH);
        let third = log_entry(2, &EpochId::new(vec![3]), SystemTime::UNIX_EPOCH);
        // Written out of order. The provider returns entries unordered anyway,
        // so the sort must come from the sequence numbers alone.
        for entry in [&second, &third, &first] {
            <MemoryStorage as StorageProvider<CURRENT_VERSION>>::write_vc_derivation_epoch_log_entry(
                provider.storage(),
                &group_id,
                &entry.epoch_id,
                entry,
            )
            .expect("write log entry");
        }

        let log = VcDerivationEpochLog::load(provider.storage(), &group_id).expect("load the log");
        assert_eq!(
            log.newest().map(|entry| entry.epoch_id.clone()),
            Some(third.epoch_id.clone())
        );
        assert_eq!(
            newest_vc_derivation_epoch(provider.storage(), &group_id).expect("newest epoch"),
            Some(third.epoch_id.clone())
        );

        // Pruning drops the entries with the lowest sequences first.
        let mut log = log;
        assert_eq!(log.shrink_to(2), vec![first.epoch_id.clone()]);
        assert_eq!(
            log.newest().map(|entry| entry.epoch_id.clone()),
            Some(third.epoch_id)
        );
    }

    #[test]
    fn wall_clock_sweep_measures_from_supersession() {
        let old = EpochId::new(vec![1]);
        let mid = EpochId::new(vec![2]);
        let new = EpochId::new(vec![3]);
        let start = SystemTime::UNIX_EPOCH;
        let minutes = |m: u64| std::time::Duration::from_secs(m * 60);
        // `old` lives from `start` until `mid` supersedes it 10 minutes before
        // the 24 h mark, where `new` in turn supersedes `mid`.
        let mut log = VcDerivationEpochLog {
            entries: VecDeque::from([
                log_entry(0, &old, start),
                log_entry(1, &mid, start + minutes(23 * 60 + 50)),
                log_entry(2, &new, start + minutes(24 * 60)),
            ]),
        };

        // A 24 h sweep 5 minutes past the day puts the cutoff well after
        // `old`'s registration, but `old` was only just superseded and stays.
        assert!(log.drop_superseded_before(start + minutes(5)).is_empty());
        // Once the cutoff passes `old`'s supersession, `old` goes. `mid` was
        // superseded later and stays.
        assert_eq!(
            log.drop_superseded_before(start + minutes(23 * 60 + 55)),
            vec![old]
        );
        // The newest entry has no successor and survives any cutoff.
        assert_eq!(
            log.drop_superseded_before(start + minutes(48 * 60)),
            vec![mid]
        );
        assert_eq!(log.newest().map(|entry| entry.epoch_id.clone()), Some(new));
    }
}
