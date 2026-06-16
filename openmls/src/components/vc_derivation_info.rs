use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, CryptoError},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tls_codec::{
    DeserializeBytes, Serialize as _, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes,
};

use crate::{
    binary_tree::{array_representation::TreeSize, LeafNodeIndex},
    ciphersuite::Secret,
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
// secret produced by the per-epoch operation secret tree. Only
// `Encryption Key` and `Path Generation` are wired up at the moment, which is
// all the `leaf_node` commit path needs. The spec also defines
// `Signature Key` and `Init Key` children. Those, together with the
// `key_package` and `application` operation paths that consume them, are
// deferred to a follow-up PR.
const ENCRYPTION_KEY_LABEL: &str = "Encryption Key";
const PATH_GENERATION_LABEL: &str = "Path Generation";

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
        Ok(DerivationInfoTbe::tls_deserialize_exact_bytes(&plaintext)?)
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
/// } DerivationInfoTBE
/// ```
///
/// `leaf_index` is the *emulation*-group leaf index of the sending virtual
/// client, *not* the leaf index in the group that carries this commit.
/// `generation` is the operation-ratchet generation the sender consumed for
/// this operation.
#[derive(Debug, PartialEq, Eq, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub(crate) struct DerivationInfoTbe {
    pub leaf_index: LeafNodeIndex,
    pub generation: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::{random::OpenMlsRand, OpenMlsProvider};

    const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

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

    /// Round-trip a `DerivationInfoTbe` through `encrypt` and `decrypt`.
    /// Catches any disagreement between the two methods on the derived
    /// key/nonce, the AAD, or the TLS layout of the plaintext.
    #[test]
    fn derivation_info_tbe_roundtrip() {
        let provider = OpenMlsRustCrypto::default();
        let (key, epoch_id) = setup_key_and_epoch_id(&provider);
        let leaf_encryption_key = provider.rand().random_vec(32).expect("randomness");
        let original = DerivationInfoTbe {
            leaf_index: LeafNodeIndex::new(7),
            generation: 3,
        };
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
            .decrypt(provider.crypto(), CIPHERSUITE, &key, &leaf_encryption_key)
            .expect("decrypt");
        assert_eq!(original, decrypted);
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
        let tbe = DerivationInfoTbe {
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
            )
            .expect_err("decryption with the wrong context must fail");
        assert_eq!(err, VirtualClientsError::DerivationInfoDecryptionFailed);
    }
}
