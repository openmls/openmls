//! Virtual-clients commit data (mls-virtual-clients draft).
//!
//! A virtual client attaches this struct to a commit as a Safe AAD item under
//! [`VC_COMPONENT_ID`]. It tells the sibling emulators which derivation epochs
//! the author still uses and which actions the commit performs.
//!
//! ```tls
//! enum {
//!   reserved(0),
//!   key_package_upload(1),
//!   new_derivation_epoch(2),
//!   (255)
//! } ActionType;
//!
//! struct {
//!   ActionType action_type;
//!   select (VirtualClientAction.action_type) {
//!     case key_package_upload:
//!       KeyPackageUpload key_package_upload;
//!     case new_derivation_epoch:
//!       struct{};
//!   };
//! } VirtualClientAction;
//!
//! struct {
//!   opaque epoch_id<V>;
//! } VcEpochReference;
//!
//! struct {
//!   VcEpochReference in_use_epochs<V>;
//! } VcEpochUsage;
//!
//! struct {
//!   optional<VcEpochUsage> epoch_usage;
//!   VirtualClientAction actions<V>;
//! } VirtualClientCommitData;
//! ```
//!
//! Entries of a [`VcEpochUsage`] are unique and sorted, and a
//! [`VirtualClientCommitData`] carries at most one `new_derivation_epoch`
//! action. Both rules are enforced on construction and on deserialization.
//!
//! [`VC_COMPONENT_ID`]: crate::components::vc_derivation_info::VC_COMPONENT_ID
//! [`VcEpochUsage`]: crate::components::vc_commit_data::VcEpochUsage
//! [`VirtualClientCommitData`]: crate::components::vc_commit_data::VirtualClientCommitData

use std::cmp::Ordering;

use tls_codec::{
    DeserializeBytes as TlsDeserializeBytesTrait, Serialize as TlsSerializeTrait,
    TlsDeserializeBytes, TlsSerialize, TlsSize,
};

use crate::{
    components::vc_derivation_info::{EpochId, KeyPackageUpload, VC_COMPONENT_ID},
    framing::{SafeAad, SafeAadItem},
};

/// Errors that can occur when building or parsing a [`VirtualClientCommitData`].
#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum VcCommitDataError {
    /// Two [`VcEpochReference`] entries carry the same `epoch_id`.
    #[error("duplicate epoch id in VcEpochUsage")]
    DuplicateEpochId,
    /// Entries are not sorted in strictly-increasing order by the TLS
    /// serialization of `epoch_id`.
    #[error("VcEpochUsage entries are not sorted by the serialized epoch id in increasing order")]
    EpochsNotSortedAscending,
    /// More than one `new_derivation_epoch` action is present.
    #[error("VirtualClientCommitData carries more than one new_derivation_epoch action")]
    MultipleNewDerivationEpochs,
    /// Encoding or decoding failure.
    #[error("codec error: {0}")]
    Codec(String),
}

impl From<tls_codec::Error> for VcCommitDataError {
    fn from(err: tls_codec::Error) -> Self {
        Self::Codec(err.to_string())
    }
}

/// One action a virtual client's commit performs.
#[derive(Debug, PartialEq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
#[repr(u8)]
pub enum VirtualClientAction {
    /// The author published a batch of KeyPackages.
    #[tls_codec(discriminant = 1)]
    KeyPackageUpload(KeyPackageUpload),
    /// The author asks the group to start a new derivation epoch.
    #[tls_codec(discriminant = 2)]
    NewDerivationEpoch,
}

/// A reference to a derivation epoch by its [`EpochId`].
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct VcEpochReference {
    epoch_id: EpochId,
}

impl VcEpochReference {
    /// The referenced epoch.
    pub fn epoch_id(&self) -> &EpochId {
        &self.epoch_id
    }
}

impl From<EpochId> for VcEpochReference {
    fn from(epoch_id: EpochId) -> Self {
        Self { epoch_id }
    }
}

impl From<VcEpochReference> for EpochId {
    fn from(reference: VcEpochReference) -> Self {
        reference.epoch_id
    }
}

/// The set of derivation epochs the author of a commit still uses.
///
/// Entries are unique and sorted by the TLS serialization of their `epoch_id`.
/// That order is a canonical encoding rule only. It says nothing about the
/// order in which the derivation epochs were created or should be used.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsSize)]
pub struct VcEpochUsage {
    in_use_epochs: Vec<VcEpochReference>,
}

impl VcEpochUsage {
    /// Build a usage declaration covering `epoch_ids`.
    ///
    /// The epochs are a set, so the caller may pass them in any order and may
    /// repeat them. Duplicates are dropped and the entries are put into the
    /// canonical order.
    pub fn new(epoch_ids: impl IntoIterator<Item = EpochId>) -> Result<Self, VcCommitDataError> {
        let mut keyed = epoch_ids
            .into_iter()
            .map(|epoch_id| Ok((epoch_id.tls_serialize_detached()?, epoch_id)))
            .collect::<Result<Vec<_>, tls_codec::Error>>()?;
        keyed.sort_by(|(left, _), (right, _)| left.cmp(right));
        keyed.dedup_by(|(left, _), (right, _)| left == right);
        Ok(Self {
            in_use_epochs: keyed
                .into_iter()
                .map(|(_, epoch_id)| VcEpochReference::from(epoch_id))
                .collect(),
        })
    }

    /// Build a usage declaration covering no epoch at all.
    ///
    /// This is not the same as omitting the declaration: it retires every epoch
    /// the author declared before.
    pub fn empty() -> Self {
        Self {
            in_use_epochs: Vec::new(),
        }
    }

    /// The entries in canonical order.
    pub fn in_use_epochs(&self) -> &[VcEpochReference] {
        &self.in_use_epochs
    }

    /// The referenced epochs in canonical order.
    pub fn epoch_ids(&self) -> impl Iterator<Item = &EpochId> {
        self.in_use_epochs.iter().map(VcEpochReference::epoch_id)
    }

    /// Returns true if no epoch is declared as in use.
    pub fn is_empty(&self) -> bool {
        self.in_use_epochs.is_empty()
    }

    fn from_entries(entries: Vec<VcEpochReference>) -> Result<Self, VcCommitDataError> {
        let mut previous: Option<Vec<u8>> = None;
        for entry in &entries {
            let current = entry.epoch_id.tls_serialize_detached()?;
            if let Some(previous) = &previous {
                match current.cmp(previous) {
                    Ordering::Equal => return Err(VcCommitDataError::DuplicateEpochId),
                    Ordering::Less => return Err(VcCommitDataError::EpochsNotSortedAscending),
                    Ordering::Greater => {}
                }
            }
            previous = Some(current);
        }
        Ok(Self {
            in_use_epochs: entries,
        })
    }
}

impl TlsDeserializeBytesTrait for VcEpochUsage {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error> {
        let (entries, rest) = Vec::<VcEpochReference>::tls_deserialize_bytes(bytes)?;
        let usage = VcEpochUsage::from_entries(entries)
            .map_err(|err| tls_codec::Error::DecodingError(err.to_string()))?;
        Ok((usage, rest))
    }
}

/// What a virtual client tells its siblings about a commit it authored.
#[derive(Debug, PartialEq, TlsSerialize, TlsSize)]
pub struct VirtualClientCommitData {
    epoch_usage: Option<VcEpochUsage>,
    actions: Vec<VirtualClientAction>,
}

impl VirtualClientCommitData {
    /// Assemble the commit data.
    ///
    /// Pass `None` for `epoch_usage` to leave the author's previous declaration
    /// in place, and `Some(VcEpochUsage::empty())` to replace it with the empty
    /// set.
    ///
    /// Returns an error if `actions` holds more than one
    /// [`VirtualClientAction::NewDerivationEpoch`].
    pub fn new(
        epoch_usage: Option<VcEpochUsage>,
        actions: Vec<VirtualClientAction>,
    ) -> Result<Self, VcCommitDataError> {
        Self::validate(&actions)?;
        Ok(Self {
            epoch_usage,
            actions,
        })
    }

    /// The author's epoch usage declaration, or `None` if the commit does not
    /// restate it.
    pub fn epoch_usage(&self) -> Option<&VcEpochUsage> {
        self.epoch_usage.as_ref()
    }

    /// All actions the commit performs.
    pub fn actions(&self) -> &[VirtualClientAction] {
        &self.actions
    }

    /// Adds a [`VirtualClientAction::NewDerivationEpoch`] action unless the
    /// commit data already carries one.
    pub(crate) fn require_new_derivation_epoch(&mut self) {
        if !self.creates_derivation_epoch() {
            self.actions.push(VirtualClientAction::NewDerivationEpoch);
        }
    }

    /// Returns true if the commit asks for a new derivation epoch.
    pub fn creates_derivation_epoch(&self) -> bool {
        self.actions
            .iter()
            .any(|action| matches!(action, VirtualClientAction::NewDerivationEpoch))
    }

    /// The KeyPackage batches the commit publishes, in wire order.
    pub fn key_package_uploads(&self) -> impl Iterator<Item = &KeyPackageUpload> {
        self.actions.iter().filter_map(|action| match action {
            VirtualClientAction::KeyPackageUpload(upload) => Some(upload),
            VirtualClientAction::NewDerivationEpoch => None,
        })
    }

    /// Wrap this commit data in a Safe AAD item tagged with
    /// [`VC_COMPONENT_ID`], ready to be attached to an outgoing commit.
    pub fn to_safe_aad_item(&self) -> Result<SafeAadItem, VcCommitDataError> {
        let data = self.tls_serialize_detached()?;
        Ok(SafeAadItem::new(VC_COMPONENT_ID, data))
    }

    /// Parse commit data from the bytes of a Safe AAD item tagged with
    /// [`VC_COMPONENT_ID`]. Rejects bytes left over after the struct.
    pub fn from_safe_aad_item_data(data: &[u8]) -> Result<Self, VcCommitDataError> {
        Ok(Self::tls_deserialize_exact_bytes(data)?)
    }

    /// Parse the commit data carried by `safe_aad` under [`VC_COMPONENT_ID`].
    ///
    /// Returns `Ok(None)` when `safe_aad` carries no such item.
    pub fn from_safe_aad(safe_aad: &SafeAad) -> Result<Option<Self>, VcCommitDataError> {
        safe_aad
            .get(VC_COMPONENT_ID)
            .map(Self::from_safe_aad_item_data)
            .transpose()
    }

    fn validate(actions: &[VirtualClientAction]) -> Result<(), VcCommitDataError> {
        let new_epoch_actions = actions
            .iter()
            .filter(|action| matches!(action, VirtualClientAction::NewDerivationEpoch))
            .count();
        if new_epoch_actions > 1 {
            return Err(VcCommitDataError::MultipleNewDerivationEpochs);
        }
        Ok(())
    }
}

impl TlsDeserializeBytesTrait for VirtualClientCommitData {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error> {
        let (epoch_usage, rest) = Option::<VcEpochUsage>::tls_deserialize_bytes(bytes)?;
        let (actions, rest) = Vec::<VirtualClientAction>::tls_deserialize_bytes(rest)?;
        let commit_data = VirtualClientCommitData::new(epoch_usage, actions)
            .map_err(|err| tls_codec::Error::DecodingError(err.to_string()))?;
        Ok((commit_data, rest))
    }
}

#[cfg(test)]
mod tests {
    use openmls_traits::types::Ciphersuite;

    use super::*;
    use crate::{
        binary_tree::LeafNodeIndex, ciphersuite::hash_ref::KeyPackageRef,
        components::vc_derivation_info::KeyPackageInfo,
    };

    const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    fn epoch_id(bytes: &[u8]) -> EpochId {
        EpochId::new(bytes.to_vec())
    }

    fn key_package_upload() -> KeyPackageUpload {
        KeyPackageUpload {
            epoch_id: epoch_id(b"epoch-for-upload"),
            leaf_index: LeafNodeIndex::new(3),
            generation: 7,
            key_package_info: vec![
                KeyPackageInfo {
                    key_package_ref: KeyPackageRef::from_slice(b"first key package ref"),
                    cipher_suite: CIPHERSUITE,
                    key_package_index: 0,
                },
                KeyPackageInfo {
                    key_package_ref: KeyPackageRef::from_slice(b"second key package ref"),
                    cipher_suite: CIPHERSUITE,
                    key_package_index: 1,
                },
            ],
        }
    }

    fn full_commit_data() -> VirtualClientCommitData {
        let usage = VcEpochUsage::new([epoch_id(b"aaa"), epoch_id(b"bb"), epoch_id(b"cccc")])
            .expect("epoch ids must serialize");
        VirtualClientCommitData::new(
            Some(usage),
            vec![
                VirtualClientAction::KeyPackageUpload(key_package_upload()),
                VirtualClientAction::NewDerivationEpoch,
            ],
        )
        .expect("one new_derivation_epoch action is valid")
    }

    #[test]
    fn vc_commit_data_roundtrip() {
        let commit_data = full_commit_data();

        let bytes = commit_data.tls_serialize_detached().unwrap();
        let parsed = VirtualClientCommitData::tls_deserialize_exact_bytes(&bytes).unwrap();

        assert_eq!(parsed, commit_data);
        assert_eq!(parsed.tls_serialize_detached().unwrap(), bytes);
        assert!(parsed.creates_derivation_epoch());
        assert_eq!(
            parsed.key_package_uploads().collect::<Vec<_>>(),
            vec![&key_package_upload()]
        );
        assert_eq!(
            parsed.epoch_usage().unwrap().in_use_epochs().len(),
            3,
            "all three epochs are distinct"
        );
    }

    #[test]
    fn vc_commit_data_absent_and_empty_epoch_usage_differ() {
        let absent = VirtualClientCommitData::new(None, Vec::new()).unwrap();
        let empty = VirtualClientCommitData::new(Some(VcEpochUsage::empty()), Vec::new()).unwrap();

        let absent_bytes = absent.tls_serialize_detached().unwrap();
        let empty_bytes = empty.tls_serialize_detached().unwrap();

        // `optional<>` prefixes the value with 0 for absent and 1 for present.
        // The present-but-empty case then adds the empty entry vector.
        assert_eq!(absent_bytes, vec![0x00, 0x00]);
        assert_eq!(empty_bytes, vec![0x01, 0x00, 0x00]);

        let parsed_absent =
            VirtualClientCommitData::tls_deserialize_exact_bytes(&absent_bytes).unwrap();
        let parsed_empty =
            VirtualClientCommitData::tls_deserialize_exact_bytes(&empty_bytes).unwrap();

        assert_eq!(parsed_absent.epoch_usage(), None);
        assert_eq!(parsed_empty.epoch_usage(), Some(&VcEpochUsage::empty()));
        assert!(parsed_empty.epoch_usage().unwrap().is_empty());
    }

    #[test]
    fn vc_commit_data_new_rejects_two_new_derivation_epochs() {
        let err = VirtualClientCommitData::new(
            None,
            vec![
                VirtualClientAction::NewDerivationEpoch,
                VirtualClientAction::NewDerivationEpoch,
            ],
        )
        .unwrap_err();

        assert_eq!(err, VcCommitDataError::MultipleNewDerivationEpochs);
    }

    #[test]
    fn vc_commit_data_deserialize_rejects_two_new_derivation_epochs() {
        // Hand-craft bytes the constructor would refuse to produce: absent
        // epoch usage followed by two `new_derivation_epoch` actions.
        let raw_bytes = vec![0x00, 0x02, 0x02, 0x02];

        let err = VirtualClientCommitData::tls_deserialize_exact_bytes(&raw_bytes).unwrap_err();
        match err {
            tls_codec::Error::DecodingError(message) => assert!(
                message.contains("more than one new_derivation_epoch"),
                "unexpected error message: {message}"
            ),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn vc_epoch_usage_new_sorts_and_dedups() {
        let usage = VcEpochUsage::new([
            epoch_id(b"cccc"),
            epoch_id(b"aaa"),
            epoch_id(b"bb"),
            epoch_id(b"aaa"),
        ])
        .unwrap();

        let epochs: Vec<&[u8]> = usage.epoch_ids().map(EpochId::as_bytes).collect();
        // Sorting compares the TLS serializations, which start with the length
        // prefix, so the shorter id sorts first regardless of its content.
        assert_eq!(epochs, vec![b"bb".as_slice(), b"aaa", b"cccc"]);
    }

    #[test]
    fn vc_epoch_usage_deserialize_rejects_unsorted() {
        let entries: Vec<VcEpochReference> = vec![
            epoch_id(b"cccc").into(),
            epoch_id(b"aaa").into(),
            epoch_id(b"bb").into(),
        ];
        let raw_bytes = entries.tls_serialize_detached().unwrap();

        let err = VcEpochUsage::tls_deserialize_exact_bytes(&raw_bytes).unwrap_err();
        match err {
            tls_codec::Error::DecodingError(message) => assert!(
                message.contains("not sorted"),
                "unexpected error message: {message}"
            ),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn vc_epoch_usage_deserialize_rejects_duplicates() {
        let entries: Vec<VcEpochReference> =
            vec![epoch_id(b"same").into(), epoch_id(b"same").into()];
        let raw_bytes = entries.tls_serialize_detached().unwrap();

        let err = VcEpochUsage::tls_deserialize_exact_bytes(&raw_bytes).unwrap_err();
        match err {
            tls_codec::Error::DecodingError(message) => assert!(
                message.contains("duplicate"),
                "unexpected error message: {message}"
            ),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn vc_epoch_usage_sorting_compares_serializations() {
        // A 64-byte id needs a two-byte length prefix, a 63-byte id one byte,
        // so the longer id sorts last even though its content byte is smaller.
        let short = epoch_id(&[0xff; 63]);
        let long = epoch_id(&[0x00; 64]);

        let usage = VcEpochUsage::new([long.clone(), short.clone()]).unwrap();

        let epochs: Vec<&EpochId> = usage.epoch_ids().collect();
        assert_eq!(epochs, vec![&short, &long]);
    }

    #[test]
    fn vc_action_deserialize_rejects_reserved_and_unknown_types() {
        for discriminant in [0x00u8, 0x03, 0xff] {
            let err = VirtualClientAction::tls_deserialize_exact_bytes(&[discriminant])
                .expect_err("only key_package_upload and new_derivation_epoch are valid");
            assert!(
                matches!(err, tls_codec::Error::UnknownValue(value) if value == discriminant as u64),
                "unexpected error variant for {discriminant}: {err:?}"
            );
        }
    }

    #[test]
    fn vc_commit_data_safe_aad_item_roundtrip() {
        let commit_data = full_commit_data();

        let item = commit_data.to_safe_aad_item().unwrap();
        assert_eq!(item.component_id(), VC_COMPONENT_ID);

        let parsed = VirtualClientCommitData::from_safe_aad_item_data(item.data()).unwrap();
        assert_eq!(parsed, commit_data);
    }

    #[test]
    fn vc_commit_data_from_item_data_rejects_trailing_bytes() {
        let mut data = full_commit_data()
            .to_safe_aad_item()
            .unwrap()
            .data()
            .to_vec();
        data.push(0x00);

        let err = VirtualClientCommitData::from_safe_aad_item_data(&data).unwrap_err();
        assert_eq!(
            err,
            VcCommitDataError::Codec(tls_codec::Error::TrailingData.to_string())
        );
    }
}
