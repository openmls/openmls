//! Virtual-clients commit data (mls-virtual-clients draft).
//!
//! A virtual client attaches this struct to a commit as a Safe AAD item under
//! [`VC_COMPONENT_ID`]. It tells the sibling emulators which actions the commit
//! performs.
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
//!   VirtualClientAction actions<V>;
//! } VirtualClientCommitData;
//! ```
//!
//! A [`VirtualClientCommitData`] carries at most one `new_derivation_epoch`
//! action. That rule is enforced on construction and on deserialization.
//!
//! [`VC_COMPONENT_ID`]: crate::components::vc_derivation_info::VC_COMPONENT_ID
//! [`VirtualClientCommitData`]: crate::components::vc_commit_data::VirtualClientCommitData

use tls_codec::{
    DeserializeBytes as TlsDeserializeBytesTrait, Serialize as TlsSerializeTrait,
    TlsDeserializeBytes, TlsSerialize, TlsSize,
};

use crate::{
    components::vc_derivation_info::{KeyPackageUpload, VC_COMPONENT_ID},
    framing::{SafeAad, SafeAadItem},
};

/// Errors that can occur when building or parsing a [`VirtualClientCommitData`].
#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum VcCommitDataError {
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

/// What a virtual client tells its siblings about a commit it authored.
#[derive(Debug, PartialEq, TlsSerialize, TlsSize)]
pub struct VirtualClientCommitData {
    actions: Vec<VirtualClientAction>,
}

impl VirtualClientCommitData {
    /// Assemble the commit data.
    ///
    /// Returns an error if `actions` holds more than one
    /// [`VirtualClientAction::NewDerivationEpoch`].
    pub fn new(actions: Vec<VirtualClientAction>) -> Result<Self, VcCommitDataError> {
        Self::validate(&actions)?;
        Ok(Self { actions })
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
        let (actions, rest) = Vec::<VirtualClientAction>::tls_deserialize_bytes(bytes)?;
        let commit_data = VirtualClientCommitData::new(actions)
            .map_err(|err| tls_codec::Error::DecodingError(err.to_string()))?;
        Ok((commit_data, rest))
    }
}

#[cfg(test)]
mod tests {
    use openmls_traits::types::Ciphersuite;

    use super::*;
    use crate::{
        binary_tree::LeafNodeIndex,
        ciphersuite::hash_ref::KeyPackageRef,
        components::vc_derivation_info::{EpochId, KeyPackageInfo},
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
        VirtualClientCommitData::new(vec![
            VirtualClientAction::KeyPackageUpload(key_package_upload()),
            VirtualClientAction::NewDerivationEpoch,
        ])
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
    }

    #[test]
    fn vc_commit_data_new_rejects_two_new_derivation_epochs() {
        let err = VirtualClientCommitData::new(vec![
            VirtualClientAction::NewDerivationEpoch,
            VirtualClientAction::NewDerivationEpoch,
        ])
        .unwrap_err();

        assert_eq!(err, VcCommitDataError::MultipleNewDerivationEpochs);
    }

    #[test]
    fn vc_commit_data_deserialize_rejects_two_new_derivation_epochs() {
        // Hand-craft bytes the constructor would refuse to produce: two
        // `new_derivation_epoch` actions.
        let raw_bytes = vec![0x02, 0x02, 0x02];

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
