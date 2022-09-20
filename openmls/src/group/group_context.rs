//! # Group Context
//!
//! TODO: #779

use openmls_traits::types::Ciphersuite;

use super::*;

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct GroupContext {
    group_id: GroupId,
    epoch: GroupEpoch,
    tree_hash: TlsByteVecU8,
    confirmed_transcript_hash: TlsByteVecU8,
    extensions: TlsVecU32<Extension>,
}

#[cfg(any(feature = "test-utils", test))]
impl GroupContext {
    pub(crate) fn set_epoch(&mut self, epoch: GroupEpoch) {
        self.epoch = epoch;
    }
}

impl GroupContext {
    /// Create a new group context
    pub(crate) fn new(
        group_id: GroupId,
        epoch: impl Into<GroupEpoch>,
        tree_hash: Vec<u8>,
        confirmed_transcript_hash: Vec<u8>,
        extensions: &[Extension],
    ) -> Self {
        GroupContext {
            group_id,
            epoch: epoch.into(),
            tree_hash: tree_hash.into(),
            confirmed_transcript_hash: confirmed_transcript_hash.into(),
            extensions: extensions.into(),
        }
    }

    /// Create the `GroupContext` needed upon creation of a new group.
    pub(crate) fn create_initial_group_context(
        ciphersuite: Ciphersuite,
        group_id: GroupId,
        tree_hash: Vec<u8>,
        extensions: &[Extension],
    ) -> Self {
        Self::new(
            group_id,
            0,
            tree_hash,
            zero(ciphersuite.hash_length()),
            extensions,
        )
    }

    /// Return the group ID
    pub(crate) fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// Return the epoch
    pub(crate) fn epoch(&self) -> GroupEpoch {
        self.epoch
    }

    /// Return the extensions of the context
    pub(crate) fn extensions(&self) -> &[Extension] {
        self.extensions.as_slice()
    }

    /// Get the required capabilities extension.
    pub(crate) fn required_capabilities(&self) -> Option<&RequiredCapabilitiesExtension> {
        self.extensions
            .iter()
            .find(|e| e.extension_type() == ExtensionType::RequiredCapabilities)
            .and_then(|e| e.as_required_capabilities_extension().ok())
    }

    /// Return the confirmed transcript hash
    pub(crate) fn confirmed_transcript_hash(&self) -> &[u8] {
        self.confirmed_transcript_hash.as_slice()
    }
}
