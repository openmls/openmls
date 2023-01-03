//! # Group Context
//!
//! TODO: #779

use openmls_traits::types::Ciphersuite;

use crate::versions::ProtocolVersion;

use super::*;

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct GroupContext {
    protocol_version: ProtocolVersion,
    ciphersuite: Ciphersuite,
    group_id: GroupId,
    epoch: GroupEpoch,
    tree_hash: VLBytes,
    confirmed_transcript_hash: VLBytes,
    extensions: Extensions,
}

#[cfg(any(feature = "test-utils", test))]
impl GroupContext {
    pub(crate) fn set_epoch(&mut self, epoch: GroupEpoch) {
        self.epoch = epoch;
    }
}

#[cfg(test)]
impl GroupContext {
    /// Set the ciphersuite
    pub(crate) fn set_ciphersuite(&mut self, ciphersuite: Ciphersuite) {
        self.ciphersuite = ciphersuite;
    }
}

impl GroupContext {
    /// Create a new group context
    pub(crate) fn new(
        ciphersuite: Ciphersuite,
        group_id: GroupId,
        epoch: impl Into<GroupEpoch>,
        tree_hash: Vec<u8>,
        confirmed_transcript_hash: Vec<u8>,
        extensions: Extensions,
    ) -> Self {
        GroupContext {
            ciphersuite,
            protocol_version: ProtocolVersion::Mls10,
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
        extensions: Extensions,
    ) -> Self {
        Self::new(
            ciphersuite,
            group_id,
            0,
            tree_hash,
            zero(ciphersuite.hash_length()),
            extensions,
        )
    }

    /// Return the protocol version.
    pub(crate) fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Return the ciphersuite.
    pub(crate) fn ciphersuite(&self) -> Ciphersuite {
        self.ciphersuite
    }

    /// Return the group ID.
    pub(crate) fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// Return the epoch.
    pub(crate) fn epoch(&self) -> GroupEpoch {
        self.epoch
    }

    /// Return the tree hash.
    pub(crate) fn tree_hash(&self) -> &[u8] {
        self.tree_hash.as_slice()
    }

    /// Return the confirmed transcript hash.
    pub(crate) fn confirmed_transcript_hash(&self) -> &[u8] {
        self.confirmed_transcript_hash.as_slice()
    }

    /// Return the extensions.
    pub(crate) fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Get the required capabilities extension.
    pub(crate) fn required_capabilities(&self) -> Option<&RequiredCapabilitiesExtension> {
        self.extensions.required_capabilities()
    }
}
