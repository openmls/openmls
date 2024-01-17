//! # Group Context
//!
//! TODO: #779

use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::Ciphersuite;

use super::*;
use crate::{
    error::LibraryError,
    framing::{mls_auth_content::AuthenticatedContent, ConfirmedTranscriptHashInput},
    versions::ProtocolVersion,
};

/// 8.1 Group Context
///
///```c
/// struct {
///     ProtocolVersion version = mls10;
///     CipherSuite cipher_suite;
///     opaque group_id<V>;
///     uint64 epoch;
///     opaque tree_hash<V>;
///     opaque confirmed_transcript_hash<V>;
///     Extension extensions<V>;
/// } GroupContext;
///
/// The [`GroupContext`] is a state object maintained which summarizes the group
/// state agreed upon by each member of the group.
///```
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
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

    /// Set the ciphersuite
    #[cfg(test)]
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
            extensions,
        }
    }

    /// Create the `GroupContext` needed upon creation of a new group.
    pub(crate) fn create_initial_group_context(
        ciphersuite: Ciphersuite,
        group_id: GroupId,
        tree_hash: Vec<u8>,
        extensions: Extensions,
    ) -> Self {
        // Note: Confirmed transcript hash is "The zero-length octet string."
        Self::new(ciphersuite, group_id, 0, tree_hash, vec![], extensions)
    }

    /// Increment the current [`GroupEpoch`] by one.
    pub(crate) fn increment_epoch(&mut self) {
        self.epoch.increment()
    }

    /// Update the current tree hash to the new value
    pub(crate) fn update_tree_hash(&mut self, new_tree_hash: Vec<u8>) {
        self.tree_hash = new_tree_hash.into()
    }

    /// Update the confirmed transcript hash using the given
    /// `interim_transcript_hash`, as well as the `commit_content`.
    pub(crate) fn update_confirmed_transcript_hash(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        interim_transcript_hash: &[u8],
        authenticated_content: &AuthenticatedContent,
    ) -> Result<(), LibraryError> {
        let confirmed_transcript_hash = {
            let input = ConfirmedTranscriptHashInput::try_from(authenticated_content)
                .map_err(|_| LibraryError::custom("PublicMessage did not contain a commit"))?;

            input.calculate_confirmed_transcript_hash(
                crypto,
                self.ciphersuite,
                interim_transcript_hash,
            )?
        };

        self.confirmed_transcript_hash = confirmed_transcript_hash.into();

        Ok(())
    }

    /// Return the protocol version.
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Return the ciphersuite.
    pub fn ciphersuite(&self) -> Ciphersuite {
        self.ciphersuite
    }

    /// Return the group ID.
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// Return the epoch.
    pub fn epoch(&self) -> GroupEpoch {
        self.epoch
    }

    /// Return the tree hash.
    pub fn tree_hash(&self) -> &[u8] {
        self.tree_hash.as_slice()
    }

    /// Return the confirmed transcript hash.
    pub fn confirmed_transcript_hash(&self) -> &[u8] {
        self.confirmed_transcript_hash.as_slice()
    }

    pub(crate) fn set_extensions(&mut self, extensions: Extensions) {
        self.extensions = extensions;
    }

    /// Return the extensions.
    pub fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Get the required capabilities extension.
    pub fn required_capabilities(&self) -> Option<&RequiredCapabilitiesExtension> {
        self.extensions.required_capabilities()
    }
}
