//! # Group Context
//!
//! TODO: #779

use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};
use tls_codec::Serialize;

use crate::{
    error::LibraryError,
    framing::{mls_auth_content::AuthenticatedContent, ConfirmedTranscriptHashInput},
    versions::ProtocolVersion,
};

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

#[cfg(test)]
impl GroupContext {
    // XXX[KAT]: #1051 only used in KATs
    pub(crate) fn _set_epoch(&mut self, epoch: GroupEpoch) {
        self.epoch = epoch;
    }

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
        Self::new(
            ciphersuite,
            group_id,
            0,
            tree_hash,
            zero(ciphersuite.hash_length()),
            extensions,
        )
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
        backend: &impl OpenMlsCryptoProvider,
        interim_transcript_hash: &[u8],
        commit_content: &AuthenticatedContent,
    ) -> Result<(), LibraryError> {
        // Calculate the confirmed transcript hash
        let mls_plaintext_commit_content: &ConfirmedTranscriptHashInput =
            &ConfirmedTranscriptHashInput::try_from(commit_content)
                .map_err(|_| LibraryError::custom("PublicMessage did not contain a commit"))?;
        let commit_content_bytes: Vec<u8> = mls_plaintext_commit_content
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        self.confirmed_transcript_hash = backend
            .crypto()
            .hash(
                self.ciphersuite.hash_algorithm(),
                &[interim_transcript_hash, &commit_content_bytes].concat(),
            )
            .map_err(LibraryError::unexpected_crypto_error)?
            .into();
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

    /// Return the extensions.
    pub fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Get the required capabilities extension.
    pub fn required_capabilities(&self) -> Option<&RequiredCapabilitiesExtension> {
        self.extensions.required_capabilities()
    }
}
