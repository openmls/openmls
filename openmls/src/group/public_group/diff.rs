use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite, OpenMlsCryptoProvider};
use serde::{Deserialize, Serialize};
use tls_codec::Serialize as TlsSerialize;

use crate::{
    binary_tree::LeafNodeIndex,
    error::LibraryError,
    framing::{
        mls_auth_content::AuthenticatedContent,
        public_message::{ConfirmedTranscriptHashInput, InterimTranscriptHashInput},
    },
    group::GroupContext,
    messages::{proposals::AddProposal, ConfirmationTag, EncryptedGroupSecrets},
    schedule::{psk::PreSharedKeyId, CommitSecret, JoinerSecret},
    treesync::{
        diff::{StagedTreeSyncDiff, TreeSyncDiff},
        errors::ApplyUpdatePathError,
        node::{
            encryption_keys::EncryptionKeyPair, leaf_node::OpenMlsLeafNode,
            parent_node::PlainUpdatePathNode, Node,
        },
        treekem::{DecryptPathParams, UpdatePath},
    },
};

use super::PublicGroup;

pub(crate) mod apply_proposals;
pub(crate) mod process_path;

pub(crate) struct PublicGroupDiff<'a> {
    original_group: &'a PublicGroup,
    diff: TreeSyncDiff<'a>,
    group_context: GroupContext,
    interim_transcript_hash: Vec<u8>,
    // Most recent confirmation tag. Kept here for verification purposes.
    confirmation_tag: ConfirmationTag,
}

impl<'a> PublicGroupDiff<'a> {
    /// Create a new [`PublicGroupDiff`] based on the given [`PublicGroup`].
    pub(super) fn new(public_group: &'a PublicGroup) -> PublicGroupDiff<'a> {
        Self {
            original_group: public_group,
            diff: public_group.treesync().empty_diff(),
            group_context: public_group.group_context().clone(),
            interim_transcript_hash: public_group.interim_transcript_hash.to_vec(),
            confirmation_tag: public_group.confirmation_tag().clone(),
        }
    }

    /// Turn this [`PublicGroupDiff`] into a [`StagedPublicGroupDiff`], thus
    /// freezing it until it is merged with the original [`PublicGroup`].
    pub(crate) fn into_staged_diff(
        self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
    ) -> Result<StagedPublicGroupDiff, LibraryError> {
        let staged_diff = self.diff.into_staged_diff(backend, ciphersuite)?;
        Ok(StagedPublicGroupDiff {
            staged_diff,
            group_context: self.group_context,
            interim_transcript_hash: self.interim_transcript_hash,
            confirmation_tag: self.confirmation_tag,
        })
    }

    /// Prepare the [`EncryptedGroupSecrets`] for a number of `invited_members`
    /// based on this [`PublicGroupDiff`]. If a slice of [`PlainUpdatePathNode`]
    /// is given, they are included in the [`GroupSecrets`] of the path.
    ///
    /// Returns an error if
    ///  - the own node is outside the tree
    ///  - the invited members are not part of the tree yet
    ///  - the leaf index of a new member is identical to the own leaf index
    ///  - the plain path does not contain the correct secrets
    pub(crate) fn encrypt_group_secrets(
        &self,
        joiner_secret: &JoinerSecret,
        invited_members: Vec<(LeafNodeIndex, AddProposal)>,
        plain_path_option: Option<&[PlainUpdatePathNode]>,
        presharedkeys: &[PreSharedKeyId],
        backend: &impl OpenMlsCryptoProvider,
        leaf_index: LeafNodeIndex,
    ) -> Result<Vec<EncryptedGroupSecrets>, LibraryError> {
        self.diff.encrypt_group_secrets(
            joiner_secret,
            invited_members,
            plain_path_option,
            presharedkeys,
            backend,
            leaf_index,
        )
    }

    /// Returns the number of leaves in the tree that would result from merging
    /// this diff.
    pub(crate) fn leaf_count(&self) -> u32 {
        self.diff.leaf_count()
    }

    /// Returns a vector of all nodes in the tree resulting from merging this
    /// diff.
    pub(crate) fn export_nodes(&self) -> Vec<Option<Node>> {
        self.diff.export_nodes()
    }

    /// Decrypt an [`UpdatePath`] originating from the given
    /// `sender_leaf_index`. The `group_context` is used in the decryption
    /// process and the `exclusion_list` is used to determine the position of
    /// the ciphertext in the `UpdatePath` that we can decrypt.
    ///
    /// Returns the [`CommitSecret`] resulting from their derivation. Returns an
    /// error if the `sender_leaf_index` is outside of the tree.
    ///
    /// ValSem203: Path secrets must decrypt correctly
    /// ValSem204: Public keys from Path must be verified and match the private keys from the direct path
    /// TODO #804
    pub(crate) fn decrypt_path(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        params: DecryptPathParams,
        owned_keys: &[&EncryptionKeyPair],
        own_leaf_index: LeafNodeIndex,
    ) -> Result<(Vec<EncryptionKeyPair>, CommitSecret), ApplyUpdatePathError> {
        self.diff
            .decrypt_path(backend, ciphersuite, params, owned_keys, own_leaf_index)
    }

    /// Return a reference to the leaf with the given index.
    pub(crate) fn leaf(&self, index: LeafNodeIndex) -> Option<&OpenMlsLeafNode> {
        self.diff.leaf(index)
    }

    /// Set the given path as the direct path of the `sender_leaf_index` and
    /// replace the [`LeafNode`] in the corresponding leaf with the given one.
    ///
    /// Returns an error if the `sender_leaf_index` is outside of the tree.
    /// ValSem202: Path must be the right length
    /// TODO #804
    pub(crate) fn apply_received_update_path(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        sender_leaf_index: LeafNodeIndex,
        update_path: &UpdatePath,
    ) -> Result<(), ApplyUpdatePathError> {
        self.diff
            .apply_received_update_path(backend, ciphersuite, sender_leaf_index, update_path)
    }

    /// Update the interim transcript hash of the diff and store the
    /// confirmation tag s.t. it can later be merged back into the original
    /// group.
    pub(crate) fn update_interim_transcript_hash(
        &mut self,
        ciphersuite: Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        confirmation_tag: ConfirmationTag,
    ) -> Result<(), LibraryError> {
        self.confirmation_tag = confirmation_tag;
        self.interim_transcript_hash = {
            let mls_plaintext_commit_auth_data =
                &InterimTranscriptHashInput::from(&self.confirmation_tag);
            let confirmed_transcript_hash = self.group_context.confirmed_transcript_hash();
            let commit_auth_data_bytes = mls_plaintext_commit_auth_data
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?;
            backend
                .crypto()
                .hash(
                    ciphersuite.hash_algorithm(),
                    &[confirmed_transcript_hash, &commit_auth_data_bytes].concat(),
                )
                .map_err(LibraryError::unexpected_crypto_error)
        }?;
        Ok(())
    }

    /// Update the [`GroupContext`] of the diff using the given
    /// `commit_content`. This includes computing the confirmed transcript hash,
    /// tree hash computation and epoch incrementation.
    pub(crate) fn update_group_context(
        &mut self,
        ciphersuite: Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        commit_content: &AuthenticatedContent,
    ) -> Result<(), LibraryError> {
        // Calculate the confirmed transcript hash
        let confirmed_transcript_hash = {
            let mls_plaintext_commit_content: &ConfirmedTranscriptHashInput =
                &ConfirmedTranscriptHashInput::try_from(commit_content)
                    .map_err(|_| LibraryError::custom("PublicMessage did not contain a commit"))?;
            let interim_transcript_hash = self.original_group.interim_transcript_hash();
            let commit_content_bytes = mls_plaintext_commit_content
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?;
            backend
                .crypto()
                .hash(
                    ciphersuite.hash_algorithm(),
                    &[interim_transcript_hash, &commit_content_bytes].concat(),
                )
                .map_err(LibraryError::unexpected_crypto_error)
        }?;

        // Calculate tree hash
        let tree_hash = self.diff.compute_tree_hashes(backend, ciphersuite)?;
        let mut new_epoch = self.original_group.group_context().epoch();
        new_epoch.increment();
        // Calculate group context
        self.group_context = GroupContext::new(
            ciphersuite,
            self.original_group.group_context().group_id().clone(),
            new_epoch,
            tree_hash,
            confirmed_transcript_hash,
            self.original_group.group_context.extensions().clone(),
        );
        Ok(())
    }

    /// Returns the current [`GroupContext`] of this diff.
    pub(crate) fn group_context(&self) -> &GroupContext {
        &self.group_context
    }
}

/// The staged version of a [`PublicGroupDiff`], which means it can no longer be
/// modified. Its only use is to merge it into the original [`PublicGroup`].
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StagedPublicGroupDiff {
    pub(super) staged_diff: StagedTreeSyncDiff,
    pub(super) group_context: GroupContext,
    pub(super) interim_transcript_hash: Vec<u8>,
    pub(super) confirmation_tag: ConfirmationTag,
}
