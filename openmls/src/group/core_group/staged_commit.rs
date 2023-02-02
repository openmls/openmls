use openmls_traits::key_store::OpenMlsKeyStore;

use super::{super::errors::*, proposals::ProposalStore, *};
use crate::{
    group::public_group::{diff::StagedPublicGroupDiff, staged_commit::PrivateGroupParams},
    treesync::node::{encryption_keys::EncryptionKeyPair, leaf_node::OpenMlsLeafNode},
};
use core::fmt::Debug;
use std::mem;

impl CoreGroup {
    /// Stages a commit message that was sent by another group member.
    /// This function does the following:
    ///  - Applies the proposals covered by the commit to the tree
    ///  - Applies the (optional) update path to the tree
    ///  - Calculates the path secrets
    ///  - Initializes the key schedule for epoch rollover
    ///  - Verifies the confirmation tag/membership tag
    /// Returns a [StagedCommit] that can be inspected and later merged
    /// into the group state with [CoreGroup::merge_commit()]
    /// This function does the following checks:
    ///  - ValSem101
    ///  - ValSem102
    ///  - ValSem104
    ///  - ValSem105
    ///  - ValSem106
    ///  - ValSem107
    ///  - ValSem108
    ///  - ValSem110
    ///  - ValSem111
    ///  - ValSem112
    ///  - ValSem200
    ///  - ValSem201
    ///  - ValSem202: Path must be the right length
    ///  - ValSem203: Path secrets must decrypt correctly
    ///  - ValSem204: Public keys from Path must be verified and match the
    ///               private keys from the direct path
    ///  - ValSem205
    ///  - ValSem240
    ///  - ValSem241
    ///  - ValSem242
    ///  - ValSem243
    ///  - ValSem244
    /// Returns an error if the given commit was sent by the owner of this
    /// group.
    pub(crate) fn stage_commit(
        &self,
        mls_content: &AuthenticatedContent,
        proposal_store: &ProposalStore,
        own_leaf_nodes: &[OpenMlsLeafNode],
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<StagedCommit, StageCommitError> {
        // Check that the sender is another member of the group
        if let Sender::Member(member) = mls_content.sender() {
            if member == &self.own_leaf_index() {
                return Err(StageCommitError::OwnCommit);
            }
        }

        // All keys from the previous epoch are potential decryption keypairs.
        let old_epoch_keypairs = self.read_epoch_keypairs(backend);

        // If we are processing an update proposal that originally came from
        // us, the keypair corresponding to the leaf in the update is also a
        // potential decryption keypair.
        let leaf_node_keypairs = own_leaf_nodes
            .iter()
            .map(|leaf_node| {
                EncryptionKeyPair::read_from_key_store(backend, leaf_node.encryption_key())
                    .ok_or(StageCommitError::MissingDecryptionKey)
            })
            .collect::<Result<Vec<EncryptionKeyPair>, StageCommitError>>()?;

        let private_group_params = PrivateGroupParams {
            own_leaf_index: self.own_leaf_index(),
            epoch_secrets: self.group_epoch_secrets(),
            old_epoch_keypairs,
            leaf_node_keypairs,
        };

        self.public_group.stage_commit_private(
            mls_content,
            proposal_store,
            backend,
            private_group_params,
        )
    }

    /// Merges a [StagedCommit] into the group state and optionally return a [`SecretTree`]
    /// from the previous epoch. The secret tree is returned if the Commit does not contain a self removal.
    ///
    /// This function should not fail and only returns a [`Result`], because it
    /// might throw a `LibraryError`.
    pub(crate) fn merge_commit<KeyStore: OpenMlsKeyStore>(
        &mut self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        staged_commit: StagedCommit,
    ) -> Result<Option<MessageSecrets>, MergeCommitError<KeyStore::Error>> {
        // Get all keypairs from the old epoch, so we can later store the ones
        // that are still relevant in the new epoch.
        let old_epoch_keypairs = self.read_epoch_keypairs(backend);
        match staged_commit.state {
            StagedCommitState::SelfRemoved(staged_diff) => {
                self.public_group.merge_diff(*staged_diff);
                Ok(None)
            }
            StagedCommitState::GroupMember(state) => {
                self.group_epoch_secrets = state.group_epoch_secrets;

                // Replace the previous message secrets with the new ones and return the previous message secrets
                let mut message_secrets = state.message_secrets;
                mem::swap(
                    &mut message_secrets,
                    self.message_secrets_store.message_secrets_mut(),
                );

                self.public_group.merge_diff(state.staged_diff);

                // TODO #1194: Group storage and key storage should be
                // correlated s.t. there is no divergence between key material
                // and group state.

                let leaf_keypair = if let Some(keypair) = &state.new_leaf_keypair_option {
                    vec![keypair.clone()]
                } else {
                    vec![]
                };

                // Figure out which keys we need in the new epoch.
                let new_owned_encryption_keys = self
                    .public_group
                    .treesync()
                    .owned_encryption_keys(self.own_leaf_index());
                // From the old and new keys, keep the ones that are still relevant in the new epoch.
                let epoch_keypairs: Vec<EncryptionKeyPair> = old_epoch_keypairs
                    .into_iter()
                    .chain(state.new_keypairs.into_iter())
                    .chain(leaf_keypair.into_iter())
                    .filter(|keypair| new_owned_encryption_keys.contains(keypair.public_key()))
                    .collect();
                // We should have private keys for all owned encryption keys.

                debug_assert_eq!(new_owned_encryption_keys.len(), epoch_keypairs.len());
                if new_owned_encryption_keys.len() != epoch_keypairs.len() {
                    return Err(LibraryError::custom(
                        "We should have all the private key material we need.",
                    )
                    .into());
                }
                // Store the relevant keys under the new epoch
                self.store_epoch_keypairs(backend, epoch_keypairs.as_slice())
                    .map_err(MergeCommitError::KeyStoreError)?;
                // Delete the old keys.
                self.delete_previous_epoch_keypairs(backend)
                    .map_err(MergeCommitError::KeyStoreError)?;
                if let Some(keypair) = state.new_leaf_keypair_option {
                    keypair
                        .delete_from_key_store(backend)
                        .map_err(MergeCommitError::KeyStoreError)?;
                }

                Ok(Some(message_secrets))
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum StagedCommitState {
    SelfRemoved(Box<StagedPublicGroupDiff>),
    GroupMember(Box<MemberStagedCommitState>),
}

/// Contains the changes from a commit to the group state.
#[derive(Debug, Serialize, Deserialize)]
pub struct StagedCommit {
    staged_proposal_queue: ProposalQueue,
    state: StagedCommitState,
}

impl StagedCommit {
    /// Create a new [`StagedCommit`] from the provisional group state created
    /// during the commit process.
    pub(crate) fn new(staged_proposal_queue: ProposalQueue, state: StagedCommitState) -> Self {
        StagedCommit {
            staged_proposal_queue,
            state,
        }
    }

    /// Returns the Add proposals that are covered by the Commit message as in iterator over [QueuedAddProposal].
    pub fn add_proposals(&self) -> impl Iterator<Item = QueuedAddProposal> {
        self.staged_proposal_queue.add_proposals()
    }

    /// Returns the Remove proposals that are covered by the Commit message as in iterator over [QueuedRemoveProposal].
    pub fn remove_proposals(&self) -> impl Iterator<Item = QueuedRemoveProposal> {
        self.staged_proposal_queue.remove_proposals()
    }

    /// Returns the Update proposals that are covered by the Commit message as in iterator over [QueuedUpdateProposal].
    pub fn update_proposals(&self) -> impl Iterator<Item = QueuedUpdateProposal> {
        self.staged_proposal_queue.update_proposals()
    }

    /// Returns the PresharedKey proposals that are covered by the Commit message as in iterator over [QueuedPskProposal].
    pub fn psk_proposals(&self) -> impl Iterator<Item = QueuedPskProposal> {
        self.staged_proposal_queue.psk_proposals()
    }

    /// Returns `true` if the member was removed through a proposal covered by this Commit message
    /// and `false` otherwise.
    pub fn self_removed(&self) -> bool {
        matches!(self.state, StagedCommitState::SelfRemoved(_))
    }
}

/// This struct is used internally by [StagedCommit] to encapsulate all the modified group state.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MemberStagedCommitState {
    group_epoch_secrets: GroupEpochSecrets,
    message_secrets: MessageSecrets,
    staged_diff: StagedPublicGroupDiff,
    new_keypairs: Vec<EncryptionKeyPair>,
    new_leaf_keypair_option: Option<EncryptionKeyPair>,
}

impl MemberStagedCommitState {
    pub(crate) fn new(
        group_epoch_secrets: GroupEpochSecrets,
        message_secrets: MessageSecrets,
        staged_diff: StagedPublicGroupDiff,
        new_keypairs: Vec<EncryptionKeyPair>,
        new_leaf_keypair_option: Option<EncryptionKeyPair>,
    ) -> Self {
        Self {
            group_epoch_secrets,
            message_secrets,
            staged_diff,
            new_keypairs,
            new_leaf_keypair_option,
        }
    }
}
