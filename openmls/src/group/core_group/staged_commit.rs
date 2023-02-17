use core::fmt::Debug;
use std::mem;

use openmls_traits::key_store::OpenMlsKeyStore;
use public_group::diff::{apply_proposals::ApplyProposalsValues, StagedPublicGroupDiff};

use super::{super::errors::*, proposals::ProposalStore, *};
use crate::treesync::node::encryption_keys::EncryptionKeyPair;

impl CoreGroup {
    fn derive_epoch_secrets(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        apply_proposals_values: ApplyProposalsValues,
        epoch_secrets: &GroupEpochSecrets,
        commit_secret: CommitSecret,
        serialized_provisional_group_context: &[u8],
    ) -> Result<EpochSecrets, StageCommitError> {
        // Check if we need to include the init secret from an external commit
        // we applied earlier or if we use the one from the previous epoch.
        let joiner_secret = if let Some(ref external_init_proposal) =
            apply_proposals_values.external_init_proposal_option
        {
            // Decrypt the content and derive the external init secret.
            let external_priv = epoch_secrets
                .external_secret()
                .derive_external_keypair(backend.crypto(), self.ciphersuite())
                .private
                .into();
            let init_secret = InitSecret::from_kem_output(
                backend,
                self.ciphersuite(),
                self.version(),
                &external_priv,
                external_init_proposal.kem_output(),
            )?;
            JoinerSecret::new(
                backend,
                commit_secret,
                &init_secret,
                serialized_provisional_group_context,
            )
            .map_err(LibraryError::unexpected_crypto_error)?
        } else {
            JoinerSecret::new(
                backend,
                commit_secret,
                epoch_secrets.init_secret(),
                serialized_provisional_group_context,
            )
            .map_err(LibraryError::unexpected_crypto_error)?
        };

        // Prepare the PskSecret
        let psk_secret = PskSecret::new(
            self.ciphersuite(),
            backend,
            &apply_proposals_values.presharedkeys,
        )?;

        // Create key schedule
        let mut key_schedule =
            KeySchedule::init(self.ciphersuite(), backend, joiner_secret, psk_secret)?;

        key_schedule
            .add_context(backend, serialized_provisional_group_context)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        Ok(key_schedule
            .epoch_secrets(backend)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?)
    }

    /// Stages a commit message that was sent by another group member.
    /// This function does the following:
    ///  - Applies the proposals covered by the commit to the tree
    ///  - Applies the (optional) update path to the tree
    ///  - Decrypts and calculates the path secrets
    ///  - Initializes the key schedule for epoch rollover
    ///  - Verifies the confirmation tag
    ///
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
        old_epoch_keypairs: Vec<EncryptionKeyPair>,
        leaf_node_keypairs: Vec<EncryptionKeyPair>,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<StagedCommit, StageCommitError> {
        // Check that the sender is another member of the group
        if let Sender::Member(member) = mls_content.sender() {
            if member == &self.own_leaf_index() {
                return Err(StageCommitError::OwnCommit);
            }
        }

        let ciphersuite = self.ciphersuite();

        let (commit, proposal_queue, sender_index) =
            self.public_group
                .validate_commit(mls_content, proposal_store, backend)?;

        // Create the provisional public group state (including the tree and
        // group context) and apply proposals.
        let mut diff = self.public_group.empty_diff();

        let apply_proposals_values =
            diff.apply_proposals(&proposal_queue, self.own_leaf_index())?;

        // Check if we were removed from the group
        if apply_proposals_values.self_removed {
            let staged_diff = diff.into_staged_diff(backend, ciphersuite)?;
            return Ok(StagedCommit::new(
                proposal_queue,
                StagedCommitState::PublicState(Box::new(staged_diff)),
            ));
        }

        // Determine if Commit has a path
        let (commit_secret, new_keypairs, new_leaf_keypair_option) =
            if let Some(path) = commit.path.clone() {
                // Update the public group
                // ValSem202: Path must be the right length
                diff.apply_received_update_path(backend, ciphersuite, sender_index, &path)?;

                // Update group context
                diff.update_group_context(backend)?;

                let decryption_keypairs: Vec<&EncryptionKeyPair> = old_epoch_keypairs
                    .iter()
                    .chain(leaf_node_keypairs.iter())
                    .collect();

                // ValSem203: Path secrets must decrypt correctly
                // ValSem204: Public keys from Path must be verified and match the private keys from the direct path
                let (new_keypairs, commit_secret) = diff.decrypt_path(
                    backend,
                    &decryption_keypairs,
                    self.own_leaf_index(),
                    sender_index,
                    path.nodes(),
                    &apply_proposals_values.exclusion_list(),
                )?;

                // Check if one of our update proposals was applied. If so, we
                // need to store that keypair separately, because after merging
                // it needs to be removed from the key store separately and in
                // addition to the removal of the keypairs of the previous
                // epoch.
                let new_leaf_keypair_option = if let Some(leaf) = diff.leaf(self.own_leaf_index()) {
                    leaf_node_keypairs.into_iter().find_map(|keypair| {
                        if leaf.encryption_key() == keypair.public_key() {
                            Some(keypair)
                        } else {
                            None
                        }
                    })
                } else {
                    // We should have an own leaf at this point.
                    debug_assert!(false);
                    None
                };
                (commit_secret, new_keypairs, new_leaf_keypair_option)
            } else {
                if apply_proposals_values.path_required {
                    // ValSem201
                    return Err(StageCommitError::RequiredPathNotFound);
                }

                // Even if there is no path, we have to update the group context.
                diff.update_group_context(backend)?;

                (
                    CommitSecret::zero_secret(ciphersuite, self.version()),
                    vec![],
                    None,
                )
            };

        // Update the confirmed transcript hash before we compute the confirmation tag.
        diff.update_confirmed_transcript_hash(backend, mls_content)?;

        let received_confirmation_tag = mls_content
            .confirmation_tag()
            .ok_or(StageCommitError::ConfirmationTagMissing)?;

        let serialized_provisional_group_context = diff
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        let (provisional_group_secrets, provisional_message_secrets) = self
            .derive_epoch_secrets(
                backend,
                apply_proposals_values,
                self.group_epoch_secrets(),
                commit_secret,
                &serialized_provisional_group_context,
            )?
            .split_secrets(
                serialized_provisional_group_context,
                diff.tree_size(),
                self.own_leaf_index(),
            );

        // Verify confirmation tag
        // ValSem205
        let own_confirmation_tag = provisional_message_secrets
            .confirmation_key()
            .tag(backend, diff.group_context().confirmed_transcript_hash())
            .map_err(LibraryError::unexpected_crypto_error)?;
        if &own_confirmation_tag != received_confirmation_tag {
            log::error!("Confirmation tag mismatch");
            log_crypto!(trace, "  Got:      {:x?}", received_confirmation_tag);
            log_crypto!(trace, "  Expected: {:x?}", own_confirmation_tag);
            // TODO: We have tests expecting this error.
            //       They need to be rewritten.
            // debug_assert!(false, "Confirmation tag mismatch");
            return Err(StageCommitError::ConfirmationTagMismatch);
        }

        diff.update_interim_transcript_hash(ciphersuite, backend, own_confirmation_tag)?;

        let staged_diff = diff.into_staged_diff(backend, ciphersuite)?;
        let staged_commit_state =
            StagedCommitState::GroupMember(Box::new(MemberStagedCommitState::new(
                provisional_group_secrets,
                provisional_message_secrets,
                staged_diff,
                new_keypairs,
                new_leaf_keypair_option,
            )));

        Ok(StagedCommit::new(proposal_queue, staged_commit_state))
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
            StagedCommitState::PublicState(staged_diff) => {
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

    #[cfg(test)]
    /// Helper function that reads the decryption keys from the key store
    /// (unwrapping the result) and stages the given commit.
    pub(crate) fn read_keys_and_stage_commit(
        &self,
        mls_content: &AuthenticatedContent,
        proposal_store: &ProposalStore,
        own_leaf_nodes: &[OpenMlsLeafNode],
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<StagedCommit, StageCommitError> {
        let (old_epoch_keypairs, leaf_node_keypairs) = self
            .read_decryption_keypairs(backend, own_leaf_nodes)
            .unwrap();

        self.stage_commit(
            mls_content,
            proposal_store,
            old_epoch_keypairs,
            leaf_node_keypairs,
            backend,
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum StagedCommitState {
    PublicState(Box<StagedPublicGroupDiff>),
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
        matches!(self.state, StagedCommitState::PublicState(_))
    }

    /// Consume this [`StagedCommit`] and return the internal [`StagedCommitState`].
    pub(crate) fn into_state(self) -> StagedCommitState {
        self.state
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
