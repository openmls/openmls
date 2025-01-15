use core::fmt::Debug;
use std::mem;

use openmls_traits::storage::StorageProvider;
use serde::{Deserialize, Serialize};
use tls_codec::Serialize as _;

use super::proposal_store::{
    QueuedAddProposal, QueuedPskProposal, QueuedRemoveProposal, QueuedUpdateProposal,
};

use super::{
    super::errors::*, load_psks, Credential, Extension, GroupContext, GroupEpochSecrets, GroupId,
    JoinerSecret, KeySchedule, LeafNode, LibraryError, MessageSecrets, MlsGroup, OpenMlsProvider,
    Proposal, ProposalQueue, PskSecret, QueuedProposal, Sender,
};
use crate::{
    ciphersuite::{hash_ref::ProposalRef, Secret},
    framing::mls_auth_content::AuthenticatedContent,
    group::public_group::{
        diff::{apply_proposals::ApplyProposalsValues, StagedPublicGroupDiff},
        staged_commit::PublicStagedCommitState,
    },
    schedule::{CommitSecret, EpochAuthenticator, EpochSecrets, InitSecret, PreSharedKeyId},
    treesync::node::encryption_keys::EncryptionKeyPair,
};

impl MlsGroup {
    fn derive_epoch_secrets(
        &self,
        provider: &impl OpenMlsProvider,
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
                .derive_external_keypair(provider.crypto(), self.ciphersuite())
                .map_err(LibraryError::unexpected_crypto_error)?
                .private;
            let init_secret = InitSecret::from_kem_output(
                provider.crypto(),
                self.ciphersuite(),
                self.version(),
                &external_priv,
                external_init_proposal.kem_output(),
            )?;
            JoinerSecret::new(
                provider.crypto(),
                self.ciphersuite(),
                commit_secret,
                &init_secret,
                serialized_provisional_group_context,
            )
            .map_err(LibraryError::unexpected_crypto_error)?
        } else {
            JoinerSecret::new(
                provider.crypto(),
                self.ciphersuite(),
                commit_secret,
                epoch_secrets.init_secret(),
                serialized_provisional_group_context,
            )
            .map_err(LibraryError::unexpected_crypto_error)?
        };

        // Prepare the PskSecret
        // Fails if PSKs are missing ([valn1205](https://validation.openmls.tech/#valn1205))
        let psk_secret = {
            let psks: Vec<(&PreSharedKeyId, Secret)> = load_psks(
                provider.storage(),
                &self.resumption_psk_store,
                &apply_proposals_values.presharedkeys,
            )?;

            PskSecret::new(provider.crypto(), self.ciphersuite(), psks)?
        };

        // Create key schedule
        let mut key_schedule = KeySchedule::init(
            self.ciphersuite(),
            provider.crypto(),
            &joiner_secret,
            psk_secret,
        )?;

        key_schedule
            .add_context(provider.crypto(), serialized_provisional_group_context)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        Ok(key_schedule
            .epoch_secrets(provider.crypto(), self.ciphersuite())
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?)
    }

    /// Stages a commit message that was sent by another group member. This
    /// function does the following:
    ///  - Applies the proposals covered by the commit to the tree
    ///  - Applies the (optional) update path to the tree
    ///  - Decrypts and calculates the path secrets
    ///  - Initializes the key schedule for epoch rollover
    ///  - Verifies the confirmation tag
    ///
    /// Returns a [StagedCommit] that can be inspected and later merged into the
    /// group state with [MlsGroup::merge_commit()] This function does the
    /// following checks:
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
    ///  - ValSem113: All Proposals: The proposal type must be supported by all
    ///               members of the group
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
    ///  - ValSem244 Returns an error if the given commit was sent by the owner
    ///              of this group.
    pub(crate) fn stage_commit(
        &self,
        mls_content: &AuthenticatedContent,
        old_epoch_keypairs: Vec<EncryptionKeyPair>,
        leaf_node_keypairs: Vec<EncryptionKeyPair>,
        provider: &impl OpenMlsProvider,
    ) -> Result<StagedCommit, StageCommitError> {
        // Check that the sender is another member of the group
        if let Sender::Member(member) = mls_content.sender() {
            if member == &self.own_leaf_index() {
                return Err(StageCommitError::OwnCommit);
            }
        }

        let ciphersuite = self.ciphersuite();

        let (commit, proposal_queue, sender_index) = self
            .public_group
            .validate_commit(mls_content, provider.crypto())?;

        // Create the provisional public group state (including the tree and
        // group context) and apply proposals.
        let mut diff = self.public_group.empty_diff();

        let apply_proposals_values =
            diff.apply_proposals(&proposal_queue, self.own_leaf_index())?;

        // Determine if Commit has a path
        let (commit_secret, new_keypairs, new_leaf_keypair_option, update_path_leaf_node) =
            if let Some(path) = commit.path.clone() {
                // Update the public group
                // ValSem202: Path must be the right length
                diff.apply_received_update_path(
                    provider.crypto(),
                    ciphersuite,
                    sender_index,
                    &path,
                )?;

                // Update group context
                diff.update_group_context(
                    provider.crypto(),
                    apply_proposals_values.extensions.clone(),
                )?;

                // Check if we were removed from the group
                if apply_proposals_values.self_removed {
                    // If so, we return here, because we can't decrypt the path
                    let staged_diff = diff.into_staged_diff(provider.crypto(), ciphersuite)?;
                    let staged_state = PublicStagedCommitState::new(
                        staged_diff,
                        commit.path.as_ref().map(|path| path.leaf_node().clone()),
                    );
                    return Ok(StagedCommit::new(
                        proposal_queue,
                        StagedCommitState::PublicState(Box::new(staged_state)),
                    ));
                }

                let decryption_keypairs: Vec<&EncryptionKeyPair> = old_epoch_keypairs
                    .iter()
                    .chain(leaf_node_keypairs.iter())
                    .collect();

                // ValSem203: Path secrets must decrypt correctly
                // ValSem204: Public keys from Path must be verified and match the private keys from the direct path
                let (new_keypairs, commit_secret) = diff.decrypt_path(
                    provider.crypto(),
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

                // Return the leaf node in the update path so the credential can be validated.
                // Since the diff has already been updated, this should be the same as the leaf
                // at the sender index.
                let update_path_leaf_node = Some(path.leaf_node().clone());
                debug_assert_eq!(diff.leaf(sender_index), path.leaf_node().into());

                (
                    commit_secret,
                    new_keypairs,
                    new_leaf_keypair_option,
                    update_path_leaf_node,
                )
            } else {
                if apply_proposals_values.path_required {
                    // ValSem201
                    return Err(StageCommitError::RequiredPathNotFound);
                }

                // Even if there is no path, we have to update the group context.
                diff.update_group_context(
                    provider.crypto(),
                    apply_proposals_values.extensions.clone(),
                )?;

                (CommitSecret::zero_secret(ciphersuite), vec![], None, None)
            };

        // Update the confirmed transcript hash before we compute the confirmation tag.
        diff.update_confirmed_transcript_hash(provider.crypto(), mls_content)?;

        let received_confirmation_tag = mls_content
            .confirmation_tag()
            .ok_or(StageCommitError::ConfirmationTagMissing)?;

        let serialized_provisional_group_context = diff
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        let (provisional_group_secrets, provisional_message_secrets) = self
            .derive_epoch_secrets(
                provider,
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
            .tag(
                provider.crypto(),
                self.ciphersuite(),
                diff.group_context().confirmed_transcript_hash(),
            )
            .map_err(LibraryError::unexpected_crypto_error)?;
        if &own_confirmation_tag != received_confirmation_tag {
            log::error!("Confirmation tag mismatch");
            log_crypto!(trace, "  Got:      {:x?}", received_confirmation_tag);
            log_crypto!(trace, "  Expected: {:x?}", own_confirmation_tag);
            // TODO: We have tests expecting this error.
            //       They need to be rewritten.
            // debug_assert!(false, "Confirmation tag mismatch");

            // in some tests we need to be able to proceed despite the tag being wrong,
            // e.g. to test whether a later validation check is performed correctly.
            if !crate::skip_validation::is_disabled::confirmation_tag() {
                return Err(StageCommitError::ConfirmationTagMismatch);
            }
        }

        diff.update_interim_transcript_hash(ciphersuite, provider.crypto(), own_confirmation_tag)?;

        let staged_diff = diff.into_staged_diff(provider.crypto(), ciphersuite)?;
        let staged_commit_state =
            StagedCommitState::GroupMember(Box::new(MemberStagedCommitState::new(
                provisional_group_secrets,
                provisional_message_secrets,
                staged_diff,
                new_keypairs,
                new_leaf_keypair_option,
                update_path_leaf_node,
            )));

        Ok(StagedCommit::new(proposal_queue, staged_commit_state))
    }

    /// Merges a [StagedCommit] into the group state and optionally return a [`SecretTree`]
    /// from the previous epoch. The secret tree is returned if the Commit does not contain a self removal.
    ///
    /// This function should not fail and only returns a [`Result`], because it
    /// might throw a `LibraryError`.
    pub(crate) fn merge_commit<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        staged_commit: StagedCommit,
    ) -> Result<(), MergeCommitError<Provider::StorageError>> {
        // Get all keypairs from the old epoch, so we can later store the ones
        // that are still relevant in the new epoch.
        let old_epoch_keypairs = self
            .read_epoch_keypairs(provider.storage())
            .map_err(MergeCommitError::StorageError)?;
        match staged_commit.state {
            StagedCommitState::PublicState(staged_state) => {
                self.public_group
                    .merge_diff(staged_state.into_staged_diff());
                self.store(provider.storage())
                    .map_err(MergeCommitError::StorageError)?;
                Ok(())
            }
            StagedCommitState::GroupMember(state) => {
                // Save the past epoch
                let past_epoch = self.context().epoch();
                // Get all the full leaves
                let leaves = self.public_group().members().collect();
                // Merge the staged commit into the group state and store the secret tree from the
                // previous epoch in the message secrets store.
                self.group_epoch_secrets = state.group_epoch_secrets;

                // Replace the previous message secrets with the new ones and return the previous message secrets
                let mut message_secrets = state.message_secrets;
                mem::swap(
                    &mut message_secrets,
                    self.message_secrets_store.message_secrets_mut(),
                );
                self.message_secrets_store
                    .add(past_epoch, message_secrets, leaves);

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
                    .public_group()
                    .owned_encryption_keys(self.own_leaf_index());
                // From the old and new keys, keep the ones that are still relevant in the new epoch.
                let epoch_keypairs: Vec<EncryptionKeyPair> = old_epoch_keypairs
                    .into_iter()
                    .chain(state.new_keypairs)
                    .chain(leaf_keypair)
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

                // Store the updated group state
                let storage = provider.storage();
                let group_id = self.group_id();

                self.public_group
                    .store(storage)
                    .map_err(MergeCommitError::StorageError)?;
                storage
                    .write_group_epoch_secrets(group_id, &self.group_epoch_secrets)
                    .map_err(MergeCommitError::StorageError)?;
                storage
                    .write_message_secrets(group_id, &self.message_secrets_store)
                    .map_err(MergeCommitError::StorageError)?;

                // Store the relevant keys under the new epoch
                self.store_epoch_keypairs(storage, epoch_keypairs.as_slice())
                    .map_err(MergeCommitError::StorageError)?;

                // Delete the old keys.
                self.delete_previous_epoch_keypairs(storage)
                    .map_err(MergeCommitError::StorageError)?;
                if let Some(keypair) = state.new_leaf_keypair_option {
                    keypair
                        .delete(storage)
                        .map_err(MergeCommitError::StorageError)?;
                }

                // Empty the proposal store
                storage
                    .clear_proposal_queue::<GroupId, ProposalRef>(group_id)
                    .map_err(MergeCommitError::StorageError)?;
                self.proposal_store_mut().empty();

                Ok(())
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
pub(crate) enum StagedCommitState {
    PublicState(Box<PublicStagedCommitState>),
    GroupMember(Box<MemberStagedCommitState>),
}

/// Contains the changes from a commit to the group state.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
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

    /// Returns an iterator over all [`QueuedProposal`]s.
    pub fn queued_proposals(&self) -> impl Iterator<Item = &QueuedProposal> {
        self.staged_proposal_queue.queued_proposals()
    }

    /// Returns the leaf node of the (optional) update path.
    pub fn update_path_leaf_node(&self) -> Option<&LeafNode> {
        match self.state {
            StagedCommitState::PublicState(ref public_state) => {
                public_state.update_path_leaf_node()
            }
            StagedCommitState::GroupMember(ref group_member_state) => {
                group_member_state.update_path_leaf_node.as_ref()
            }
        }
    }

    /// Returns the credentials that the caller needs to verify are valid.
    pub fn credentials_to_verify(&self) -> impl Iterator<Item = &Credential> {
        let update_path_leaf_node_cred = if let Some(node) = self.update_path_leaf_node() {
            vec![node.credential()]
        } else {
            vec![]
        };

        update_path_leaf_node_cred
            .into_iter()
            .chain(
                self.queued_proposals()
                    .flat_map(|proposal: &QueuedProposal| match proposal.proposal() {
                        Proposal::Update(update_proposal) => {
                            vec![update_proposal.leaf_node().credential()].into_iter()
                        }
                        Proposal::Add(add_proposal) => {
                            vec![add_proposal.key_package().leaf_node().credential()].into_iter()
                        }
                        Proposal::GroupContextExtensions(gce_proposal) => gce_proposal
                            .extensions()
                            .iter()
                            .flat_map(|extension| {
                                match extension {
                                    Extension::ExternalSenders(external_senders) => {
                                        external_senders
                                            .iter()
                                            .map(|external_sender| external_sender.credential())
                                            .collect()
                                    }
                                    _ => vec![],
                                }
                                .into_iter()
                            })
                            // TODO: ideally we wouldn't collect in between here, but the match arms
                            //       have to all return the same type. We solve this by having them all
                            //       be vec::IntoIter, but it would be nice if we just didn't have to
                            //       do this.
                            //       It might be possible to solve this by letting all match arms
                            //       evaluate to a dyn Iterator.
                            .collect::<Vec<_>>()
                            .into_iter(),
                        _ => vec![].into_iter(),
                    }),
            )
    }

    /// Returns `true` if the member was removed through a proposal covered by this Commit message
    /// and `false` otherwise.
    pub fn self_removed(&self) -> bool {
        matches!(self.state, StagedCommitState::PublicState(_))
    }

    /// Returns the [`GroupContext`] of the staged commit state.
    pub fn group_context(&self) -> &GroupContext {
        match self.state {
            StagedCommitState::PublicState(ref ps) => ps.staged_diff().group_context(),
            StagedCommitState::GroupMember(ref gm) => gm.group_context(),
        }
    }

    /// Consume this [`StagedCommit`] and return the internal [`StagedCommitState`].
    pub(crate) fn into_state(self) -> StagedCommitState {
        self.state
    }

    /// Returns the [`EpochAuthenticator`] of the staged commit state if the
    /// owner of the originating group state is a member of the group. Returns
    /// `None` otherwise.
    pub fn epoch_authenticator(&self) -> Option<&EpochAuthenticator> {
        if let StagedCommitState::GroupMember(ref gm) = self.state {
            Some(gm.group_epoch_secrets.epoch_authenticator())
        } else {
            None
        }
    }
}

/// This struct is used internally by [StagedCommit] to encapsulate all the modified group state.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
pub(crate) struct MemberStagedCommitState {
    group_epoch_secrets: GroupEpochSecrets,
    message_secrets: MessageSecrets,
    staged_diff: StagedPublicGroupDiff,
    new_keypairs: Vec<EncryptionKeyPair>,
    new_leaf_keypair_option: Option<EncryptionKeyPair>,
    update_path_leaf_node: Option<LeafNode>,
}

impl MemberStagedCommitState {
    pub(crate) fn new(
        group_epoch_secrets: GroupEpochSecrets,
        message_secrets: MessageSecrets,
        staged_diff: StagedPublicGroupDiff,
        new_keypairs: Vec<EncryptionKeyPair>,
        new_leaf_keypair_option: Option<EncryptionKeyPair>,
        update_path_leaf_node: Option<LeafNode>,
    ) -> Self {
        Self {
            group_epoch_secrets,
            message_secrets,
            staged_diff,
            new_keypairs,
            new_leaf_keypair_option,
            update_path_leaf_node,
        }
    }

    /// Get the staged [`GroupContext`].
    pub(crate) fn group_context(&self) -> &GroupContext {
        self.staged_diff.group_context()
    }
}
