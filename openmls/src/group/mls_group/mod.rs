//! MLS Group
//!
//! This module contains [`MlsGroup`] and its submodules.
//!

#[cfg(any(feature = "test-utils", test))]
use crate::schedule::message_secrets::MessageSecrets;

#[cfg(test)]
use openmls_traits::crypto::OpenMlsCrypto;

#[cfg(test)]
use crate::prelude::SenderRatchetConfiguration;

use super::proposals::{ProposalStore, QueuedProposal};
use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    ciphersuite::hash_ref::ProposalRef,
    credentials::Credential,
    error::LibraryError,
    framing::{mls_auth_content::AuthenticatedContent, *},
    group::*,
    key_packages::{KeyPackage, KeyPackageBundle},
    messages::{proposals::*, GroupSecrets},
    prelude::ProtocolVersion,
    schedule::{psk::store::ResumptionPskStore, GroupEpochSecrets, ResumptionPskSecret},
    storage::{OpenMlsProvider, StorageProvider},
    treesync::{node::leaf_node::LeafNode, RatchetTree},
};
use openmls_traits::types::Ciphersuite;

// Private
mod application;
mod builder;
mod creation;
mod exporting;
mod updates;

use config::*;

// Crate
pub(crate) mod config;
pub(crate) mod errors;
pub(crate) mod membership;
pub(crate) mod processing;
pub(crate) mod proposal;

// Tests
#[cfg(test)]
pub(crate) mod tests_and_kats;

/// Pending Commit state. Differentiates between Commits issued by group members
/// and External Commits.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
pub enum PendingCommitState {
    /// Commit from a group member
    Member(StagedCommit),
    /// Commit from an external joiner
    External(StagedCommit),
}

impl PendingCommitState {
    /// Returns a reference to the [`StagedCommit`] contained in the
    /// [`PendingCommitState`] enum.
    pub(crate) fn staged_commit(&self) -> &StagedCommit {
        match self {
            PendingCommitState::Member(pc) => pc,
            PendingCommitState::External(pc) => pc,
        }
    }
}

impl From<PendingCommitState> for StagedCommit {
    fn from(pcs: PendingCommitState) -> Self {
        match pcs {
            PendingCommitState::Member(pc) => pc,
            PendingCommitState::External(pc) => pc,
        }
    }
}

/// [`MlsGroupState`] determines the state of an [`MlsGroup`]. The different
/// states and their transitions are as follows:
///
/// * [`MlsGroupState::Operational`]: This is the main state of the group, which
///   allows access to all of its functionality, (except merging pending commits,
///   see the [`MlsGroupState::PendingCommit`] for more information) and it's the
///   state the group starts in (except when created via
///   [`MlsGroup::join_by_external_commit()`], see the functions documentation for
///   more information). From this `Operational`, the group state can either
///   transition to [`MlsGroupState::Inactive`], when it processes a commit that
///   removes this client from the group, or to [`MlsGroupState::PendingCommit`],
///   when this client creates a commit.
///
/// * [`MlsGroupState::Inactive`]: A group can enter this state from any other
///   state when it processes a commit that removes this client from the group.
///   This is a terminal state that the group can not exit from. If the clients
///   wants to re-join the group, it can either be added by a group member or it
///   can join via external commit.
///
/// * [`MlsGroupState::PendingCommit`]: This state is split into two possible
///   sub-states, one for each Commit type:
///   [`PendingCommitState::Member`] and [`PendingCommitState::External`]:
///
///   * If the client creates a commit for this group, the `PendingCommit` state
///     is entered with [`PendingCommitState::Member`] and with the [`StagedCommit`] as
///     additional state variable. In this state, it can perform the same
///     operations as in the [`MlsGroupState::Operational`], except that it cannot
///     create proposals or commits. However, it can merge or clear the stored
///     [`StagedCommit`], where both actions result in a transition to the
///     [`MlsGroupState::Operational`]. Additionally, if a commit from another
///     group member is processed, the own pending commit is also cleared and
///     either the `Inactive` state is entered (if this client was removed from
///     the group as part of the processed commit), or the `Operational` state is
///     entered.
///
///   * A group can enter the [`PendingCommitState::External`] sub-state only as
///     the initial state when the group is created via
///     [`MlsGroup::join_by_external_commit()`]. In contrast to the
///     [`PendingCommitState::Member`] `PendingCommit` state, the only possible
///     functionality that can be used is the [`MlsGroup::merge_pending_commit()`]
///     function, which merges the pending external commit and transitions the
///     state to [`MlsGroupState::PendingCommit`]. For more information on the
///     external commit process, see [`MlsGroup::join_by_external_commit()`] or
///     Section 11.2.1 of the MLS specification.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
pub enum MlsGroupState {
    /// There is currently a pending Commit that hasn't been merged yet.
    PendingCommit(Box<PendingCommitState>),
    /// The group state is in an opertaional state, where new messages and Commits can be created.
    Operational,
    /// The group is inactive because the member has been removed.
    Inactive,
}

/// A `MlsGroup` represents an MLS group with a high-level API. The API exposes
/// high level functions to manage a group by adding/removing members, get the
/// current member list, etc.
///
/// The API is modeled such that it can serve as a direct interface to the
/// Delivery Service. Functions that modify the public state of the group will
/// return a `Vec<MLSMessageOut>` that can be sent to the Delivery Service
/// directly. Conversely, incoming messages from the Delivery Service can be fed
/// into [process_message()](`MlsGroup::process_message()`).
///
/// An `MlsGroup` has an internal queue of pending proposals that builds up as
/// new messages are processed. When creating proposals, those messages are not
/// automatically appended to this queue, instead they have to be processed
/// again through [process_message()](`MlsGroup::process_message()`). This
/// allows the Delivery Service to reject them (e.g. if they reference the wrong
/// epoch).
///
/// If incoming messages or applied operations are semantically or syntactically
/// incorrect, an error event will be returned with a corresponding error
/// message and the state of the group will remain unchanged.
///
/// An `MlsGroup` has an internal state variable determining if it is active or
/// inactive, as well as if it has a pending commit. See [`MlsGroupState`] for
/// more information.
#[derive(Debug)]
#[cfg_attr(feature = "test-utils", derive(Clone, PartialEq))]
pub struct MlsGroup {
    /// The group configuration. See [`MlsGroupJoinConfig`] for more information.
    mls_group_config: MlsGroupJoinConfig,
    /// The public state of the group.
    public_group: PublicGroup,
    /// Epoch-specific secrets of the group.
    group_epoch_secrets: GroupEpochSecrets,
    /// The own leaf index in the ratchet tree.
    own_leaf_index: LeafNodeIndex,
    /// Group config.
    /// Set to true if the ratchet tree extension is added to the `GroupInfo`.
    /// Defaults to `false`.
    use_ratchet_tree_extension: bool,
    /// A [`MessageSecretsStore`] that stores message secrets.
    /// By default this store has the length of 1, i.e. only the [`MessageSecrets`]
    /// of the current epoch is kept.
    /// If more secrets from past epochs should be kept in order to be
    /// able to decrypt application messages from previous epochs, the size of
    /// the store must be increased through [`max_past_epochs()`].
    message_secrets_store: MessageSecretsStore,
    // Resumption psk store. This is where the resumption psks are kept in a rollover list.
    pub(crate) resumption_psk_store: ResumptionPskStore,
    // Own [`LeafNode`]s that were created for update proposals and that
    // are needed in case an update proposal is committed by another group
    // member. The vector is emptied after every epoch change.
    own_leaf_nodes: Vec<LeafNode>,
    // Additional authenticated data (AAD) for the next outgoing message. This
    // is ephemeral and will be reset by every API call that successfully
    // returns an [`MlsMessageOut`].
    aad: Vec<u8>,
    // A variable that indicates the state of the group. See [`MlsGroupState`]
    // for more information.
    group_state: MlsGroupState,
}

impl MlsGroup {
    // === Configuration ===

    /// Returns the configuration.
    pub fn configuration(&self) -> &MlsGroupJoinConfig {
        &self.mls_group_config
    }

    /// Sets the configuration.
    pub fn set_configuration<Storage: StorageProvider>(
        &mut self,
        storage: &Storage,
        mls_group_config: &MlsGroupJoinConfig,
    ) -> Result<(), Storage::Error> {
        self.mls_group_config = mls_group_config.clone();
        storage.write_mls_join_config(self.group_id(), mls_group_config)
    }

    /// Sets the additional authenticated data (AAD) for the next outgoing
    /// message. This is ephemeral and will be reset by every API call that
    /// successfully returns an [`MlsMessageOut`].
    pub fn set_aad(&mut self, aad: Vec<u8>) {
        self.aad = aad;
    }

    /// Returns the additional authenticated data (AAD) for the next outgoing
    /// message.
    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    // === Advanced functions ===

    /// Returns the group's ciphersuite.
    pub fn ciphersuite(&self) -> Ciphersuite {
        self.public_group.ciphersuite()
    }

    /// Returns whether the own client is still a member of the group or if it
    /// was already evicted
    pub fn is_active(&self) -> bool {
        !matches!(self.group_state, MlsGroupState::Inactive)
    }

    /// Returns own credential. If the group is inactive, it returns a
    /// `UseAfterEviction` error.
    pub fn credential(&self) -> Result<&Credential, MlsGroupStateError> {
        if !self.is_active() {
            return Err(MlsGroupStateError::UseAfterEviction);
        }
        self.public_group
            .leaf(self.own_leaf_index())
            .map(|node| node.credential())
            .ok_or_else(|| LibraryError::custom("Own leaf node missing").into())
    }

    /// Get the required capabilities extension of this group.
    pub(crate) fn required_capabilities(&self) -> Option<&RequiredCapabilitiesExtension> {
        self.public_group.required_capabilities()
    }

    /// Returns the leaf index of the client in the tree owning this group.
    pub(crate) fn own_leaf_index(&self) -> LeafNodeIndex {
        self.own_leaf_index
    }

    /// Get a reference to the group epoch secrets from the group
    pub(crate) fn group_epoch_secrets(&self) -> &GroupEpochSecrets {
        &self.group_epoch_secrets
    }

    /// Get a reference to the message secrets from a group
    pub(crate) fn message_secrets(&self) -> &MessageSecrets {
        self.message_secrets_store.message_secrets()
    }

    /// Sets the size of the [`MessageSecretsStore`], i.e. the number of past
    /// epochs to keep.
    /// This allows application messages from previous epochs to be decrypted.
    pub(crate) fn set_max_past_epochs(&mut self, max_past_epochs: usize) {
        self.message_secrets_store.resize(max_past_epochs);
    }

    /// Get the message secrets. Either from the secrets store or from the group.
    pub(crate) fn message_secrets_mut(
        &mut self,
        epoch: GroupEpoch,
    ) -> Result<&mut MessageSecrets, SecretTreeError> {
        if epoch < self.context().epoch() {
            self.message_secrets_store
                .secrets_for_epoch_mut(epoch)
                .ok_or(SecretTreeError::TooDistantInThePast)
        } else {
            Ok(self.message_secrets_store.message_secrets_mut())
        }
    }

    /// Get the message secrets. Either from the secrets store or from the group.
    pub(crate) fn message_secrets_for_epoch(
        &self,
        epoch: GroupEpoch,
    ) -> Result<&MessageSecrets, SecretTreeError> {
        if epoch < self.context().epoch() {
            self.message_secrets_store
                .secrets_for_epoch(epoch)
                .ok_or(SecretTreeError::TooDistantInThePast)
        } else {
            Ok(self.message_secrets_store.message_secrets())
        }
    }

    /// Get the message secrets and leaves for the given epoch. Either from the
    /// secrets store or from the group.
    ///
    /// Note that the leaves vector is empty for message secrets of the current
    /// epoch. The caller can use treesync in this case.
    pub(crate) fn message_secrets_and_leaves_mut(
        &mut self,
        epoch: GroupEpoch,
    ) -> Result<(&mut MessageSecrets, &[Member]), MessageDecryptionError> {
        if epoch < self.context().epoch() {
            self.message_secrets_store
                .secrets_and_leaves_for_epoch_mut(epoch)
                .ok_or({
                    MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast)
                })
        } else {
            // No need for leaves here. The tree of the current epoch is
            // available to the caller.
            Ok((self.message_secrets_store.message_secrets_mut(), &[]))
        }
    }

    pub fn own_leaf_node(&self) -> Result<&LeafNode, LibraryError> {
        self.public_group()
            .leaf(self.own_leaf_index())
            .ok_or_else(|| LibraryError::custom("Tree has no own leaf."))
    }

    /// Returns the group ID.
    pub fn group_id(&self) -> &GroupId {
        self.public_group.group_id()
    }

    /// Returns the epoch.
    pub fn epoch(&self) -> GroupEpoch {
        self.public_group.context().epoch()
    }

    /// Stores the [`CoreGroup`]. Called from methods creating a new group and mutating an
    /// existing group, both inside [`CoreGroup`] and in [`MlsGroup`].
    pub(super) fn store<Storage: StorageProvider>(
        &self,
        storage: &Storage,
    ) -> Result<(), Storage::Error> {
        let group_id = self.group_id();

        self.public_group.store(storage)?;
        storage.write_own_leaf_index(group_id, &self.own_leaf_index())?;
        storage.write_group_epoch_secrets(group_id, &self.group_epoch_secrets)?;
        storage.set_use_ratchet_tree_extension(group_id, self.use_ratchet_tree_extension)?;
        storage.write_message_secrets(group_id, &self.message_secrets_store)?;
        storage.write_resumption_psk_store(group_id, &self.resumption_psk_store)?;

        Ok(())
    }

    /// Loads a [`CoreGroup`]. Called in [`MlsGroup::load`].
    pub(super) fn load<Storage: StorageProvider>(
        storage: &Storage,
        group_id: &GroupId,
    ) -> Result<Option<Self>, Storage::Error> {
        let public_group = PublicGroup::load(storage, group_id)?;
        let group_epoch_secrets = storage.group_epoch_secrets(group_id)?;
        let own_leaf_index = storage.own_leaf_index(group_id)?;
        let use_ratchet_tree_extension = storage.use_ratchet_tree_extension(group_id)?;
        let message_secrets_store = storage.message_secrets(group_id)?;
        let resumption_psk_store = storage.resumption_psk_store(group_id)?;

        let build = || -> Option<Self> {
            Some(Self {
                public_group: public_group?,
                group_epoch_secrets: group_epoch_secrets?,
                own_leaf_index: own_leaf_index?,
                use_ratchet_tree_extension: use_ratchet_tree_extension?,
                message_secrets_store: message_secrets_store?,
                resumption_psk_store: resumption_psk_store?,
            })
        };

        Ok(build())
    }

    pub(super) fn delete<Storage: StorageProvider>(
        &self,
        storage: &Storage,
    ) -> Result<(), Storage::Error> {
        self.public_group.delete(storage)?;
        storage.delete_own_leaf_index(self.group_id())?;
        storage.delete_group_epoch_secrets(self.group_id())?;
        storage.delete_use_ratchet_tree_extension(self.group_id())?;
        storage.delete_message_secrets(self.group_id())?;
        storage.delete_all_resumption_psk_secrets(self.group_id())?;

        Ok(())
    }

    /// Store the given [`EncryptionKeyPair`]s in the `provider`'s key store
    /// indexed by this group's [`GroupId`] and [`GroupEpoch`].
    ///
    /// Returns an error if access to the key store fails.
    pub(super) fn store_epoch_keypairs<Storage: StorageProvider>(
        &self,
        store: &Storage,
        keypair_references: &[EncryptionKeyPair],
    ) -> Result<(), Storage::Error> {
        store.write_encryption_epoch_key_pairs(
            self.group_id(),
            &self.context().epoch(),
            self.own_leaf_index().u32(),
            keypair_references,
        )
    }

    /// Read the [`EncryptionKeyPair`]s of this group and its current
    /// [`GroupEpoch`] from the `provider`'s storage.
    ///
    /// Returns an empty vector if access to the store fails or it can't find
    /// any keys.
    pub(super) fn read_epoch_keypairs<Storage: StorageProvider>(
        &self,
        store: &Storage,
    ) -> Vec<EncryptionKeyPair> {
        store
            .encryption_epoch_key_pairs(
                self.group_id(),
                &self.context().epoch(),
                self.own_leaf_index().u32(),
            )
            .unwrap_or_default()
    }

    /// Delete the [`EncryptionKeyPair`]s from the previous [`GroupEpoch`] from
    /// the `provider`'s key store.
    ///
    /// Returns an error if access to the key store fails.
    pub(super) fn delete_previous_epoch_keypairs<Storage: StorageProvider>(
        &self,
        store: &Storage,
    ) -> Result<(), Storage::Error> {
        store.delete_encryption_epoch_key_pairs(
            self.group_id(),
            &GroupEpoch::from(self.context().epoch().as_u64() - 1),
            self.own_leaf_index().u32(),
        )
    }

    pub(crate) fn create_commit<Provider: OpenMlsProvider>(
        &self,
        params: CreateCommitParams,
        provider: &Provider,
        signer: &impl Signer,
    ) -> Result<CreateCommitResult, CreateCommitError<Provider::StorageError>> {
        let ciphersuite = self.ciphersuite();

        let sender = match params.commit_type() {
            CommitType::External(_) => Sender::NewMemberCommit,
            CommitType::Member => Sender::build_member(self.own_leaf_index()),
        };

        // Filter proposals
        let (proposal_queue, contains_own_updates) = ProposalQueue::filter_proposals(
            ciphersuite,
            provider.crypto(),
            sender.clone(),
            self.proposal_store(),
            params.inline_proposals(),
            self.own_leaf_index(),
        )
        .map_err(|e| match e {
            ProposalQueueError::LibraryError(e) => e.into(),
            ProposalQueueError::ProposalNotFound => CreateCommitError::MissingProposal,
            ProposalQueueError::UpdateFromExternalSender => {
                CreateCommitError::WrongProposalSenderType
            }
        })?;

        // TODO: #581 Filter proposals by support
        // 11.2:
        // Proposals with a non-default proposal type MUST NOT be included in a commit
        // unless the proposal type is supported by all the members of the group that
        // will process the Commit (i.e., not including any members being added
        // or removed by the Commit).

        let proposal_reference_list = proposal_queue.commit_list();

        // Validate the proposals by doing the following checks:

        // ValSem113: All Proposals: The proposal type must be supported by all
        // members of the group
        self.public_group
            .validate_proposal_type_support(&proposal_queue)?;
        // ValSem101
        // ValSem102
        // ValSem103
        // ValSem104
        self.public_group
            .validate_key_uniqueness(&proposal_queue, None)?;
        // ValSem105
        self.public_group.validate_add_proposals(&proposal_queue)?;
        // ValSem106
        // ValSem109
        self.public_group.validate_capabilities(&proposal_queue)?;
        // ValSem107
        // ValSem108
        self.public_group
            .validate_remove_proposals(&proposal_queue)?;
        self.public_group
            .validate_pre_shared_key_proposals(&proposal_queue)?;
        // Validate update proposals for member commits
        if let Sender::Member(sender_index) = &sender {
            // ValSem110
            // ValSem111
            // ValSem112
            self.public_group
                .validate_update_proposals(&proposal_queue, *sender_index)?;
        }

        // ValSem208
        // ValSem209
        self.public_group
            .validate_group_context_extensions_proposal(&proposal_queue)?;

        // Make a copy of the public group to apply proposals safely
        let mut diff = self.public_group.empty_diff();

        // Apply proposals to tree
        let apply_proposals_values =
            diff.apply_proposals(&proposal_queue, self.own_leaf_index())?;
        if apply_proposals_values.self_removed && params.commit_type() == &CommitType::Member {
            return Err(CreateCommitError::CannotRemoveSelf);
        }

        let path_computation_result =
            // If path is needed, compute path values
            if apply_proposals_values.path_required
                || contains_own_updates
                || params.force_self_update()
                || !params.leaf_node_parameters().is_empty()
            {
                // Process the path. This includes updating the provisional
                // group context by updating the epoch and computing the new
                // tree hash.
                diff.compute_path(
                    provider,
                    self.own_leaf_index(),
                    apply_proposals_values.exclusion_list(),
                    params.commit_type(),
                    params.leaf_node_parameters(),
                    signer,
                    apply_proposals_values.extensions.clone()
                )?
            } else {
                // If path is not needed, update the group context and return
                // empty path processing results
                diff.update_group_context(provider.crypto(), apply_proposals_values.extensions.clone())?;
                PathComputationResult::default()
            };

        let update_path_leaf_node = path_computation_result
            .encrypted_path
            .as_ref()
            .map(|path| path.leaf_node().clone());

        // Create commit message
        let commit = Commit {
            proposals: proposal_reference_list,
            path: path_computation_result.encrypted_path,
        };

        // Build AuthenticatedContent
        let mut authenticated_content = AuthenticatedContent::commit(
            *params.framing_parameters(),
            sender,
            commit,
            self.public_group.group_context(),
            signer,
        )?;

        // Update the confirmed transcript hash using the commit we just created.
        diff.update_confirmed_transcript_hash(provider.crypto(), &authenticated_content)?;

        let serialized_provisional_group_context = diff
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        let joiner_secret = JoinerSecret::new(
            provider.crypto(),
            ciphersuite,
            path_computation_result.commit_secret,
            self.group_epoch_secrets().init_secret(),
            &serialized_provisional_group_context,
        )
        .map_err(LibraryError::unexpected_crypto_error)?;

        // Prepare the PskSecret
        let psk_secret = {
            let psks = load_psks(
                provider.storage(),
                &self.resumption_psk_store,
                &apply_proposals_values.presharedkeys,
            )?;

            PskSecret::new(provider.crypto(), ciphersuite, psks)?
        };

        // Create key schedule
        let mut key_schedule =
            KeySchedule::init(ciphersuite, provider.crypto(), &joiner_secret, psk_secret)?;

        let serialized_provisional_group_context = diff
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        let welcome_secret = key_schedule
            .welcome(provider.crypto(), self.ciphersuite())
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        key_schedule
            .add_context(provider.crypto(), &serialized_provisional_group_context)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        let provisional_epoch_secrets = key_schedule
            .epoch_secrets(provider.crypto(), self.ciphersuite())
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;

        // Calculate the confirmation tag
        let confirmation_tag = provisional_epoch_secrets
            .confirmation_key()
            .tag(
                provider.crypto(),
                self.ciphersuite(),
                diff.group_context().confirmed_transcript_hash(),
            )
            .map_err(LibraryError::unexpected_crypto_error)?;

        // Set the confirmation tag
        authenticated_content.set_confirmation_tag(confirmation_tag.clone());

        diff.update_interim_transcript_hash(
            ciphersuite,
            provider.crypto(),
            confirmation_tag.clone(),
        )?;

        // only computes the group info if necessary
        let group_info = if !apply_proposals_values.invitation_list.is_empty()
            || self.use_ratchet_tree_extension
        {
            // Create the ratchet tree extension if necessary
            let external_pub = provisional_epoch_secrets
                .external_secret()
                .derive_external_keypair(provider.crypto(), ciphersuite)
                .map_err(LibraryError::unexpected_crypto_error)?
                .public;
            let external_pub_extension =
                Extension::ExternalPub(ExternalPubExtension::new(external_pub.into()));
            let other_extensions: Extensions = if self.use_ratchet_tree_extension {
                Extensions::from_vec(vec![
                    Extension::RatchetTree(RatchetTreeExtension::new(diff.export_ratchet_tree())),
                    external_pub_extension,
                ])?
            } else {
                Extensions::single(external_pub_extension)
            };

            // Create to-be-signed group info.
            let group_info_tbs = {
                GroupInfoTBS::new(
                    diff.group_context().clone(),
                    other_extensions,
                    confirmation_tag,
                    self.own_leaf_index(),
                )
            };
            // Sign to-be-signed group info.
            Some(group_info_tbs.sign(signer)?)
        } else {
            None
        };

        // Check if new members were added and, if so, create welcome messages
        let welcome_option = if !apply_proposals_values.invitation_list.is_empty() {
            // Encrypt GroupInfo object
            let (welcome_key, welcome_nonce) = welcome_secret
                .derive_welcome_key_nonce(provider.crypto(), self.ciphersuite())
                .map_err(LibraryError::unexpected_crypto_error)?;
            let encrypted_group_info = welcome_key
                .aead_seal(
                    provider.crypto(),
                    group_info
                        .as_ref()
                        .ok_or_else(|| LibraryError::custom("GroupInfo was not computed"))?
                        .tls_serialize_detached()
                        .map_err(LibraryError::missing_bound_check)?
                        .as_slice(),
                    &[],
                    &welcome_nonce,
                )
                .map_err(LibraryError::unexpected_crypto_error)?;

            // Create group secrets for later use, so we can afterwards consume the
            // `joiner_secret`.
            let encrypted_secrets = diff.encrypt_group_secrets(
                &joiner_secret,
                apply_proposals_values.invitation_list,
                path_computation_result.plain_path.as_deref(),
                &apply_proposals_values.presharedkeys,
                &encrypted_group_info,
                provider.crypto(),
                self.own_leaf_index(),
            )?;

            // Create welcome message
            let welcome = Welcome::new(self.ciphersuite(), encrypted_secrets, encrypted_group_info);
            Some(welcome)
        } else {
            None
        };

        let (provisional_group_epoch_secrets, provisional_message_secrets) =
            provisional_epoch_secrets.split_secrets(
                serialized_provisional_group_context,
                diff.tree_size(),
                self.own_leaf_index(),
            );

        let staged_commit_state = MemberStagedCommitState::new(
            provisional_group_epoch_secrets,
            provisional_message_secrets,
            diff.into_staged_diff(provider.crypto(), ciphersuite)?,
            path_computation_result.new_keypairs,
            // The committer is not allowed to include their own update
            // proposal, so there is no extra keypair to store here.
            None,
            update_path_leaf_node,
        );
        let staged_commit = StagedCommit::new(
            proposal_queue,
            StagedCommitState::GroupMember(Box::new(staged_commit_state)),
        );

        Ok(CreateCommitResult {
            commit: authenticated_content,
            welcome_option,
            staged_commit,
            group_info: group_info.filter(|_| self.use_ratchet_tree_extension),
        })
    }

    /// Create a new group context extension proposal
    pub(crate) fn create_group_context_ext_proposal<Provider: OpenMlsProvider>(
        &self,
        framing_parameters: FramingParameters,
        extensions: Extensions,
        signer: &impl Signer,
    ) -> Result<AuthenticatedContent, CreateGroupContextExtProposalError<Provider::StorageError>>
    {
        // Ensure that the group supports all the extensions that are wanted.
        let required_extension = extensions
            .iter()
            .find(|extension| extension.extension_type() == ExtensionType::RequiredCapabilities);
        if let Some(required_extension) = required_extension {
            let required_capabilities = required_extension.as_required_capabilities_extension()?;
            // Ensure we support all the capabilities.
            self.own_leaf_node()?
                .capabilities()
                .supports_required_capabilities(required_capabilities)?;

            // Ensure that all other leaf nodes support all the required
            // extensions as well.
            self.public_group()
                .check_extension_support(required_capabilities.extension_types())?;
        }
        let proposal = GroupContextExtensionProposal::new(extensions);
        let proposal = Proposal::GroupContextExtensions(proposal);
        AuthenticatedContent::member_proposal(
            framing_parameters,
            self.own_leaf_index(),
            proposal,
            self.context(),
            signer,
        )
        .map_err(|e| e.into())
    }

    /// Returns an `Iterator` over pending proposals.
    pub fn pending_proposals(&self) -> impl Iterator<Item = &QueuedProposal> {
        self.proposal_store().proposals()
    }

    /// Returns a reference to the [`StagedCommit`] of the most recently created
    /// commit. If there was no commit created in this epoch, either because
    /// this commit or another commit was merged, it returns `None`.
    pub fn pending_commit(&self) -> Option<&StagedCommit> {
        match self.group_state {
            MlsGroupState::PendingCommit(ref pending_commit_state) => {
                Some(pending_commit_state.staged_commit())
            }
            MlsGroupState::Operational => None,
            MlsGroupState::Inactive => None,
        }
    }

    /// Sets the `group_state` to [`MlsGroupState::Operational`], thus clearing
    /// any potentially pending commits.
    ///
    /// Note that this has no effect if the group was created through an external commit and
    /// the resulting external commit has not been merged yet. For more
    /// information, see [`MlsGroup::join_by_external_commit()`].
    ///
    /// Use with caution! This function should only be used if it is clear that
    /// the pending commit will not be used in the group. In particular, if a
    /// pending commit is later accepted by the group, this client will lack the
    /// key material to encrypt or decrypt group messages.
    pub fn clear_pending_commit<Storage: StorageProvider>(
        &mut self,
        storage: &Storage,
    ) -> Result<(), Storage::Error> {
        match self.group_state {
            MlsGroupState::PendingCommit(ref pending_commit_state) => {
                if let PendingCommitState::Member(_) = **pending_commit_state {
                    self.group_state = MlsGroupState::Operational;
                    storage.write_group_state(self.group_id(), &self.group_state)
                } else {
                    Ok(())
                }
            }
            MlsGroupState::Operational | MlsGroupState::Inactive => Ok(()),
        }
    }

    /// Clear the pending proposals, if the proposal store is not empty.
    ///
    /// Warning: Once the pending proposals are cleared it will be impossible to process
    /// a Commit message that references those proposals. Only use this
    /// function as a last resort, e.g. when a call to
    /// `MlsGroup::commit_to_pending_proposals` fails.
    pub fn clear_pending_proposals<Storage: StorageProvider>(
        &mut self,
        storage: &Storage,
    ) -> Result<(), Storage::Error> {
        // If the proposal store is not empty...
        if !self.proposal_store().is_empty() {
            // Empty the proposal store
            self.proposal_store_mut().empty();

            // Clear proposals in storage
            storage.clear_proposal_queue::<GroupId, ProposalRef>(self.group_id())?;
        }

        Ok(())
    }

    /// Get a reference to the group context [`Extensions`] of this [`MlsGroup`].
    pub fn extensions(&self) -> &Extensions {
        self.group.public_group().group_context().extensions()
    }

    /// Returns the index of the sender of a staged, external commit.
    pub fn ext_commit_sender_index(
        &self,
        commit: &StagedCommit,
    ) -> Result<LeafNodeIndex, LibraryError> {
        self.group.public_group().ext_commit_sender_index(commit)
    }

    // === Storage Methods ===

    /// Loads the state of the group with given id from persisted state.
    pub fn load<Storage: crate::storage::StorageProvider>(
        storage: &Storage,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroup>, Storage::Error> {
        let group_config = storage.mls_group_join_config(group_id)?;
        let core_group = CoreGroup::load(storage, group_id)?;
        let own_leaf_nodes = storage.own_leaf_nodes(group_id)?;
        let aad = Vec::new();
        let group_state = storage.group_state(group_id)?;

        let build = || -> Option<Self> {
            Some(Self {
                mls_group_config: group_config?,
                group: core_group?,
                own_leaf_nodes,
                aad,
                group_state: group_state?,
            })
        };

        Ok(build())
    }

    /// Remove the persisted state from storage
    pub fn delete<StorageProvider: crate::storage::StorageProvider>(
        &mut self,
        storage: &StorageProvider,
    ) -> Result<(), StorageProvider::Error> {
        self.group.delete(storage)?;
        storage.delete_group_config(self.group_id())?;
        storage.clear_proposal_queue::<GroupId, ProposalRef>(self.group_id())?;
        storage.delete_own_leaf_nodes(self.group_id())?;
        storage.delete_group_state(self.group_id())?;

        self.proposal_store_mut().empty();

        Ok(())
    }

    // === Extensions ===

    /// Exports the Ratchet Tree.
    pub fn export_ratchet_tree(&self) -> RatchetTree {
        self.group.public_group().export_ratchet_tree()
    }
}

// Private methods of MlsGroup
impl MlsGroup {
    /// Converts PublicMessage to MlsMessage. Depending on whether handshake
    /// message should be encrypted, PublicMessage messages are encrypted to
    /// PrivateMessage first.
    fn content_to_mls_message(
        &mut self,
        mls_auth_content: AuthenticatedContent,
        provider: &impl OpenMlsProvider,
    ) -> Result<MlsMessageOut, LibraryError> {
        let msg = match self.configuration().wire_format_policy().outgoing() {
            OutgoingWireFormatPolicy::AlwaysPlaintext => {
                let mut plaintext: PublicMessage = mls_auth_content.into();
                // Set the membership tag only if the sender type is `Member`.
                if plaintext.sender().is_member() {
                    plaintext.set_membership_tag(
                        provider.crypto(),
                        self.ciphersuite(),
                        self.group.message_secrets().membership_key(),
                        self.group.message_secrets().serialized_context(),
                    )?;
                }
                plaintext.into()
            }
            OutgoingWireFormatPolicy::AlwaysCiphertext => {
                let ciphertext = self
                    .group
                    .encrypt(
                        mls_auth_content,
                        self.configuration().padding_size(),
                        provider,
                    )
                    // We can be sure the encryption will work because the plaintext was created by us
                    .map_err(|_| LibraryError::custom("Malformed plaintext"))?;
                MlsMessageOut::from_private_message(ciphertext, self.group.version())
            }
        };
        Ok(msg)
    }

    /// Group framing parameters
    pub(crate) fn framing_parameters(&self) -> FramingParameters {
        FramingParameters::new(
            &self.aad,
            self.mls_group_config.wire_format_policy().outgoing(),
        )
    }

    /// Check if the group is operational. Throws an error if the group is
    /// inactive or if there is a pending commit.
    fn is_operational(&self) -> Result<(), MlsGroupStateError> {
        match self.group_state {
            MlsGroupState::PendingCommit(_) => Err(MlsGroupStateError::PendingCommit),
            MlsGroupState::Inactive => Err(MlsGroupStateError::UseAfterEviction),
            MlsGroupState::Operational => Ok(()),
        }
    }

    /// Returns a reference to the proposal store.
    pub(crate) fn proposal_store(&self) -> &ProposalStore {
        self.public_group.proposal_store()
    }

    /// Returns a mutable reference to the proposal store.
    pub(crate) fn proposal_store_mut(&mut self) -> &mut ProposalStore {
        self.public_group.proposal_store_mut()
    }

    /// Get the group context
    pub(crate) fn context(&self) -> &GroupContext {
        self.public_group.group_context()
    }

    /// Get the MLS version used in this group.
    pub(crate) fn version(&self) -> ProtocolVersion {
        self.public_group.version()
    }

    /// Resets the AAD.
    #[inline]
    pub(crate) fn reset_aad(&mut self) {
        self.aad.clear();
    }
}

// Methods used in tests
impl MlsGroup {
    #[cfg(any(feature = "test-utils", test))]
    pub fn export_group_context(&self) -> &GroupContext {
        self.group.context()
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn tree_hash(&self) -> &[u8] {
        self.group.public_group().group_context().tree_hash()
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn message_secrets_test_mut(&mut self) -> &mut MessageSecrets {
        self.group.message_secrets_test_mut()
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn print_ratchet_tree(&self, message: &str) {
        self.group.print_ratchet_tree(message)
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn context_mut(&mut self) -> &mut GroupContext {
        self.group.context_mut()
    }

    // Encrypt an AuthenticatedContent into a PrivateMessage. Only needed for
    // the message protection KAT.
    #[cfg(test)]
    pub(crate) fn encrypt<Provider: OpenMlsProvider>(
        &mut self,
        public_message: AuthenticatedContent,
        padding_size: usize,
        provider: &Provider,
    ) -> Result<PrivateMessage, MessageEncryptionError<Provider::StorageError>> {
        self.group.encrypt(public_message, padding_size, provider)
    }

    #[cfg(test)]
    // Decrypt a ProtocolMessage. Only needed for the message protection KAT.
    pub(crate) fn decrypt_message(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        message: ProtocolMessage,
        sender_ratchet_configuration: &SenderRatchetConfiguration,
    ) -> Result<DecryptedMessage, ValidationError> {
        self.group
            .decrypt_message(crypto, message, sender_ratchet_configuration)
    }

    #[cfg(test)]
    pub(crate) fn set_group_context(&mut self, group_context: GroupContext) {
        self.group.set_group_context(group_context)
    }

    #[cfg(test)]
    pub(crate) fn set_own_leaf_index(&mut self, own_leaf_index: LeafNodeIndex) {
        self.group.set_own_leaf_index(own_leaf_index)
    }

    /// Returns the underlying [CoreGroup].
    #[cfg(test)]
    pub(crate) fn group(&self) -> &CoreGroup {
        &self.group
    }
}

/// A [`StagedWelcome`] can be inspected and then turned into a [`MlsGroup`].
/// This allows checking who authored the Welcome message.
#[derive(Debug)]
pub struct StagedWelcome {
    // The group configuration. See [`MlsGroupJoinConfig`] for more information.
    mls_group_config: MlsGroupJoinConfig,
    // The internal `CoreGroup` used for lower level operations. See `CoreGroup` for more
    // information.
    group: StagedCoreWelcome,
}

/// A `Welcome` message that has been processed but not staged yet.
///
/// This may be used in order to retrieve information from the `Welcome` about
/// the ratchet tree and PSKs.
///
/// Use `into_staged_welcome` to stage it into a [`StagedWelcome`].
pub struct ProcessedWelcome {
    // The group configuration. See [`MlsGroupJoinConfig`] for more information.
    mls_group_config: MlsGroupJoinConfig,

    // The following is the state after parsing the Welcome message, before actually
    // building the group.
    ciphersuite: Ciphersuite,
    group_secrets: GroupSecrets,
    key_schedule: crate::schedule::KeySchedule,
    verifiable_group_info: crate::messages::group_info::VerifiableGroupInfo,
    resumption_psk_store: crate::schedule::psk::store::ResumptionPskStore,
    key_package_bundle: KeyPackageBundle,
}
