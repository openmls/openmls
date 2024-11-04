//! MLS Group
//!
//! This module contains [`MlsGroup`] and its submodules.
//!

use create_commit::{CommitType, CreateCommitParams};
use past_secrets::MessageSecretsStore;
use proposal_store::ProposalQueue;
use serde::{Deserialize, Serialize};
use staged_commit::{MemberStagedCommitState, StagedCommitState};
use tls_codec::Serialize as _;

#[cfg(test)]
use crate::treesync::node::leaf_node::TreePosition;

use super::{
    diff::compute_path::PathComputationResult,
    proposal_store::{ProposalStore, QueuedProposal},
};
use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    ciphersuite::{hash_ref::ProposalRef, signable::Signable},
    credentials::Credential,
    error::LibraryError,
    framing::{mls_auth_content::AuthenticatedContent, *},
    group::{
        CreateCommitError, CreateGroupContextExtProposalError, Extension, ExtensionType,
        Extensions, ExternalPubExtension, GroupContext, GroupEpoch, GroupId, MlsGroupJoinConfig,
        MlsGroupStateError, OutgoingWireFormatPolicy, ProposalQueueError, PublicGroup,
        RatchetTreeExtension, RequiredCapabilitiesExtension, StagedCommit,
    },
    key_packages::KeyPackageBundle,
    messages::{
        group_info::{GroupInfo, GroupInfoTBS, VerifiableGroupInfo},
        proposals::*,
        Commit, GroupSecrets, Welcome,
    },
    schedule::{
        message_secrets::MessageSecrets,
        psk::{load_psks, store::ResumptionPskStore, PskSecret},
        GroupEpochSecrets, JoinerSecret, KeySchedule,
    },
    storage::{OpenMlsProvider, StorageProvider},
    treesync::{
        node::{encryption_keys::EncryptionKeyPair, leaf_node::LeafNode},
        RatchetTree,
    },
    versions::ProtocolVersion,
};
use openmls_traits::{signatures::Signer, storage::StorageProvider as _, types::Ciphersuite};

// Private
mod application;
mod builder;
mod creation;
mod exporting;
mod updates;

use config::*;

// Crate
pub(crate) mod commit_builder;
pub(crate) mod config;
pub(crate) mod create_commit;
pub(crate) mod errors;
pub(crate) mod membership;
pub(crate) mod past_secrets;
pub(crate) mod processing;
pub(crate) mod proposal;
pub(crate) mod proposal_store;
pub(crate) mod staged_commit;

// Tests
#[cfg(test)]
pub(crate) mod tests_and_kats;

#[derive(Debug)]
pub(crate) struct CreateCommitResult {
    pub(crate) commit: AuthenticatedContent,
    pub(crate) welcome_option: Option<Welcome>,
    pub(crate) staged_commit: StagedCommit,
    pub(crate) group_info: Option<GroupInfo>,
}

/// A member in the group is identified by this [`Member`] struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// The member's leaf index in the ratchet tree.
    pub index: LeafNodeIndex,
    /// The member's credential.
    pub credential: Credential,
    /// The member's public HPHKE encryption key.
    pub encryption_key: Vec<u8>,
    /// The member's public signature key.
    pub signature_key: Vec<u8>,
}

impl Member {
    /// Create new member.
    pub fn new(
        index: LeafNodeIndex,
        encryption_key: Vec<u8>,
        signature_key: Vec<u8>,
        credential: Credential,
    ) -> Self {
        Self {
            index,
            encryption_key,
            signature_key,
            credential,
        }
    }
}

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
    /// A [`MessageSecretsStore`] that stores message secrets.
    /// By default this store has the length of 1, i.e. only the [`MessageSecrets`]
    /// of the current epoch is kept.
    /// If more secrets from past epochs should be kept in order to be
    /// able to decrypt application messages from previous epochs, the size of
    /// the store must be increased through [`max_past_epochs()`].
    message_secrets_store: MessageSecretsStore,
    // Resumption psk store. This is where the resumption psks are kept in a rollover list.
    resumption_psk_store: ResumptionPskStore,
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

    /// Returns the leaf index of the client in the tree owning this group.
    pub fn own_leaf_index(&self) -> LeafNodeIndex {
        self.own_leaf_index
    }

    /// Returns the leaf node of the client in the tree owning this group.
    pub fn own_leaf_node(&self) -> Option<&LeafNode> {
        self.public_group().leaf(self.own_leaf_index())
    }

    /// Returns the group ID.
    pub fn group_id(&self) -> &GroupId {
        self.public_group.group_id()
    }

    /// Returns the epoch.
    pub fn epoch(&self) -> GroupEpoch {
        self.public_group.group_context().epoch()
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
        self.public_group().group_context().extensions()
    }

    /// Returns the index of the sender of a staged, external commit.
    pub fn ext_commit_sender_index(
        &self,
        commit: &StagedCommit,
    ) -> Result<LeafNodeIndex, LibraryError> {
        self.public_group().ext_commit_sender_index(commit)
    }

    // === Storage Methods ===

    /// Loads the state of the group with given id from persisted state.
    pub fn load<Storage: crate::storage::StorageProvider>(
        storage: &Storage,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroup>, Storage::Error> {
        let public_group = PublicGroup::load(storage, group_id)?;
        let group_epoch_secrets = storage.group_epoch_secrets(group_id)?;
        let own_leaf_index = storage.own_leaf_index(group_id)?;
        let message_secrets_store = storage.message_secrets(group_id)?;
        let resumption_psk_store = storage.resumption_psk_store(group_id)?;
        let mls_group_config = storage.mls_group_join_config(group_id)?;
        let own_leaf_nodes = storage.own_leaf_nodes(group_id)?;
        let group_state = storage.group_state(group_id)?;

        let build = || -> Option<Self> {
            Some(Self {
                public_group: public_group?,
                group_epoch_secrets: group_epoch_secrets?,
                own_leaf_index: own_leaf_index?,
                message_secrets_store: message_secrets_store?,
                resumption_psk_store: resumption_psk_store?,
                mls_group_config: mls_group_config?,
                own_leaf_nodes,
                aad: vec![],
                group_state: group_state?,
            })
        };

        Ok(build())
    }

    /// Remove the persisted state of this group from storage. Note that
    /// signature key material is not managed by OpenMLS and has to be removed
    /// from the storage provider separately (if desired).
    pub fn delete<Storage: crate::storage::StorageProvider>(
        &mut self,
        storage: &Storage,
    ) -> Result<(), Storage::Error> {
        PublicGroup::delete(storage, self.group_id())?;
        storage.delete_own_leaf_index(self.group_id())?;
        storage.delete_group_epoch_secrets(self.group_id())?;
        storage.delete_message_secrets(self.group_id())?;
        storage.delete_all_resumption_psk_secrets(self.group_id())?;
        storage.delete_group_config(self.group_id())?;
        storage.delete_own_leaf_nodes(self.group_id())?;
        storage.delete_group_state(self.group_id())?;
        storage.clear_proposal_queue::<GroupId, ProposalRef>(self.group_id())?;

        self.proposal_store_mut().empty();
        storage.delete_encryption_epoch_key_pairs(
            self.group_id(),
            &self.epoch(),
            self.own_leaf_index().u32(),
        )?;

        self.proposal_store_mut().empty();

        Ok(())
    }

    // === Extensions ===

    /// Exports the Ratchet Tree.
    pub fn export_ratchet_tree(&self) -> RatchetTree {
        self.public_group().export_ratchet_tree()
    }
}

// Crate-public functions
impl MlsGroup {
    /// Get the required capabilities extension of this group.
    pub(crate) fn required_capabilities(&self) -> Option<&RequiredCapabilitiesExtension> {
        self.public_group.required_capabilities()
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
            self.own_leaf_node()
                .ok_or_else(|| LibraryError::custom("Tree has no own leaf."))?
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

    // Encrypt an AuthenticatedContent into an PrivateMessage
    pub(crate) fn encrypt<Provider: OpenMlsProvider>(
        &mut self,
        public_message: AuthenticatedContent,
        provider: &Provider,
    ) -> Result<PrivateMessage, MessageEncryptionError<Provider::StorageError>> {
        let padding_size = self.configuration().padding_size();
        let msg = PrivateMessage::try_from_authenticated_content(
            &public_message,
            self.ciphersuite(),
            provider,
            self.message_secrets_store.message_secrets_mut(),
            padding_size,
        )?;

        provider
            .storage()
            .write_message_secrets(self.group_id(), &self.message_secrets_store)
            .map_err(MessageEncryptionError::StorageError)?;

        Ok(msg)
    }

    /// Group framing parameters
    pub(crate) fn framing_parameters(&self) -> FramingParameters {
        FramingParameters::new(
            &self.aad,
            self.mls_group_config.wire_format_policy().outgoing(),
        )
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

    /// Returns a reference to the public group.
    pub(crate) fn public_group(&self) -> &PublicGroup {
        &self.public_group
    }
}

// Private methods of MlsGroup
impl MlsGroup {
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

    /// Stores the state of this group. Only to be called from constructors to
    /// store the initial state of the group.
    pub(super) fn store<Storage: crate::storage::StorageProvider>(
        &self,
        storage: &Storage,
    ) -> Result<(), Storage::Error> {
        self.public_group.store(storage)?;
        storage.write_group_epoch_secrets(self.group_id(), &self.group_epoch_secrets)?;
        storage.write_own_leaf_index(self.group_id(), &self.own_leaf_index)?;
        storage.write_message_secrets(self.group_id(), &self.message_secrets_store)?;
        storage.write_resumption_psk_store(self.group_id(), &self.resumption_psk_store)?;
        storage.write_mls_join_config(self.group_id(), &self.mls_group_config)?;
        storage.write_group_state(self.group_id(), &self.group_state)?;

        Ok(())
    }

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
                        self.message_secrets().membership_key(),
                        self.message_secrets().serialized_context(),
                    )?;
                }
                plaintext.into()
            }
            OutgoingWireFormatPolicy::AlwaysCiphertext => {
                let ciphertext = self
                    .encrypt(mls_auth_content, provider)
                    // We can be sure the encryption will work because the plaintext was created by us
                    .map_err(|_| LibraryError::custom("Malformed plaintext"))?;
                MlsMessageOut::from_private_message(ciphertext, self.version())
            }
        };
        Ok(msg)
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
}

// Methods used in tests
impl MlsGroup {
    #[cfg(any(feature = "test-utils", test))]
    pub fn export_group_context(&self) -> &GroupContext {
        self.context()
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn tree_hash(&self) -> &[u8] {
        self.public_group().group_context().tree_hash()
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn message_secrets_test_mut(&mut self) -> &mut MessageSecrets {
        self.message_secrets_store.message_secrets_mut()
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn print_ratchet_tree(&self, message: &str) {
        println!("{}: {}", message, self.public_group().export_ratchet_tree());
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn context_mut(&mut self) -> &mut GroupContext {
        self.public_group.context_mut()
    }

    #[cfg(test)]
    pub(crate) fn set_own_leaf_index(&mut self, own_leaf_index: LeafNodeIndex) {
        self.own_leaf_index = own_leaf_index;
    }

    #[cfg(test)]
    pub(crate) fn own_tree_position(&self) -> TreePosition {
        TreePosition::new(self.group_id().clone(), self.own_leaf_index())
    }

    #[cfg(test)]
    pub(crate) fn message_secrets_store(&self) -> &MessageSecretsStore {
        &self.message_secrets_store
    }

    #[cfg(test)]
    pub(crate) fn resumption_psk_store(&self) -> &ResumptionPskStore {
        &self.resumption_psk_store
    }

    #[cfg(test)]
    pub(crate) fn set_group_context(&mut self, group_context: GroupContext) {
        self.public_group.set_group_context(group_context)
    }
}

/// A [`StagedWelcome`] can be inspected and then turned into a [`MlsGroup`].
/// This allows checking who authored the Welcome message.
#[derive(Debug)]
pub struct StagedWelcome {
    // The group configuration. See [`MlsGroupJoinConfig`] for more information.
    mls_group_config: MlsGroupJoinConfig,
    public_group: PublicGroup,
    group_epoch_secrets: GroupEpochSecrets,
    own_leaf_index: LeafNodeIndex,

    /// A [`MessageSecretsStore`] that stores message secrets.
    /// By default this store has the length of 1, i.e. only the [`MessageSecrets`]
    /// of the current epoch is kept.
    /// If more secrets from past epochs should be kept in order to be
    /// able to decrypt application messages from previous epochs, the size of
    /// the store must be increased through [`max_past_epochs()`].
    message_secrets_store: MessageSecretsStore,

    /// Resumption psk store. This is where the resumption psks are kept in a rollover list.
    resumption_psk_store: ResumptionPskStore,

    /// The [`VerifiableGroupInfo`] from the [`Welcome`] message.
    verifiable_group_info: VerifiableGroupInfo,

    /// The key package bundle used for this welcome.
    key_package_bundle: KeyPackageBundle,

    /// If we got a path secret, these are the derived path keys.
    path_keypairs: Option<Vec<EncryptionKeyPair>>,
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
