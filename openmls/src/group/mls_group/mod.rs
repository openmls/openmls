//! MLS Group
//!
//! This module contains [`MlsGroup`] and its submodules.
//!

#[cfg(test)]
use crate::schedule::message_secrets::MessageSecrets;

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
    schedule::ResumptionPskSecret,
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
pub(crate) mod ser;

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
    // The group configuration. See [`MlsGroupJoinConfig`] for more information.
    mls_group_config: MlsGroupJoinConfig,
    // the internal `CoreGroup` used for lower level operations. See `CoreGroup` for more
    // information.
    group: CoreGroup,
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
        self.group.ciphersuite()
    }

    /// Returns whether the own client is still a member of the group or if it
    /// was already evicted
    pub fn is_active(&self) -> bool {
        !matches!(self.group_state, MlsGroupState::Inactive)
    }

    /// Returns own credential. If the group is inactive, it returns a
    /// `UseAfterEviction` error.
    pub fn credential<Provider: OpenMlsProvider>(
        &self,
    ) -> Result<&Credential, MlsGroupStateError<Provider::StorageError>> {
        if !self.is_active() {
            return Err(MlsGroupStateError::UseAfterEviction);
        }
        self.group
            .public_group()
            .leaf(self.own_leaf_index())
            .map(|node| node.credential())
            .ok_or_else(|| LibraryError::custom("Own leaf node missing").into())
    }

    /// Returns the leaf index of the client in the tree owning this group.
    pub fn own_leaf_index(&self) -> LeafNodeIndex {
        self.group.own_leaf_index()
    }

    /// Returns the leaf node of the client in the tree owning this group.
    pub fn own_leaf_node(&self) -> Option<&LeafNode> {
        self.group.own_leaf_node().ok()
    }

    /// Returns the group ID.
    pub fn group_id(&self) -> &GroupId {
        self.group.group_id()
    }

    /// Returns the epoch.
    pub fn epoch(&self) -> GroupEpoch {
        self.group.context().epoch()
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
    fn is_operational<StorageError>(&self) -> Result<(), MlsGroupStateError<StorageError>> {
        match self.group_state {
            MlsGroupState::PendingCommit(_) => Err(MlsGroupStateError::PendingCommit),
            MlsGroupState::Inactive => Err(MlsGroupStateError::UseAfterEviction),
            MlsGroupState::Operational => Ok(()),
        }
    }

    /// Returns a reference to the proposal store.
    pub(crate) fn proposal_store(&self) -> &ProposalStore {
        self.group.proposal_store()
    }

    /// Returns a mutable reference to the proposal store.
    pub(crate) fn proposal_store_mut(&mut self) -> &mut ProposalStore {
        self.group.proposal_store_mut()
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

    #[cfg(test)]
    pub(crate) fn message_secrets_test_mut(&mut self) -> &mut MessageSecrets {
        self.group.message_secrets_test_mut()
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn print_ratchet_tree(&self, message: &str) {
        self.group.print_ratchet_tree(message)
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
