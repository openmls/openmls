//! MLS Group
//!
//! This module contains [`MlsGroup`] and its submodules.
//!

use past_secrets::MessageSecretsStore;
use proposal_store::ProposalQueue;
use serde::{Deserialize, Serialize};

#[cfg(feature = "migration-export")]
use super::proposal_store::ProposalStore;
use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    credentials::Credential,
    group::{Extensions, MlsGroupJoinConfig, PublicGroup, StagedCommit},
    schedule::{
        message_secrets::MessageSecrets, psk::store::ResumptionPskStore, GroupEpochSecrets,
    },
    treesync::node::leaf_node::LeafNode,
};
#[cfg(feature = "migration-export")]
use crate::{
    ciphersuite::hash_ref::ProposalRef,
    group::{GroupContext, GroupEpoch, GroupId},
    messages::ConfirmationTag,
    storage::StorageProvider,
    treesync::node::encryption_keys::EncryptionKeyPair,
};
use openmls_traits::types::Ciphersuite;

#[cfg(feature = "extensions-draft-08")]
use crate::schedule::application_export_tree::ApplicationExportTree;

// Crate
pub(crate) mod config;
pub(crate) mod creation;
pub(crate) mod past_secrets;
pub(crate) mod proposal_store;
pub(crate) mod staged_commit;

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

/// Pending Commit state. Differentiates between Commits issued by group members
/// and External Commits.
#[derive(Debug, Serialize, Deserialize)]
pub enum PendingCommitState {
    /// Commit from a group member
    Member(StagedCommit),
    /// Commit from an external joiner
    External(StagedCommit),
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
///   [`MlsGroup::external_commit_builder()`], see the functions documentation for
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
///     [`MlsGroup::external_commit_builder()`]. In contrast to the
///     [`PendingCommitState::Member`] `PendingCommit` state, the only possible
///     functionality that can be used is the [`MlsGroup::merge_pending_commit()`]
///     function, which merges the pending external commit and transitions the
///     state to [`MlsGroupState::PendingCommit`]. For more information on the
///     external commit process, see [`MlsGroup::external_commit_builder()`] or
///     Section 11.2.1 of the MLS specification.
#[derive(Debug, Serialize, Deserialize)]
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
#[cfg_attr(feature = "migration-export", derive(serde::Serialize))]
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
    /// The state of the Application Exporter. See the MLS Extensions Draft 08
    /// for more information. This is `None` if an old OpenMLS group state was
    /// loaded and has not yet merged a commit.
    #[cfg(feature = "extensions-draft-08")]
    application_export_tree: Option<ApplicationExportTree>,
}

impl MlsGroup {
    // === Configuration ===

    /// Returns the configuration.
    pub fn configuration(&self) -> &MlsGroupJoinConfig {
        &self.mls_group_config
    }

    // === Advanced functions ===

    #[cfg(feature = "migration-export")]
    /// Returns the group's ciphersuite.
    pub fn ciphersuite(&self) -> Ciphersuite {
        self.public_group.ciphersuite()
    }

    #[cfg(feature = "migration-export")]
    /// Get confirmation tag.
    pub fn confirmation_tag(&self) -> &ConfirmationTag {
        self.public_group.confirmation_tag()
    }

    /// Returns the leaf index of the client in the tree owning this group.
    pub fn own_leaf_index(&self) -> LeafNodeIndex {
        self.own_leaf_index
    }

    #[cfg(feature = "migration-export")]
    /// Returns the group ID.
    pub fn group_id(&self) -> &GroupId {
        self.public_group.group_id()
    }

    #[cfg(feature = "migration-export")]
    /// Returns the epoch.
    pub fn epoch(&self) -> GroupEpoch {
        self.public_group.group_context().epoch()
    }

    // === Storage Methods ===

    #[cfg(feature = "migration-export")]
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
        #[cfg(feature = "extensions-draft-08")]
        let application_export_tree = storage.application_export_tree(group_id)?;

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
                #[cfg(feature = "extensions-draft-08")]
                application_export_tree,
            })
        };

        Ok(build())
    }

    #[cfg(feature = "migration-export")]
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

        #[cfg(feature = "extensions-draft-08")]
        storage.delete_application_export_tree::<_, ApplicationExportTree>(self.group_id())?;

        self.proposal_store_mut().empty();
        storage.delete_encryption_epoch_key_pairs(
            self.group_id(),
            &self.epoch(),
            self.own_leaf_index().u32(),
        )?;

        Ok(())
    }

    // === Extensions ===
}

// Crate-public functions
#[cfg(feature = "migration-export")]
impl MlsGroup {
    /// Returns a mutable reference to the proposal store.
    pub(crate) fn proposal_store_mut(&mut self) -> &mut ProposalStore {
        self.public_group.proposal_store_mut()
    }

    /// Get the group context
    pub(crate) fn context(&self) -> &GroupContext {
        self.public_group.group_context()
    }
}

#[cfg(feature = "migration-export")]
impl MlsGroup {
    /// Read the [`EncryptionKeyPair`]s of this group and its current
    /// [`GroupEpoch`] from the `provider`'s storage.
    ///
    /// Returns an error if the lookup in the [`StorageProvider`] fails.
    pub(super) fn read_epoch_keypairs<Storage: StorageProvider>(
        &self,
        store: &Storage,
    ) -> Result<Vec<EncryptionKeyPair>, Storage::Error> {
        store.encryption_epoch_key_pairs(
            self.group_id(),
            &self.context().epoch(),
            self.own_leaf_index().u32(),
        )
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
}

/// A serializable snapshot of a group together with all of the group-associated
/// data it owns, produced for migration to a newer OpenMLS version.
#[cfg(feature = "migration-export")]
#[derive(serde::Serialize)]
pub struct GroupMigrationBundle {
    group: MlsGroup,
    epoch_encryption_key_pairs: Vec<EncryptionKeyPair>,
    update_encryption_key_pairs: Vec<EncryptionKeyPair>,
}

#[cfg(feature = "migration-export")]
impl MlsGroup {
    /// Load a group together with every piece of group-associated data it owns
    /// into one serializable bundle, for migration to a newer OpenMLS version.
    ///
    /// The bundle is serialized to a self-describing format and imported by the
    /// target version (see that version's `GroupMigrationBundle::store`).
    pub fn export_for_migration<Storage: crate::storage::StorageProvider>(
        storage: &Storage,
        group_id: &GroupId,
    ) -> Result<Option<GroupMigrationBundle>, Storage::Error> {
        let Some(group) = Self::load(storage, group_id)? else {
            return Ok(None);
        };

        // The group's own encryption key pairs for the current epoch.
        let epoch_encryption_key_pairs = group.read_epoch_keypairs(storage)?;

        // Encryption key pairs for pending (uncommitted) update leaf nodes.
        let mut update_encryption_key_pairs = Vec::new();
        for leaf_node in group.own_leaf_nodes.iter() {
            if let Some(key_pair) = storage.encryption_key_pair(leaf_node.encryption_key())? {
                update_encryption_key_pairs.push(key_pair);
            }
        }

        Ok(Some(GroupMigrationBundle {
            group,
            epoch_encryption_key_pairs,
            update_encryption_key_pairs,
        }))
    }
}

#[cfg(feature = "migration-export")]
impl GroupMigrationBundle {
    /// Delete the group and all of the group-associated data captured in this
    /// bundle from `storage`.
    ///
    /// Use this to remove the old-format entries after an in-place migration, in
    /// particular when the storage keys changed between versions (e.g. the
    /// `GroupId` serialization differs): the entries can then only be addressed
    /// with this — the previous — version's key encoding, which this method uses.
    pub fn delete<Storage: crate::storage::StorageProvider>(
        &mut self,
        storage: &Storage,
    ) -> Result<(), Storage::Error> {
        // Group state, proposals, and the current epoch's encryption key pairs.
        self.group.delete(storage)?;

        // Pending-update encryption key pairs (keyed by encryption public key).
        for key_pair in &self.update_encryption_key_pairs {
            key_pair.delete(storage)?;
        }

        Ok(())
    }
}
