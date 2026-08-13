//! Retention lifecycle of an emulation group's derivation epochs
//! (mls-virtual-clients draft).
//!
//! [`VcRetentionState`] holds the bookkeeping and decides what an emulation
//! group protects. This module connects it to the group flows: it starts the
//! bookkeeping where a group becomes an emulation group, computes the
//! declaration an outgoing commit carries, applies a merged commit's membership
//! changes and declaration, deletes derivation-epoch state nothing protects
//! anymore, tears the whole bookkeeping down with the group, and offers the
//! application the two signals OpenMLS cannot derive on its own.
//!
//! It also maintains the reverse reference index [`VcEpochRefs`], through which
//! a higher-level group holds a derivation epoch its pending commit, its leaf
//! bindings or its unacknowledged creation still needs. Every reference goes
//! through [`update_vc_epoch_refs`], which keeps a row for exactly as long as
//! something holds the epoch.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{proposal_store::removed_leaves, MlsGroup, StagedCommit};
use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::hash_ref::KeyPackageRef,
    components::{
        vc_derivation_info::{EpochId, RegisteredVcDerivationEpoch, VcEmulationBindings},
        vc_retention::{VcCreationTracking, VcEpochRefs, VcRetentionState},
    },
    group::{GroupId, PublicGroup},
    storage::StorageProvider,
};

/// Error of the virtual-clients retention entry points on [`MlsGroup`].
#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum VcRetentionUpdateError<StorageError> {
    /// The group is not an emulation group, so it holds no derivation-epoch
    /// state and no retention bookkeeping.
    #[error("The group is not an emulation group.")]
    NotAnEmulationGroup,
    /// The group is an emulation group, but its retention bookkeeping was never
    /// initialized, so nothing can be recorded against it.
    #[error("The emulation group has no retention state.")]
    MissingRetentionState,
    /// A reference was taken on a derivation epoch the emulation group does not
    /// retain anymore, so the epoch could not be declared to the siblings.
    #[error("The derivation epoch {0:?} is not retained anymore.")]
    UnretainedEpoch(EpochId),
    /// Reading or writing retention state failed.
    #[error("Storage error: {0}")]
    Storage(StorageError),
}

/// Why a mutation of the retention bookkeeping was rejected. A rejected mutation
/// leaves the stored state untouched.
enum VcRetentionRejection {
    /// A reference was taken on a derivation epoch the bookkeeping does not
    /// protect anymore.
    UnretainedEpoch(EpochId),
}

impl<StorageError> From<VcRetentionRejection> for VcRetentionUpdateError<StorageError> {
    fn from(rejection: VcRetentionRejection) -> Self {
        match rejection {
            VcRetentionRejection::UnretainedEpoch(epoch_id) => Self::UnretainedEpoch(epoch_id),
        }
    }
}

/// The `epoch_usage` declaration a commit carries, with the emulation-group leaf
/// of its author.
///
/// Captured when the commit is built or staged, applied when it is merged. Both
/// values install together, so a merge never advances a watermark without the
/// declaration that belongs to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct VcStagedDeclaration {
    pub(crate) author: LeafNodeIndex,
    /// The epochs the author declares as in use. An empty set is a declaration
    /// too: it retires everything the author declared before.
    pub(crate) declared: BTreeSet<EpochId>,
}

impl VcStagedDeclaration {
    pub(crate) fn new(author: LeafNodeIndex, declared: BTreeSet<EpochId>) -> Self {
        Self { author, declared }
    }
}

/// What applying a commit's retention effects needs from the commit itself.
///
/// Collected before the staged diff is merged, since the merge consumes the
/// staged commit.
pub(crate) struct VcRetentionMergeInput {
    /// The leaves the commit removes, whether by Remove or by SelfRemove.
    removed: BTreeSet<LeafNodeIndex>,
    /// The declaration the commit carries, if it carries one.
    declaration: Option<VcStagedDeclaration>,
}

impl VcRetentionMergeInput {
    pub(crate) fn new(staged_commit: &StagedCommit) -> Self {
        Self {
            removed: removed_leaves(staged_commit.queued_proposals()).collect(),
            declaration: staged_commit.vc_declaration.clone(),
        }
    }
}

/// Start the retention bookkeeping of an emulation group at the derivation epoch
/// `epoch_id`, which the group's current epoch registered.
///
/// Every member starts at the current epoch, including members that were in the
/// group before this client. See [`VcRetentionState::initialize`] for why a
/// joiner cannot do better than that.
pub(crate) fn initialize_vc_retention_state<Storage: StorageProvider>(
    storage: &Storage,
    public_group: &PublicGroup,
    epoch_id: EpochId,
) -> Result<(), Storage::Error> {
    let state = VcRetentionState::initialize(
        public_group
            .treesync()
            .full_leaves()
            .map(|(index, _leaf)| index),
        public_group.group_context().epoch(),
        epoch_id,
    );
    storage.write_vc_retention_state(public_group.group_id(), &state)
}

/// Load the reverse reference index of `epoch_id`, hand it to `mutate`, and
/// persist the result.
///
/// The row is deleted rather than written when the mutation left it empty, so an
/// epoch that no higher-level group holds anymore has no row at all and the
/// reaper's check stays a plain lookup. Every reference this module takes or
/// releases goes through here.
pub(crate) fn update_vc_epoch_refs<Storage: StorageProvider>(
    storage: &Storage,
    epoch_id: &EpochId,
    mutate: impl FnOnce(&mut VcEpochRefs),
) -> Result<(), Storage::Error> {
    let mut refs: VcEpochRefs = storage.vc_epoch_refs(epoch_id)?.unwrap_or_default();
    mutate(&mut refs);
    if refs.is_empty() {
        storage.delete_vc_epoch_refs(epoch_id)
    } else {
        storage.write_vc_epoch_refs(epoch_id, &refs)
    }
}

/// Take the binding reference `group_id` gains by binding one of its epochs to
/// the derivation epoch `epoch_id`.
///
/// Used where a group is created or joined with its first binding already
/// written. Later bindings are diffed against the previous ones in
/// [`MlsGroup::update_vc_binding_refs`].
pub(crate) fn take_vc_binding_ref<Storage: StorageProvider>(
    storage: &Storage,
    group_id: &GroupId,
    epoch_id: &EpochId,
) -> Result<(), Storage::Error> {
    update_vc_epoch_refs(storage, epoch_id, |refs| {
        refs.bindings.insert(group_id.clone());
    })
}

/// Start tracking the higher-level group `new_group_id`, which this client
/// created or externally joined from the derivation epoch `epoch_id` as a
/// virtual client of `emulation_group_id`.
///
/// A sibling that has not processed the creation yet cannot hold a reference to
/// `epoch_id` of its own, and it may still have to derive its leaf in the new
/// group from that epoch. So every sibling that is in the group holds the epoch
/// until all others were seen committing there. `own_leaf` is this client's own
/// emulation leaf, which the tracking does not wait for.
///
/// Nothing is written when this client is the emulation group's only member,
/// since there is no sibling to wait for.
pub(crate) fn initialize_vc_creation_tracking<Storage: StorageProvider>(
    storage: &Storage,
    emulation_group_id: &GroupId,
    new_group_id: &GroupId,
    epoch_id: &EpochId,
    own_leaf: LeafNodeIndex,
) -> Result<(), Storage::Error> {
    let Some(state): Option<VcRetentionState> = storage.vc_retention_state(emulation_group_id)?
    else {
        log::error!(
            "vc: no retention state to read the member set from in {emulation_group_id:?}, \
             tracking no creation of {new_group_id:?}"
        );
        return Ok(());
    };
    let outstanding: BTreeSet<LeafNodeIndex> =
        state.members().filter(|leaf| *leaf != own_leaf).collect();
    if outstanding.is_empty() {
        return Ok(());
    }
    let tracking = VcCreationTracking::new(epoch_id.clone(), outstanding);
    storage.write_vc_creation_tracking(new_group_id, &tracking)?;
    update_vc_epoch_refs(storage, epoch_id, |refs| {
        refs.creations.insert(new_group_id.clone());
    })
}

/// Record the emulation-group leaves `leaves` as seen in `group_id`'s creation
/// tracking, and release the creation reference once every sibling was seen.
///
/// A sibling is seen either because it committed in the created group, which
/// proves it processed the creation, or because it left the emulation group,
/// which means it will never act on the epoch again.
///
/// The tracking row is read and written once, whatever `leaves` holds.
///
/// Releasing does not reap. The epoch becomes reapable and goes at the emulation
/// group's next reap point.
pub(crate) fn mark_vc_creation_seen<Storage: StorageProvider>(
    storage: &Storage,
    group_id: &GroupId,
    leaves: impl IntoIterator<Item = LeafNodeIndex>,
) -> Result<(), Storage::Error> {
    let Some(mut tracking): Option<VcCreationTracking> = storage.vc_creation_tracking(group_id)?
    else {
        return Ok(());
    };
    let mut seen_any = false;
    for leaf in leaves {
        seen_any |= tracking.mark_seen(leaf);
    }
    if !seen_any {
        return Ok(());
    }
    if !tracking.is_complete() {
        return storage.write_vc_creation_tracking(group_id, &tracking);
    }
    storage.delete_vc_creation_tracking(group_id)?;
    update_vc_epoch_refs(storage, tracking.epoch_id(), |refs| {
        refs.creations.remove(group_id);
    })
}

/// Release the creation reference `group_id` holds, whatever is still
/// outstanding, and drop its tracking row.
///
/// Called where the group itself goes: a group that no longer exists needs no
/// sibling to be able to derive a leaf in it.
pub(crate) fn release_vc_creation_tracking<Storage: StorageProvider>(
    storage: &Storage,
    group_id: &GroupId,
) -> Result<(), Storage::Error> {
    let Some(tracking): Option<VcCreationTracking> = storage.vc_creation_tracking(group_id)? else {
        return Ok(());
    };
    storage.delete_vc_creation_tracking(group_id)?;
    update_vc_epoch_refs(storage, tracking.epoch_id(), |refs| {
        refs.creations.remove(group_id);
    })
}

/// The epochs this client declares as in use in its next commit in `group`, or
/// `None` when the commit carries no declaration at all.
///
/// A commit carries no declaration when the group is not an emulation group, when
/// its GroupContext does not require Safe AAD framing so a commit cannot carry
/// the item, and when the group has no retention bookkeeping to declare from.
///
/// On top of what the bookkeeping itself declares, this adds the epochs a
/// higher-level group holds through a pending commit or an unacknowledged
/// creation: the siblings have to keep those, because they have work of this
/// client's that is not on the wire yet.
///
/// Two reference kinds stay out. Retained KeyPackage material is held by every
/// current member anyway, since the upload rides in a commit all of them process.
/// A leaf binding only serves this client's decryption of traffic that was
/// already delivered, which the application's ordering discipline has it process
/// before it acts on a shrinking retention set, so no sibling needs to keep the
/// epoch on its behalf.
pub(crate) fn vc_declared_epochs<Storage: StorageProvider>(
    storage: &Storage,
    group: &MlsGroup,
) -> Result<Option<BTreeSet<EpochId>>, Storage::Error> {
    if !group.carries_vc_commit_data() {
        return Ok(None);
    }
    let Some(state): Option<VcRetentionState> = storage.vc_retention_state(group.group_id())?
    else {
        return Ok(None);
    };
    let mut declared = state.declared_epochs();
    for retained in state.retained_epochs() {
        let epoch_id = retained.epoch_id();
        if declared.contains(epoch_id) {
            continue;
        }
        let Some(refs): Option<VcEpochRefs> = storage.vc_epoch_refs(epoch_id)? else {
            continue;
        };
        if !refs.pending_commits().is_empty() || !refs.creations().is_empty() {
            declared.insert(epoch_id.clone());
        }
    }
    Ok(Some(declared))
}

/// Delete every retained derivation epoch of `state` that nothing protects
/// anymore, and drop it from the retained-epoch log.
///
/// An epoch goes when the retention bookkeeping stopped protecting it, no
/// higher-level group holds it through a [`VcEpochRefs`] entry, and no retained
/// KeyPackage material was derived from it. Deleting the epoch's state also
/// deletes its operation secret tree, so the client can no longer act on the
/// epoch. Callers persist `state` afterwards.
pub(crate) fn reap_vc_derivation_epochs<Storage: StorageProvider>(
    storage: &Storage,
    state: &mut VcRetentionState,
) -> Result<(), Storage::Error> {
    let mut reaped = BTreeSet::new();
    for epoch_id in state.reapable_epochs() {
        let refs: Option<VcEpochRefs> = storage.vc_epoch_refs(&epoch_id)?;
        match refs {
            // A row exists only while something holds the epoch, so an empty
            // one is a leftover this reap cleans up.
            Some(refs) if !refs.is_empty() => continue,
            Some(_) => storage.delete_vc_epoch_refs(&epoch_id)?,
            None => {}
        }
        if storage.has_retained_key_package_material_for_epoch(&epoch_id)? {
            continue;
        }
        storage.delete_vc_derivation_epoch_state(&epoch_id)?;
        reaped.insert(epoch_id);
    }
    state.remove_retained(&reaped);
    Ok(())
}

/// Mark every leaf in `removed` as seen in the creation tracking of the
/// higher-level groups that hold a retained epoch of `state`.
///
/// A client removed from the emulation group performs no further virtual-client
/// operation, so waiting for it to commit in a created group would hold the
/// epoch forever. Run before the reaper, so an epoch this releases can go in the
/// same merge.
fn release_creations_of_removed_members<Storage: StorageProvider>(
    storage: &Storage,
    state: &VcRetentionState,
    removed: &BTreeSet<LeafNodeIndex>,
) -> Result<(), Storage::Error> {
    // Collect first: marking a leaf as seen rewrites the reference rows this
    // walk reads.
    let mut tracked: BTreeSet<GroupId> = BTreeSet::new();
    for retained in state.retained_epochs() {
        let Some(refs): Option<VcEpochRefs> = storage.vc_epoch_refs(retained.epoch_id())? else {
            continue;
        };
        tracked.extend(refs.creations().iter().cloned());
    }
    for group_id in &tracked {
        mark_vc_creation_seen(storage, group_id, removed.iter().copied())?;
    }
    Ok(())
}

impl MlsGroup {
    /// Delete every trace of virtual clients from this group, in both roles a
    /// group can play: as a higher-level group of a virtual client and as an
    /// emulation group.
    ///
    /// Called where the group itself goes, on self-removal and on group deletion.
    /// `pending_epoch_id` names the derivation epoch a still-pending commit was
    /// built from, which the caller has to read off the pending commit before it
    /// overwrites the group state.
    ///
    /// A group only plays one of the two roles, and the teardown of the other one
    /// finds nothing to do.
    pub(crate) fn tear_down_vc_state<Storage: StorageProvider>(
        &self,
        storage: &Storage,
        pending_epoch_id: Option<&EpochId>,
    ) -> Result<(), Storage::Error> {
        self.release_vc_higher_level_state(storage, pending_epoch_id)?;
        self.tear_down_vc_emulation_state(storage)
    }

    /// Release every derivation-epoch reference this group holds as a
    /// higher-level group of a virtual client, and delete the state behind those
    /// references: its leaf bindings and its creation tracking.
    ///
    /// The derivation epochs themselves are not deleted. They are keyed on the
    /// epoch and belong to the emulation group, which may still exist and whose
    /// other higher-level groups may still hold them. A released epoch becomes
    /// reapable and goes at the emulation group's next reap point.
    fn release_vc_higher_level_state<Storage: StorageProvider>(
        &self,
        storage: &Storage,
        pending_epoch_id: Option<&EpochId>,
    ) -> Result<(), Storage::Error> {
        let group_id = self.group_id();
        if let Some(epoch_id) = pending_epoch_id {
            update_vc_epoch_refs(storage, epoch_id, |refs| {
                refs.pending_commits.remove(group_id);
            })?;
        }
        let bindings: Option<VcEmulationBindings> = storage.vc_emulation_bindings(group_id)?;
        if let Some(bindings) = bindings {
            let bound: BTreeSet<&EpochId> = bindings.epoch_ids().collect();
            for epoch_id in bound {
                update_vc_epoch_refs(storage, epoch_id, |refs| {
                    refs.bindings.remove(group_id);
                })?;
            }
        }
        // The virtual client's leaf in this group is gone, so no sibling has to
        // be able to derive one here anymore.
        release_vc_creation_tracking(storage, group_id)?;
        storage.delete_vc_emulation_bindings(group_id)
    }

    /// Delete this group's state as an emulation group: the per-epoch state of
    /// every derivation epoch its retained-epoch log still holds, the KeyPackage
    /// material retained from those epochs, the log itself, and the
    /// derivation-epoch registration record.
    ///
    /// Unlike the reaper, this deletes every retained epoch unconditionally,
    /// references and retained KeyPackage material notwithstanding. The virtual
    /// client is gone with its emulation group, so nothing can act on one of its
    /// epochs anymore, and the retained-epoch log is the only index of that
    /// per-epoch state: whatever the log still names when it goes is key material
    /// nothing could ever find again, let alone delete.
    ///
    /// The retained KeyPackage material goes for the same reason. It is keyed by
    /// KeyPackage reference, so the log is the only way to reach it, and its seed
    /// secret is usable without any of the epoch state deleted here.
    fn tear_down_vc_emulation_state<Storage: StorageProvider>(
        &self,
        storage: &Storage,
    ) -> Result<(), Storage::Error> {
        let group_id = self.group_id();
        let state: Option<VcRetentionState> = storage.vc_retention_state(group_id)?;
        if let Some(state) = state {
            for retained in state.retained_epochs() {
                storage.delete_vc_derivation_epoch_state(retained.epoch_id())?;
                storage.delete_vc_epoch_refs(retained.epoch_id())?;
                storage.delete_retained_key_package_material_for_epoch(retained.epoch_id())?;
            }
        }
        storage.delete_registered_vc_derivation_epoch(group_id)?;
        storage.delete_vc_retention_state(group_id)
    }

    /// Apply a merged commit's retention effects, with the group already moved
    /// into the commit's output epoch and `created` naming the derivation epoch
    /// the merge registered, if it registered one.
    ///
    /// Members come and go with the commit's proposals, a created derivation
    /// epoch is appended to the retained-epoch log, and a declaration the commit
    /// carries installs and advances its author's watermark. A removed member is
    /// also marked as seen in every creation tracking that still waits for it,
    /// since it will never act on the epoch again. The reaper runs last, so the
    /// state written here is already free of the epochs it deleted.
    pub(crate) fn apply_vc_retention_at_merge<Storage: StorageProvider>(
        &self,
        storage: &Storage,
        input: VcRetentionMergeInput,
        created: Option<EpochId>,
    ) -> Result<(), Storage::Error> {
        let VcRetentionMergeInput {
            removed,
            declaration,
        } = input;
        let output_epoch = self.context().epoch();
        let occupied_now = self.occupied_leaves();
        // The registration this merge performed, which is the authority on the
        // emulation-group epoch a derivation epoch was sourced from. Every
        // retention comparison is made against the log's epoch numbers, and the
        // group's current epoch may run ahead of the epoch the registration
        // recorded.
        let registered: Option<RegisteredVcDerivationEpoch> =
            storage.registered_vc_derivation_epoch(self.group_id())?;
        let created = created.map(|epoch_id| {
            let sourced_from = match &registered {
                Some(record) if record.epoch_id == epoch_id => record.group_epoch,
                _ => output_epoch,
            };
            (sourced_from, epoch_id)
        });
        // A commit that changes membership always creates a derivation epoch, so
        // a member row is only ever added at one.
        let member_epoch = created.as_ref().map_or(output_epoch, |(epoch, _)| *epoch);

        let mut state = match storage.vc_retention_state(self.group_id())? {
            Some(state) => state,
            None => {
                // This client joined the emulation group through this very
                // commit, by way of an external commit. The creation and Welcome
                // paths initialize the bookkeeping themselves.
                let seed = created.clone().or_else(|| {
                    registered
                        .as_ref()
                        .map(|record| (record.group_epoch, record.epoch_id.clone()))
                });
                let Some((epoch, epoch_id)) = seed else {
                    log::error!(
                        "vc: no derivation epoch to start retention bookkeeping from in {:?}",
                        self.group_id()
                    );
                    return Ok(());
                };
                VcRetentionState::initialize(occupied_now.iter().copied(), epoch, epoch_id)
            }
        };

        for leaf in &removed {
            state.member_removed(*leaf);
        }
        // The removals above ran first, so a leaf the commit removes and refills
        // in one step has no row left here and gets a fresh one: the new occupant
        // carries none of the previous one's retention.
        for leaf in &occupied_now {
            if state.member(*leaf).is_none() {
                state.member_added(*leaf, member_epoch);
            }
        }

        if let Some((epoch, epoch_id)) = created {
            state.record_derivation_epoch(epoch, epoch_id);
        }
        // After the registration above, so the author advances to a derivation
        // epoch the commit creates rather than to the one it built on.
        if let Some(declaration) = declaration {
            state.apply_declaration(declaration.author, &declaration.declared);
        }

        if !removed.is_empty() {
            release_creations_of_removed_members(storage, &state, &removed)?;
        }
        reap_vc_derivation_epochs(storage, &mut state)?;
        storage.write_vc_retention_state(self.group_id(), &state)
    }

    /// Bring this group's binding references in line with a binding row that now
    /// binds `bound` and stopped pointing at every epoch in `unbound`.
    ///
    /// `unbound` comes straight off [`VcEmulationBindings::insert`], so an epoch
    /// bound at several of the group's epochs keeps its reference until the last
    /// of those bindings goes.
    pub(crate) fn update_vc_binding_refs<Storage: StorageProvider>(
        &self,
        storage: &Storage,
        bound: &EpochId,
        unbound: &[EpochId],
    ) -> Result<(), Storage::Error> {
        take_vc_binding_ref(storage, self.group_id(), bound)?;
        let group_id = self.group_id();
        for epoch_id in unbound {
            update_vc_epoch_refs(storage, epoch_id, |refs| {
                refs.bindings.remove(group_id);
            })?;
        }
        Ok(())
    }

    /// Take a pending-commit reference on `epoch_id` for this group, the epoch a
    /// commit that is about to become pending was built from.
    pub(crate) fn take_vc_pending_commit_ref<Storage: StorageProvider>(
        &self,
        storage: &Storage,
        epoch_id: &EpochId,
    ) -> Result<(), Storage::Error> {
        let group_id = self.group_id().clone();
        update_vc_epoch_refs(storage, epoch_id, |refs| {
            refs.pending_commits.insert(group_id);
        })
    }

    /// Release the pending-commit reference this group holds on `epoch_id`.
    ///
    /// Called from both ends of a pending commit's life, its merge and its
    /// discard. Releasing does not reap: the epoch becomes reapable and goes at
    /// the emulation group's next reap point.
    pub(crate) fn release_vc_pending_commit_ref<Storage: StorageProvider>(
        &self,
        storage: &Storage,
        epoch_id: &EpochId,
    ) -> Result<(), Storage::Error> {
        let group_id = self.group_id();
        update_vc_epoch_refs(storage, epoch_id, |refs| {
            refs.pending_commits.remove(group_id);
        })
    }

    /// Tell OpenMLS that the virtual client's KeyPackages named by
    /// `key_package_refs` have reached the end of their life, so the material
    /// retained for them can go.
    ///
    /// This is the one signal that releases a derivation epoch held only by
    /// KeyPackage material. That material is what lets a client derive the leaf
    /// of a Welcome addressed to one of the virtual client's KeyPackages, so
    /// OpenMLS cannot tell on its own when a published KeyPackage will never be
    /// welcomed again. Only the application knows, from the lifetime it published
    /// under and from what the delivery service still hands out.
    ///
    /// The material of a reference a Welcome consumed was deleted when that
    /// Welcome was processed, so passing consumed references again is harmless.
    /// Once the last material of a derivation epoch is gone, the epoch's state is
    /// deleted unless something else still protects it.
    ///
    /// Fails with [`VcRetentionUpdateError::NotAnEmulationGroup`] unless this
    /// group is the virtual client's emulation group.
    pub fn vc_key_packages_end_of_life<Storage: StorageProvider>(
        &self,
        storage: &Storage,
        key_package_refs: &[KeyPackageRef],
    ) -> Result<(), VcRetentionUpdateError<Storage::Error>> {
        self.require_emulation_group()?;
        for key_package_ref in key_package_refs {
            storage
                .delete_retained_key_package_material(key_package_ref)
                .map_err(VcRetentionUpdateError::Storage)?;
        }
        self.with_vc_retention_state(storage, |_state| Ok(()))
    }

    /// Record that the application holds the derivation epoch `epoch_id` under
    /// `label`, so neither this client nor its siblings delete the epoch's
    /// state.
    ///
    /// References cover work OpenMLS cannot see, such as a batch of
    /// virtual-client KeyPackages the application is about to publish out of
    /// band. The epoch stays on this client and is folded into every declaration
    /// this client sends, which is how the siblings learn to keep it.
    ///
    /// The epoch must still be protected by this emulation group's bookkeeping,
    /// which is why the reference has to be taken before the work it covers
    /// becomes visible to anyone else, and before the commit that declares it is
    /// built. Fails with [`VcRetentionUpdateError::UnretainedEpoch`] otherwise:
    /// the siblings only accept a declared epoch while it is still justified on
    /// their side, so a reference on an epoch this client no longer retains would
    /// put an unjustifiable entry in every declaration it sends from then on and
    /// have the siblings reject its commits.
    ///
    /// Release the reference with [`Self::remove_vc_epoch_reference`]. Adding a
    /// reference that is already held changes nothing.
    pub fn add_vc_epoch_reference<Storage: StorageProvider>(
        &self,
        storage: &Storage,
        epoch_id: &EpochId,
        label: &[u8],
    ) -> Result<(), VcRetentionUpdateError<Storage::Error>> {
        self.require_emulation_group()?;
        self.with_vc_retention_state(storage, |state| {
            if !state.blob_protected_epochs().contains(&epoch_id) {
                return Err(VcRetentionRejection::UnretainedEpoch(epoch_id.clone()));
            }
            state.add_app_reference(epoch_id.clone(), label.to_vec());
            Ok(())
        })
    }

    /// Release the application's reference to `epoch_id` held under `label`, and
    /// delete the epoch's state if nothing protects it anymore.
    ///
    /// The epoch stops being declared from here on. The siblings keep it until
    /// they see a declaration of this client that no longer names it, so the
    /// group as a whole releases it with the next commit this client sends.
    ///
    /// See [`Self::add_vc_epoch_reference`] for what a reference is. Releasing a
    /// reference that is not held changes nothing.
    pub fn remove_vc_epoch_reference<Storage: StorageProvider>(
        &self,
        storage: &Storage,
        epoch_id: &EpochId,
        label: &[u8],
    ) -> Result<(), VcRetentionUpdateError<Storage::Error>> {
        self.require_emulation_group()?;
        self.with_vc_retention_state(storage, |state| {
            state.remove_app_reference(epoch_id, label);
            Ok(())
        })
    }

    /// Load this emulation group's retention bookkeeping, hand it to `mutate`,
    /// delete what nothing protects anymore and persist the result.
    ///
    /// A `mutate` that rejects the update leaves the stored state untouched.
    ///
    /// Reaping on every update is what keeps the three application-facing entry
    /// points uniform. It is sound for an update that only adds protection, since
    /// a larger protected set reaps nothing.
    fn with_vc_retention_state<Storage: StorageProvider>(
        &self,
        storage: &Storage,
        mutate: impl FnOnce(&mut VcRetentionState) -> Result<(), VcRetentionRejection>,
    ) -> Result<(), VcRetentionUpdateError<Storage::Error>> {
        let mut state: VcRetentionState = storage
            .vc_retention_state(self.group_id())
            .map_err(VcRetentionUpdateError::Storage)?
            .ok_or(VcRetentionUpdateError::MissingRetentionState)?;
        mutate(&mut state)?;
        reap_vc_derivation_epochs(storage, &mut state).map_err(VcRetentionUpdateError::Storage)?;
        storage
            .write_vc_retention_state(self.group_id(), &state)
            .map_err(VcRetentionUpdateError::Storage)
    }

    /// The leaf indices of the group's current members.
    fn occupied_leaves(&self) -> BTreeSet<LeafNodeIndex> {
        self.public_group()
            .treesync()
            .full_leaves()
            .map(|(index, _leaf)| index)
            .collect()
    }

    fn require_emulation_group<StorageError>(
        &self,
    ) -> Result<(), VcRetentionUpdateError<StorageError>> {
        if self.is_emulation_group() {
            Ok(())
        } else {
            Err(VcRetentionUpdateError::NotAnEmulationGroup)
        }
    }
}
