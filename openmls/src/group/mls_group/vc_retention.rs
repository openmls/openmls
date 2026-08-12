//! Retention lifecycle of an emulation group's derivation epochs
//! (mls-virtual-clients draft).
//!
//! [`VcRetentionState`] holds the bookkeeping and decides what an emulation
//! group protects. This module connects it to the group flows: it starts the
//! bookkeeping where a group becomes an emulation group, computes the
//! declaration an outgoing commit carries, applies a merged commit's membership
//! changes and declaration, deletes derivation-epoch state nothing protects
//! anymore, and offers the application the two signals OpenMLS cannot derive on
//! its own.
//!
//! It also maintains the reverse reference index [`VcEpochRefs`], through which
//! a higher-level group holds a derivation epoch its pending commit, its leaf
//! bindings or its unacknowledged creation still needs. Every reference goes
//! through [`update_vc_epoch_refs`], which keeps a row for exactly as long as
//! something holds the epoch.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{MlsGroup, Proposal, Sender, StagedCommit};
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
    /// Reading or writing retention state failed.
    #[error("Storage error: {0}")]
    Storage(StorageError),
}

/// The `epoch_usage` declaration a commit carries, with the emulation-group leaf
/// of its author.
///
/// Captured when the commit is built or staged, applied when it is merged. Both
/// values install together, so a merge never advances a watermark without the
/// declaration that belongs to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct VcStagedDeclaration {
    author: LeafNodeIndex,
    declared: BTreeSet<EpochId>,
}

impl VcStagedDeclaration {
    pub(crate) fn new(author: LeafNodeIndex, declared: BTreeSet<EpochId>) -> Self {
        Self { author, declared }
    }

    /// The epochs the author declares as in use. An empty set is a declaration
    /// too: it retires everything the author declared before.
    pub(crate) fn declared(&self) -> &BTreeSet<EpochId> {
        &self.declared
    }
}

/// What applying a commit's retention effects needs from the commit's input
/// state.
///
/// Collected before the staged diff is merged, because the registration the
/// merge performs overwrites the newest derivation epoch of the input state, and
/// because the membership the commit changes is read off the pre-merge tree.
pub(crate) struct VcRetentionMergeInput {
    /// The derivation epoch registered before this merge, if any. Absent for a
    /// client that joins the emulation group through this very commit.
    registered: Option<RegisteredVcDerivationEpoch>,
    /// The leaves occupied before the merge.
    occupied_before: BTreeSet<LeafNodeIndex>,
    /// The leaves the commit removes, whether by Remove or by SelfRemove.
    removed: BTreeSet<LeafNodeIndex>,
    /// The declaration the commit carries, if it carries one.
    declaration: Option<VcStagedDeclaration>,
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
        public_group.members().map(|member| member.index),
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

/// Release the binding references `group_id` holds through `bindings`, one per
/// distinct derivation epoch the bindings point at.
///
/// Called where a group's bindings row goes as a whole, on self-removal and on
/// group deletion. The row itself is deleted by the caller.
pub(crate) fn release_vc_binding_refs<Storage: StorageProvider>(
    storage: &Storage,
    group_id: &GroupId,
    bindings: &VcEmulationBindings,
) -> Result<(), Storage::Error> {
    let bound: BTreeSet<&EpochId> = bindings.epoch_ids().collect();
    for epoch_id in bound {
        update_vc_epoch_refs(storage, epoch_id, |refs| {
            refs.remove_binding(group_id);
        })?;
    }
    Ok(())
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
        refs.add_binding(group_id.clone());
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
        refs.add_creation(new_group_id.clone());
    })
}

/// Record the emulation-group leaf `leaf` as seen in `group_id`'s creation
/// tracking, and release the creation reference once every sibling was seen.
///
/// A sibling is seen either because it committed in the created group, which
/// proves it processed the creation, or because it left the emulation group,
/// which means it will never act on the epoch again.
///
/// Releasing does not reap. The epoch becomes reapable and goes at the emulation
/// group's next reap point.
pub(crate) fn mark_vc_creation_seen<Storage: StorageProvider>(
    storage: &Storage,
    group_id: &GroupId,
    leaf: LeafNodeIndex,
) -> Result<(), Storage::Error> {
    let Some(mut tracking): Option<VcCreationTracking> = storage.vc_creation_tracking(group_id)?
    else {
        return Ok(());
    };
    if !tracking.mark_seen(leaf) {
        return Ok(());
    }
    if !tracking.is_complete() {
        return storage.write_vc_creation_tracking(group_id, &tracking);
    }
    storage.delete_vc_creation_tracking(group_id)?;
    update_vc_epoch_refs(storage, tracking.epoch_id(), |refs| {
        refs.remove_creation(group_id);
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
        refs.remove_creation(group_id);
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
    if !group.is_emulation_group() || !group.context().safe_aad_required() {
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
    let newest = state
        .newest_epoch()
        .map(|retained| retained.epoch_id().clone());
    for epoch_id in state.reapable_epochs() {
        if Some(&epoch_id) == newest.as_ref() {
            // The newest epoch is the upper bound of the baseline window, so a
            // group with any member row at all protects it.
            debug_assert!(false, "the newest derivation epoch must never be reapable");
            continue;
        }
        let refs: Option<VcEpochRefs> = storage.vc_epoch_refs(&epoch_id)?;
        if refs.is_some_and(|refs| !refs.is_empty()) {
            continue;
        }
        if storage.has_retained_key_package_material_for_epoch(&epoch_id)? {
            continue;
        }
        storage.delete_vc_derivation_epoch_state(&epoch_id)?;
        storage.delete_vc_epoch_refs(&epoch_id)?;
        state.remove_retained(&epoch_id);
    }
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
        for leaf in removed {
            mark_vc_creation_seen(storage, group_id, *leaf)?;
        }
    }
    Ok(())
}

impl MlsGroup {
    /// Collect what applying `staged_commit`'s retention effects needs from the
    /// commit's input state. Call this before the staged diff is merged.
    pub(crate) fn vc_retention_merge_input<Storage: StorageProvider>(
        &self,
        storage: &Storage,
        staged_commit: &StagedCommit,
    ) -> Result<VcRetentionMergeInput, Storage::Error> {
        let mut removed = BTreeSet::new();
        for queued in staged_commit.queued_proposals() {
            match queued.proposal() {
                Proposal::Remove(remove) => {
                    removed.insert(remove.removed());
                }
                Proposal::SelfRemove => {
                    // Validated proposals always have a member sender here.
                    if let Sender::Member(leaf) = queued.sender() {
                        removed.insert(*leaf);
                    }
                }
                Proposal::Add(_)
                | Proposal::Update(_)
                | Proposal::PreSharedKey(_)
                | Proposal::ReInit(_)
                | Proposal::ExternalInit(_)
                | Proposal::GroupContextExtensions(_)
                | Proposal::AppDataUpdate(_)
                | Proposal::AppEphemeral(_)
                | Proposal::Custom(_) => {}
            }
        }
        let registered: Option<RegisteredVcDerivationEpoch> =
            storage.registered_vc_derivation_epoch(self.group_id())?;
        Ok(VcRetentionMergeInput {
            registered,
            occupied_before: self.occupied_leaves(),
            removed,
            declaration: staged_commit.vc_declaration.clone(),
        })
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
            registered,
            occupied_before,
            removed,
            declaration,
        } = input;
        let output_epoch = self.context().epoch();
        let occupied_now = self.occupied_leaves();

        let mut state = match storage.vc_retention_state(self.group_id())? {
            Some(state) => state,
            None => {
                // This client joined the emulation group through this very
                // commit, by way of an external commit. The creation and Welcome
                // paths initialize the bookkeeping themselves.
                let epoch_id = created
                    .clone()
                    .or_else(|| registered.as_ref().map(|record| record.epoch_id.clone()));
                let Some(epoch_id) = epoch_id else {
                    log::error!(
                        "vc: no derivation epoch to start retention bookkeeping from in {:?}",
                        self.group_id()
                    );
                    return Ok(());
                };
                VcRetentionState::initialize(occupied_now.iter().copied(), output_epoch, epoch_id)
            }
        };

        for leaf in &removed {
            state.member_removed(*leaf);
        }
        // A leaf the commit removes and refills in one step holds a new member,
        // and the new occupant carries none of the previous one's retention.
        let kept: BTreeSet<LeafNodeIndex> = occupied_before.difference(&removed).copied().collect();
        for leaf in occupied_now.difference(&kept) {
            state.member_added(*leaf, output_epoch);
        }

        let created_epoch = created.is_some().then_some(output_epoch);
        if let Some(epoch_id) = created {
            state.record_derivation_epoch(output_epoch, epoch_id);
        }
        if let Some(declaration) = declaration {
            let input_newest = registered.map_or(output_epoch, |record| record.group_epoch);
            state.apply_declaration(
                declaration.author,
                declaration.declared(),
                input_newest,
                created_epoch,
            );
        }

        if !removed.is_empty() {
            release_creations_of_removed_members(storage, &state, &removed)?;
        }
        reap_vc_derivation_epochs(storage, &mut state)?;
        storage.write_vc_retention_state(self.group_id(), &state)
    }

    /// Bring this group's binding references in line with a binding row that
    /// moved from `before` to `now`.
    ///
    /// A derivation epoch the row started pointing at gains a reference, one it
    /// stopped pointing at loses one. Both lists come straight off the row, so
    /// an epoch bound at several of the group's epochs repeats and its reference
    /// only goes when the last of those bindings does.
    pub(crate) fn update_vc_binding_refs<Storage: StorageProvider>(
        &self,
        storage: &Storage,
        before: &[EpochId],
        now: &[EpochId],
    ) -> Result<(), Storage::Error> {
        let bound_before: BTreeSet<&EpochId> = before.iter().collect();
        let bound_now: BTreeSet<&EpochId> = now.iter().collect();
        for epoch_id in bound_now.difference(&bound_before) {
            take_vc_binding_ref(storage, self.group_id(), epoch_id)?;
        }
        let group_id = self.group_id().clone();
        for epoch_id in bound_before.difference(&bound_now) {
            update_vc_epoch_refs(storage, epoch_id, |refs| {
                refs.remove_binding(&group_id);
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
            refs.add_pending_commit(group_id);
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
        let group_id = self.group_id().clone();
        update_vc_epoch_refs(storage, epoch_id, |refs| {
            refs.remove_pending_commit(&group_id);
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
        let mut state = self.load_vc_retention_state(storage)?;
        reap_vc_derivation_epochs(storage, &mut state).map_err(VcRetentionUpdateError::Storage)?;
        storage
            .write_vc_retention_state(self.group_id(), &state)
            .map_err(VcRetentionUpdateError::Storage)
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
    /// A reference has to be registered before the work it covers becomes
    /// visible to anyone else, and before the commit that declares it is built.
    /// The siblings only accept a declared epoch while it is still justified on
    /// their side, so an epoch referenced after the group stopped retaining it
    /// cannot be declared anymore, and the declaring commit is rejected.
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
        let mut state = self.load_vc_retention_state(storage)?;
        state.add_app_reference(epoch_id.clone(), label.to_vec());
        storage
            .write_vc_retention_state(self.group_id(), &state)
            .map_err(VcRetentionUpdateError::Storage)
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
        let mut state = self.load_vc_retention_state(storage)?;
        state.remove_app_reference(epoch_id, label);
        reap_vc_derivation_epochs(storage, &mut state).map_err(VcRetentionUpdateError::Storage)?;
        storage
            .write_vc_retention_state(self.group_id(), &state)
            .map_err(VcRetentionUpdateError::Storage)
    }

    /// The retention bookkeeping of this emulation group.
    pub(crate) fn load_vc_retention_state<Storage: StorageProvider>(
        &self,
        storage: &Storage,
    ) -> Result<VcRetentionState, VcRetentionUpdateError<Storage::Error>> {
        storage
            .vc_retention_state(self.group_id())
            .map_err(VcRetentionUpdateError::Storage)?
            .ok_or(VcRetentionUpdateError::MissingRetentionState)
    }

    /// The leaf indices of the group's current members.
    fn occupied_leaves(&self) -> BTreeSet<LeafNodeIndex> {
        self.public_group()
            .members()
            .map(|member| member.index)
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
