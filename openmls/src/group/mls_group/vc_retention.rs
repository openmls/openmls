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

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{MlsGroup, Proposal, Sender, StagedCommit};
use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::hash_ref::KeyPackageRef,
    components::{
        vc_derivation_info::{EpochId, RegisteredVcDerivationEpoch},
        vc_retention::{VcEpochRefs, VcRetentionState},
    },
    group::PublicGroup,
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

/// The epochs this client declares as in use in its next commit in `group`, or
/// `None` when the commit carries no declaration at all.
///
/// A commit carries no declaration when the group is not an emulation group, when
/// its GroupContext does not require Safe AAD framing so a commit cannot carry
/// the item, and when the group has no retention bookkeeping to declare from.
pub(crate) fn vc_declared_epochs<Storage: StorageProvider>(
    storage: &Storage,
    group: &MlsGroup,
) -> Result<Option<BTreeSet<EpochId>>, Storage::Error> {
    if !group.is_emulation_group() || !group.context().safe_aad_required() {
        return Ok(None);
    }
    let state: Option<VcRetentionState> = storage.vc_retention_state(group.group_id())?;
    Ok(state.map(|state| state.declared_epochs()))
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
    /// carries installs and advances its author's watermark. The reaper runs
    /// last, so the state written here is already free of the epochs it deleted.
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

        reap_vc_derivation_epochs(storage, &mut state)?;
        storage.write_vc_retention_state(self.group_id(), &state)
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
