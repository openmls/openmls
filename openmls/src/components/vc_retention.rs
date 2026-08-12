//! Retention bookkeeping for derivation-epoch state (mls-virtual-clients
//! draft).
//!
//! Emulator clients of one virtual client must agree on which derivation epochs
//! stay retained. Each client publishes a watermark by declaring its in-use
//! epochs in the `epoch_usage` of a commit, the group keeps the baseline
//! retention window from the lowest watermark through the newest derivation
//! epoch, and the effective retention set adds every member's latest
//! declaration and the obligations assumed for removed clients.
//!
//! [`VcRetentionState`] holds all of that for one emulation group. It is a
//! single storage entity because a commit installs its author's watermark and
//! its declaration together, and a reader that saw one without the other could
//! delete state another client still declares as in use.
//!
//! The state is pure bookkeeping. Nothing in this module touches storage or
//! derives key material.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    binary_tree::LeafNodeIndex,
    components::vc_derivation_info::EpochId,
    group::{GroupEpoch, GroupId},
};

/// Errors that can occur while applying or validating retention bookkeeping.
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum VcRetentionError {
    /// An `epoch_usage` entry names an epoch that the receiving client does not
    /// retain: it lies outside the baseline window, no member's latest
    /// declaration covers it, and it is not an assumed obligation.
    #[error("epoch_usage refers to the unretained derivation epoch {0:?}")]
    UnretainedEpoch(EpochId),
}

/// One entry of an emulation group's retained-epoch log, the draft's
/// `RetainedVcEpoch`: a derivation epoch together with the emulation-group
/// epoch number it was sourced from.
///
/// The number orders derivation epochs against each other and against the
/// per-member watermarks. It is the only ordering available, since an
/// [`EpochId`] is an opaque hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedVcEpoch {
    emulation_group_epoch: GroupEpoch,
    epoch_id: EpochId,
}

impl RetainedVcEpoch {
    /// The emulation-group epoch this derivation epoch was sourced from.
    pub fn emulation_group_epoch(&self) -> GroupEpoch {
        self.emulation_group_epoch
    }

    /// The derivation epoch.
    pub fn epoch_id(&self) -> &EpochId {
        &self.epoch_id
    }
}

/// What an emulation group records about one of its members for retention
/// purposes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VcMemberRetention {
    watermark: GroupEpoch,
    latest_declaration: Option<BTreeSet<EpochId>>,
}

impl VcMemberRetention {
    fn new(watermark: GroupEpoch) -> Self {
        Self {
            watermark,
            latest_declaration: None,
        }
    }

    /// The member's watermark, as the emulation-group epoch number of a
    /// derivation epoch. Every derivation epoch from here through the newest
    /// one stays retained on the member's behalf.
    pub fn watermark(&self) -> GroupEpoch {
        self.watermark
    }

    /// The member's latest applied declaration, or `None` if the member never
    /// declared.
    ///
    /// An empty set is not the same as `None`, matching the wire distinction
    /// between an absent and an empty `epoch_usage`: an empty declaration
    /// retires everything the member declared before, an absent one leaves the
    /// previous declaration in place.
    pub fn latest_declaration(&self) -> Option<&BTreeSet<EpochId>> {
        self.latest_declaration.as_ref()
    }
}

/// The retention bookkeeping of one emulation group.
///
/// Holds the ordered log of retained derivation epochs, one row per member, the
/// obligations assumed for removed clients, and the application's own labeled
/// epoch references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VcRetentionState {
    /// Ascending by `emulation_group_epoch`, oldest first.
    retained_epochs: Vec<RetainedVcEpoch>,
    members: BTreeMap<LeafNodeIndex, VcMemberRetention>,
    removed_client_usage: BTreeSet<EpochId>,
    /// The application's labeled epoch references, as `(epoch_id, label)` pairs.
    /// A set of pairs rather than a map from epoch to labels, so that the state
    /// also serializes in formats that only allow string map keys.
    app_references: BTreeSet<(EpochId, Vec<u8>)>,
}

impl VcRetentionState {
    /// Start the bookkeeping of an emulation group at the derivation epoch
    /// `epoch_id`, sourced from emulation-group epoch `epoch`, with one row per
    /// leaf in `members` and every watermark at `epoch`.
    ///
    /// Used at emulation-group creation, where `members` is the creator alone.
    /// Until state transfer for added emulator clients lands, it is also used
    /// when joining an emulation group from a Welcome, with all current
    /// members: a joiner cannot retain epochs older than its entry epoch
    /// anyway, so initializing every member at the entry epoch is the only
    /// sound choice it can make on its own.
    pub fn initialize(
        members: impl IntoIterator<Item = LeafNodeIndex>,
        epoch: GroupEpoch,
        epoch_id: EpochId,
    ) -> Self {
        Self {
            retained_epochs: vec![RetainedVcEpoch {
                emulation_group_epoch: epoch,
                epoch_id,
            }],
            members: members
                .into_iter()
                .map(|leaf| (leaf, VcMemberRetention::new(epoch)))
                .collect(),
            removed_client_usage: BTreeSet::new(),
            app_references: BTreeSet::new(),
        }
    }

    /// Append a newly registered derivation epoch to the log.
    ///
    /// Epoch numbers must grow: an emulation-group epoch registers at most one
    /// derivation epoch, and the log's order is what places an epoch inside or
    /// outside the baseline window. A repeat of the newest entry is ignored, so
    /// a caller that retries a merge does not corrupt the log. Any other
    /// non-monotonic call is a bug and leaves the log unchanged.
    pub fn record_derivation_epoch(&mut self, epoch: GroupEpoch, epoch_id: EpochId) {
        if let Some(newest) = self.retained_epochs.last() {
            if newest.emulation_group_epoch == epoch && newest.epoch_id == epoch_id {
                return;
            }
            debug_assert!(
                epoch > newest.emulation_group_epoch,
                "derivation epochs must be recorded in increasing emulation-group epoch order"
            );
            if epoch <= newest.emulation_group_epoch {
                log::error!(
                    "vc: refusing to record derivation epoch for group epoch {epoch}, newest is {}",
                    newest.emulation_group_epoch
                );
                return;
            }
        }
        self.retained_epochs.push(RetainedVcEpoch {
            emulation_group_epoch: epoch,
            epoch_id,
        });
    }

    /// Record a member added at emulation-group epoch `epoch`, with its
    /// watermark there and no declaration.
    ///
    /// Overwrites an existing row, which is what a leaf reused after a removal
    /// needs: the new occupant carries none of the old one's retention.
    pub fn member_added(&mut self, leaf: LeafNodeIndex, epoch: GroupEpoch) {
        self.members.insert(leaf, VcMemberRetention::new(epoch));
    }

    /// Drop a removed member's row, so its watermark stops pinning the baseline
    /// window.
    ///
    /// Removal alone discharges nothing. Capturing the removed client's
    /// obligations into `removed_client_usage` is separate and lands with
    /// removal obligations.
    pub fn member_removed(&mut self, leaf: LeafNodeIndex) {
        self.members.remove(&leaf);
    }

    /// Install `declaration` as the author's latest declaration and advance the
    /// author's watermark.
    ///
    /// `input_newest` is the newest derivation epoch of the commit's input
    /// state, and `created` is the epoch the commit creates a derivation epoch
    /// at, if it creates one. The watermark advances to `created` when the
    /// commit creates a derivation epoch, otherwise to `input_newest`.
    ///
    /// Only the author's row moves. Receiving a commit advances nothing for the
    /// recipient. A commit that carries no declaration must not reach this
    /// method: no declaration means no advancement.
    ///
    /// Watermarks never move backwards, so a declaration applied out of order
    /// keeps the higher watermark. The author's row is created if it is missing,
    /// at the same watermark, so a commit from a member the local state has not
    /// recorded yet still installs its declaration.
    pub fn apply_declaration(
        &mut self,
        author: LeafNodeIndex,
        declaration: &BTreeSet<EpochId>,
        input_newest: GroupEpoch,
        created: Option<GroupEpoch>,
    ) {
        let target = created.unwrap_or(input_newest);
        let member = self
            .members
            .entry(author)
            .or_insert_with(|| VcMemberRetention::new(target));
        member.watermark = member.watermark.max(target);
        member.latest_declaration = Some(declaration.clone());
    }

    /// The lowest watermark over all members, the lower bound of the baseline
    /// retention window. `None` if the group has no member rows.
    pub fn watermark_floor(&self) -> Option<GroupEpoch> {
        self.members
            .values()
            .map(VcMemberRetention::watermark)
            .min()
    }

    /// The newest retained derivation epoch, the upper bound of the baseline
    /// retention window.
    pub fn newest_epoch(&self) -> Option<&RetainedVcEpoch> {
        self.retained_epochs.last()
    }

    /// The retained-epoch log, oldest first.
    pub fn retained_epochs(&self) -> &[RetainedVcEpoch] {
        &self.retained_epochs
    }

    /// The bookkeeping for one member, or `None` if the leaf holds no member of
    /// this emulation group.
    pub fn member(&self, leaf: LeafNodeIndex) -> Option<&VcMemberRetention> {
        self.members.get(&leaf)
    }

    /// The emulation-group epoch number `epoch_id` was sourced from, or `None`
    /// if the epoch is not in the log.
    pub fn epoch_number(&self, epoch_id: &EpochId) -> Option<GroupEpoch> {
        self.retained_epochs
            .iter()
            .find(|retained| &retained.epoch_id == epoch_id)
            .map(RetainedVcEpoch::emulation_group_epoch)
    }

    /// Whether `epoch_id` lies in the baseline retention window, from the
    /// watermark floor through the newest derivation epoch.
    ///
    /// An epoch that is not in the log is not in the window.
    pub fn is_in_baseline_window(&self, epoch_id: &EpochId) -> bool {
        let (Some(floor), Some(newest), Some(number)) = (
            self.watermark_floor(),
            self.newest_epoch(),
            self.epoch_number(epoch_id),
        ) else {
            return false;
        };
        number >= floor && number <= newest.emulation_group_epoch
    }

    /// Every epoch this state protects: the baseline window, every member's
    /// latest declaration, the assumed obligations, and the application's
    /// references.
    ///
    /// This covers only what the state itself knows. An epoch outside the set
    /// may still be referenced from elsewhere, so the reaper deletes a retained
    /// epoch only if it is outside this set, has no [`VcEpochRefs`], and has no
    /// retained KeyPackage material.
    pub fn blob_protected_epochs(&self) -> BTreeSet<EpochId> {
        let mut protected = BTreeSet::new();
        if let (Some(floor), Some(newest)) = (self.watermark_floor(), self.newest_epoch()) {
            let window = floor..=newest.emulation_group_epoch;
            protected.extend(
                self.retained_epochs
                    .iter()
                    .filter(|retained| window.contains(&retained.emulation_group_epoch))
                    .map(|retained| retained.epoch_id.clone()),
            );
        }
        for member in self.members.values() {
            if let Some(declaration) = &member.latest_declaration {
                protected.extend(declaration.iter().cloned());
            }
        }
        protected.extend(self.removed_client_usage.iter().cloned());
        protected.extend(self.referenced_epochs());
        protected
    }

    /// The retained epochs this state no longer protects, in log order. The
    /// reaper still has to check the other reference sources before it deletes
    /// one of them.
    pub fn reapable_epochs(&self) -> Vec<EpochId> {
        let protected = self.blob_protected_epochs();
        self.retained_epochs
            .iter()
            .filter(|retained| !protected.contains(&retained.epoch_id))
            .map(|retained| retained.epoch_id.clone())
            .collect()
    }

    /// Drop `epoch_id` from the retained-epoch log. Called by the reaper once
    /// the epoch's state is deleted.
    pub fn remove_retained(&mut self, epoch_id: &EpochId) {
        self.retained_epochs
            .retain(|retained| &retained.epoch_id != epoch_id);
    }

    /// The epochs this client declares as in use in its next commit: the
    /// obligations it assumed for removed clients and the epochs the
    /// application holds a reference to.
    ///
    /// Epochs that are only kept alive by retained KeyPackage material are
    /// deliberately absent. Every current member holds that material as a local
    /// reference of its own, since the upload rides in a commit all of them
    /// process, so declaring it would say nothing new.
    pub fn declared_epochs(&self) -> BTreeSet<EpochId> {
        let mut declared = self.removed_client_usage.clone();
        declared.extend(self.referenced_epochs());
        declared
    }

    /// The epochs the application holds a reference to, under any label.
    fn referenced_epochs(&self) -> impl Iterator<Item = EpochId> + '_ {
        self.app_references
            .iter()
            .map(|(epoch_id, _label)| epoch_id.clone())
    }

    /// Check a commit's `epoch_usage` against this state, which must be the
    /// state the commit was built on.
    ///
    /// Every entry has to be justified by one of the three sources the whole
    /// group can see: the baseline window, some member's latest declaration, or
    /// the assumed obligations. Local references and application references
    /// justify nothing, because no other client knows about them.
    pub fn validate_epoch_usage(&self, usage: &BTreeSet<EpochId>) -> Result<(), VcRetentionError> {
        for epoch_id in usage {
            if self.is_in_baseline_window(epoch_id)
                || self.removed_client_usage.contains(epoch_id)
                || self.is_declared_by_any_member(epoch_id)
            {
                continue;
            }
            return Err(VcRetentionError::UnretainedEpoch(epoch_id.clone()));
        }
        Ok(())
    }

    /// Record an application reference to `epoch_id` under `label`. Returns
    /// whether the reference is new.
    ///
    /// References cover work OpenMLS cannot see. They keep the epoch's state
    /// alive locally and are folded into this client's outgoing declarations,
    /// which is how other clients learn to keep the epoch.
    pub fn add_app_reference(&mut self, epoch_id: EpochId, label: Vec<u8>) -> bool {
        self.app_references.insert((epoch_id, label))
    }

    /// Release the application reference to `epoch_id` held under `label`.
    /// Returns whether a reference was released.
    pub fn remove_app_reference(&mut self, epoch_id: &EpochId, label: &[u8]) -> bool {
        self.app_references
            .remove(&(epoch_id.clone(), label.to_vec()))
    }

    fn is_declared_by_any_member(&self, epoch_id: &EpochId) -> bool {
        self.members.values().any(|member| {
            member
                .latest_declaration
                .as_ref()
                .is_some_and(|declaration| declaration.contains(epoch_id))
        })
    }
}

/// The higher-level groups that hold one derivation epoch, keyed by that epoch.
///
/// A pending commit, an active leaf binding and an unacknowledged group creation
/// all keep an epoch's state in use, and all three live keyed by higher-level
/// group. A reaper working on one emulation group cannot enumerate those, so
/// each epoch keeps this reverse index of them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VcEpochRefs {
    pending_commits: BTreeSet<GroupId>,
    bindings: BTreeSet<GroupId>,
    creations: BTreeSet<GroupId>,
}

impl VcEpochRefs {
    /// Whether no higher-level group holds this epoch anymore.
    pub fn is_empty(&self) -> bool {
        self.pending_commits.is_empty() && self.bindings.is_empty() && self.creations.is_empty()
    }

    /// Record that `group_id` has a pending commit drawing on this epoch.
    /// Returns whether the index changed.
    pub fn add_pending_commit(&mut self, group_id: GroupId) -> bool {
        self.pending_commits.insert(group_id)
    }

    /// Release `group_id`'s pending-commit reference, on merge or on discard.
    /// Returns whether the index changed.
    pub fn remove_pending_commit(&mut self, group_id: &GroupId) -> bool {
        self.pending_commits.remove(group_id)
    }

    /// Record that `group_id` has a leaf bound to this epoch. Returns whether
    /// the index changed.
    pub fn add_binding(&mut self, group_id: GroupId) -> bool {
        self.bindings.insert(group_id)
    }

    /// Release `group_id`'s binding reference. Returns whether the index
    /// changed.
    pub fn remove_binding(&mut self, group_id: &GroupId) -> bool {
        self.bindings.remove(group_id)
    }

    /// Record that `group_id` was created or externally joined from this epoch
    /// and not all siblings have acknowledged it yet. Returns whether the index
    /// changed.
    pub fn add_creation(&mut self, group_id: GroupId) -> bool {
        self.creations.insert(group_id)
    }

    /// Release `group_id`'s creation reference. Returns whether the index
    /// changed.
    pub fn remove_creation(&mut self, group_id: &GroupId) -> bool {
        self.creations.remove(group_id)
    }
}

/// Which siblings still have to be seen committing in a higher-level group the
/// virtual client created or externally joined, and the derivation epoch that
/// creation drew on.
///
/// A sibling that has not committed in the group yet may still have to derive
/// its own leaf from `epoch_id`, so the epoch stays retained until `outstanding`
/// empties.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VcCreationTracking {
    epoch_id: EpochId,
    outstanding: BTreeSet<LeafNodeIndex>,
}

impl VcCreationTracking {
    /// Start tracking a group created or externally joined from `epoch_id`,
    /// waiting on the emulation-group members in `outstanding`.
    pub fn new(epoch_id: EpochId, outstanding: impl IntoIterator<Item = LeafNodeIndex>) -> Self {
        Self {
            epoch_id,
            outstanding: outstanding.into_iter().collect(),
        }
    }

    /// The derivation epoch the creation drew on.
    pub fn epoch_id(&self) -> &EpochId {
        &self.epoch_id
    }

    /// The emulation-group members not yet seen committing in the group.
    pub fn outstanding(&self) -> &BTreeSet<LeafNodeIndex> {
        &self.outstanding
    }

    /// Record `leaf` as seen, either because it committed in the group or
    /// because it was removed from the emulation group. Returns whether the set
    /// changed.
    pub fn mark_seen(&mut self, leaf: LeafNodeIndex) -> bool {
        self.outstanding.remove(&leaf)
    }

    /// Whether every sibling has been seen, so the epoch reference can go.
    pub fn is_complete(&self) -> bool {
        self.outstanding.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch_id(bytes: &[u8]) -> EpochId {
        EpochId::new(bytes.to_vec())
    }

    fn epoch(number: u64) -> GroupEpoch {
        GroupEpoch::from(number)
    }

    fn leaf(index: u32) -> LeafNodeIndex {
        LeafNodeIndex::new(index)
    }

    fn usage(epoch_ids: impl IntoIterator<Item = EpochId>) -> BTreeSet<EpochId> {
        epoch_ids.into_iter().collect()
    }

    /// Two members, three derivation epochs, no declarations.
    fn state_with_three_epochs() -> VcRetentionState {
        let mut state =
            VcRetentionState::initialize([leaf(0), leaf(1)], epoch(1), epoch_id(b"epoch-1"));
        state.record_derivation_epoch(epoch(2), epoch_id(b"epoch-2"));
        state.record_derivation_epoch(epoch(3), epoch_id(b"epoch-3"));
        state
    }

    #[test]
    fn initialize_puts_every_member_at_the_initial_epoch() {
        let state = VcRetentionState::initialize([leaf(0), leaf(2)], epoch(7), epoch_id(b"first"));

        assert_eq!(state.watermark_floor(), Some(epoch(7)));
        assert_eq!(
            state.newest_epoch().map(RetainedVcEpoch::epoch_id),
            Some(&epoch_id(b"first"))
        );
        for index in [0, 2] {
            let member = state.member(leaf(index)).expect("member row exists");
            assert_eq!(member.watermark(), epoch(7));
            assert_eq!(member.latest_declaration(), None);
        }
        assert_eq!(state.member(leaf(1)), None);
    }

    #[test]
    fn declaration_advances_only_the_author_to_the_created_epoch() {
        let mut state = state_with_three_epochs();

        state.apply_declaration(leaf(0), &usage([]), epoch(3), Some(epoch(4)));

        assert_eq!(state.member(leaf(0)).unwrap().watermark(), epoch(4));
        assert_eq!(state.member(leaf(1)).unwrap().watermark(), epoch(1));
    }

    #[test]
    fn declaration_without_a_created_epoch_advances_to_the_input_epoch() {
        let mut state = state_with_three_epochs();

        state.apply_declaration(leaf(0), &usage([]), epoch(3), None);

        assert_eq!(state.member(leaf(0)).unwrap().watermark(), epoch(3));
    }

    #[test]
    fn watermarks_never_move_backwards() {
        let mut state = state_with_three_epochs();

        state.apply_declaration(leaf(0), &usage([]), epoch(3), None);
        state.apply_declaration(leaf(0), &usage([epoch_id(b"epoch-2")]), epoch(2), None);

        assert_eq!(state.member(leaf(0)).unwrap().watermark(), epoch(3));
        assert_eq!(
            state.member(leaf(0)).unwrap().latest_declaration(),
            Some(&BTreeSet::from([epoch_id(b"epoch-2")])),
            "the later declaration still replaces the earlier one"
        );
    }

    #[test]
    fn a_stale_member_pins_the_floor_while_others_advance() {
        let mut state = state_with_three_epochs();

        state.apply_declaration(leaf(0), &usage([]), epoch(3), None);

        assert_eq!(state.watermark_floor(), Some(epoch(1)));
        assert!(state.is_in_baseline_window(&epoch_id(b"epoch-1")));

        state.apply_declaration(leaf(1), &usage([]), epoch(3), None);

        assert_eq!(state.watermark_floor(), Some(epoch(3)));
        assert!(!state.is_in_baseline_window(&epoch_id(b"epoch-1")));
        assert!(state.is_in_baseline_window(&epoch_id(b"epoch-3")));
    }

    #[test]
    fn an_empty_declaration_retires_the_previous_one_and_differs_from_none() {
        let mut state = state_with_three_epochs();
        assert_eq!(state.member(leaf(0)).unwrap().latest_declaration(), None);

        state.apply_declaration(leaf(0), &usage([epoch_id(b"epoch-1")]), epoch(3), None);
        // The other member advances too, so epoch 1 leaves the baseline window
        // and only the declaration keeps it.
        state.apply_declaration(leaf(1), &BTreeSet::new(), epoch(3), None);
        assert_eq!(
            state.member(leaf(0)).unwrap().latest_declaration(),
            Some(&BTreeSet::from([epoch_id(b"epoch-1")]))
        );
        assert!(state
            .blob_protected_epochs()
            .contains(&epoch_id(b"epoch-1")));

        state.apply_declaration(leaf(0), &BTreeSet::new(), epoch(3), None);
        assert_eq!(
            state.member(leaf(0)).unwrap().latest_declaration(),
            Some(&BTreeSet::new()),
            "the empty declaration is stored, not treated as an absent one"
        );
        assert!(
            !state
                .blob_protected_epochs()
                .contains(&epoch_id(b"epoch-1")),
            "the retired declaration stops protecting epoch 1, which is below the floor now"
        );
    }

    #[test]
    fn validation_accepts_each_source_and_rejects_anything_else() {
        let mut state = state_with_three_epochs();
        // Both members advance to the newest epoch, so epoch 1 and 2 leave the
        // baseline window.
        state.apply_declaration(leaf(0), &usage([epoch_id(b"epoch-1")]), epoch(3), None);
        state.apply_declaration(leaf(1), &usage([]), epoch(3), None);
        state.removed_client_usage.insert(epoch_id(b"gone"));
        state.add_app_reference(epoch_id(b"epoch-2"), b"upload".to_vec());

        // Baseline window.
        assert!(state
            .validate_epoch_usage(&usage([epoch_id(b"epoch-3")]))
            .is_ok());
        // Another member's latest declaration.
        assert!(state
            .validate_epoch_usage(&usage([epoch_id(b"epoch-1")]))
            .is_ok());
        // Assumed obligation.
        assert!(state
            .validate_epoch_usage(&usage([epoch_id(b"gone")]))
            .is_ok());

        // An application reference is local, so it justifies nothing.
        assert_eq!(
            state.validate_epoch_usage(&usage([epoch_id(b"epoch-2")])),
            Err(VcRetentionError::UnretainedEpoch(epoch_id(b"epoch-2")))
        );
        // An epoch nobody ever retained.
        assert_eq!(
            state.validate_epoch_usage(&usage([epoch_id(b"unknown")])),
            Err(VcRetentionError::UnretainedEpoch(epoch_id(b"unknown")))
        );
    }

    #[test]
    fn protection_covers_all_four_sources_and_reaping_covers_the_rest() {
        let mut state = state_with_three_epochs();
        state.record_derivation_epoch(epoch(4), epoch_id(b"epoch-4"));
        // Both members move to the newest epoch, so epochs 1 to 3 drop out of
        // the baseline window. One of them stays protected by a declaration.
        state.apply_declaration(leaf(0), &usage([epoch_id(b"epoch-2")]), epoch(4), None);
        state.apply_declaration(leaf(1), &usage([]), epoch(4), None);
        state.removed_client_usage.insert(epoch_id(b"epoch-3"));
        state.add_app_reference(epoch_id(b"epoch-1"), b"pending upload".to_vec());

        assert_eq!(
            state.blob_protected_epochs(),
            BTreeSet::from([
                epoch_id(b"epoch-1"),
                epoch_id(b"epoch-2"),
                epoch_id(b"epoch-3"),
                epoch_id(b"epoch-4"),
            ])
        );
        assert!(state.reapable_epochs().is_empty());

        state.remove_app_reference(&epoch_id(b"epoch-1"), b"pending upload");
        state.removed_client_usage.remove(&epoch_id(b"epoch-3"));

        assert_eq!(
            state.reapable_epochs(),
            vec![epoch_id(b"epoch-1"), epoch_id(b"epoch-3")],
            "reapable epochs come in log order, epoch 2 stays declared below the floor"
        );

        state.remove_retained(&epoch_id(b"epoch-1"));
        assert_eq!(state.epoch_number(&epoch_id(b"epoch-1")), None);
        assert_eq!(state.reapable_epochs(), vec![epoch_id(b"epoch-3")]);
    }

    #[test]
    fn record_derivation_epoch_is_monotonic_and_idempotent() {
        let mut state = state_with_three_epochs();

        // A repeat of the newest entry is a retried merge.
        state.record_derivation_epoch(epoch(3), epoch_id(b"epoch-3"));
        assert_eq!(state.retained_epochs().len(), 3);

        assert_eq!(state.epoch_number(&epoch_id(b"epoch-2")), Some(epoch(2)));
        assert_eq!(
            state.newest_epoch().map(RetainedVcEpoch::epoch_id),
            Some(&epoch_id(b"epoch-3"))
        );
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "increasing emulation-group epoch order")]
    fn record_derivation_epoch_rejects_going_backwards() {
        let mut state = state_with_three_epochs();

        state.record_derivation_epoch(epoch(2), epoch_id(b"late-epoch-2"));
    }

    #[test]
    fn member_rows_come_and_go_with_membership() {
        let mut state = state_with_three_epochs();
        state.apply_declaration(leaf(1), &usage([epoch_id(b"epoch-1")]), epoch(3), None);

        state.member_added(leaf(2), epoch(3));
        assert_eq!(state.member(leaf(2)).unwrap().watermark(), epoch(3));
        assert_eq!(state.member(leaf(2)).unwrap().latest_declaration(), None);
        assert_eq!(state.watermark_floor(), Some(epoch(1)));

        state.member_removed(leaf(0));
        assert_eq!(state.member(leaf(0)), None);
        assert_eq!(state.watermark_floor(), Some(epoch(3)));
        assert!(
            state
                .blob_protected_epochs()
                .contains(&epoch_id(b"epoch-1")),
            "the remaining member still declares epoch 1"
        );

        // A leaf reused after a removal starts fresh.
        state.member_added(leaf(1), epoch(3));
        assert_eq!(state.member(leaf(1)).unwrap().latest_declaration(), None);
        assert!(!state
            .blob_protected_epochs()
            .contains(&epoch_id(b"epoch-1")));
    }

    #[test]
    fn app_references_are_labeled_and_drop_out_when_the_last_label_goes() {
        let mut state = state_with_three_epochs();

        assert!(state.add_app_reference(epoch_id(b"epoch-1"), b"upload".to_vec()));
        assert!(!state.add_app_reference(epoch_id(b"epoch-1"), b"upload".to_vec()));
        assert!(state.add_app_reference(epoch_id(b"epoch-1"), b"backup".to_vec()));

        assert!(!state.remove_app_reference(&epoch_id(b"epoch-2"), b"upload"));
        assert!(!state.remove_app_reference(&epoch_id(b"epoch-1"), b"unknown label"));

        assert!(state.remove_app_reference(&epoch_id(b"epoch-1"), b"upload"));
        assert!(
            state
                .referenced_epochs()
                .any(|epoch| epoch == epoch_id(b"epoch-1")),
            "the second label still holds the epoch"
        );

        assert!(state.remove_app_reference(&epoch_id(b"epoch-1"), b"backup"));
        assert!(
            !state
                .referenced_epochs()
                .any(|epoch| epoch == epoch_id(b"epoch-1")),
            "the epoch is released with its last label"
        );
        assert!(!state.remove_app_reference(&epoch_id(b"epoch-1"), b"backup"));
    }

    #[test]
    fn declared_epochs_covers_obligations_and_app_references() {
        let mut state = state_with_three_epochs();
        assert!(state.declared_epochs().is_empty());

        state.removed_client_usage.insert(epoch_id(b"gone"));
        state.add_app_reference(epoch_id(b"epoch-1"), b"upload".to_vec());
        state.add_app_reference(epoch_id(b"epoch-1"), b"backup".to_vec());

        assert_eq!(
            state.declared_epochs(),
            BTreeSet::from([epoch_id(b"gone"), epoch_id(b"epoch-1")]),
            "the two labels of epoch 1 declare it once"
        );

        state.remove_app_reference(&epoch_id(b"epoch-1"), b"upload");
        assert_eq!(
            state.declared_epochs(),
            BTreeSet::from([epoch_id(b"gone"), epoch_id(b"epoch-1")])
        );
        state.remove_app_reference(&epoch_id(b"epoch-1"), b"backup");
        assert_eq!(state.declared_epochs(), BTreeSet::from([epoch_id(b"gone")]));
    }

    #[test]
    fn epoch_refs_track_each_reference_kind_separately() {
        let mut refs = VcEpochRefs::default();
        let group = GroupId::from_slice(b"higher-level group");
        assert!(refs.is_empty());

        assert!(refs.add_pending_commit(group.clone()));
        assert!(!refs.add_pending_commit(group.clone()));
        assert!(refs.add_binding(group.clone()));
        assert!(refs.add_creation(group.clone()));

        assert!(refs.remove_pending_commit(&group));
        assert!(!refs.remove_pending_commit(&group));
        assert!(!refs.is_empty(), "the binding and the creation remain");

        assert!(refs.remove_binding(&group));
        assert!(refs.remove_creation(&group));
        assert!(refs.is_empty());
    }

    #[test]
    fn creation_tracking_completes_once_every_sibling_was_seen() {
        let mut tracking = VcCreationTracking::new(epoch_id(b"epoch-1"), [leaf(0), leaf(1)]);

        assert_eq!(tracking.epoch_id(), &epoch_id(b"epoch-1"));
        assert!(!tracking.is_complete());

        assert!(tracking.mark_seen(leaf(1)));
        assert!(!tracking.mark_seen(leaf(1)));
        assert_eq!(tracking.outstanding(), &BTreeSet::from([leaf(0)]));

        assert!(tracking.mark_seen(leaf(0)));
        assert!(tracking.is_complete());
    }
}
