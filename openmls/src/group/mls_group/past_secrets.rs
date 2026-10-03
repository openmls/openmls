use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};

#[cfg(not(target_arch = "wasm32"))]
use std::time::SystemTime;
#[cfg(target_arch = "wasm32")]
use web_time::SystemTime;

use crate::schedule::message_secrets::MessageSecrets;

use super::*;

impl EpochTree {
    #[cfg(all(test, feature = "sqlite-provider", feature = "libcrux-provider"))]
    pub(crate) fn timestamp(&self) -> Option<SystemTime> {
        self.message_secrets.timestamp()
    }
}

// Internal helper struct
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
#[cfg_attr(feature = "crypto-debug", derive(Debug))]
pub(crate) struct EpochTree {
    epoch: u64,
    message_secrets: MessageSecrets,
    leaves: Vec<Member>,
}

/// Can store message secrets for up to `max_epochs`. The trees are added with [`self::add()`] and can be queried
/// with [`Self::get_epoch()`].
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
#[cfg_attr(feature = "crypto-debug", derive(Debug))]
pub(crate) struct MessageSecretsStore {
    // Maximum size of the `past_epoch_trees` list.
    pub(crate) max_epochs: usize,
    // Past message secrets.
    // NOTE: these are in order of addition (latest at end). Restored on
    // deserialization, since `resize` used to persist them rotated.
    #[serde(deserialize_with = "epoch_trees_oldest_first")]
    past_epoch_trees: VecDeque<EpochTree>,
    // The message secrets of the current epoch.
    message_secrets: MessageSecrets,
}

#[cfg(not(feature = "crypto-debug"))]
impl core::fmt::Debug for MessageSecretsStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageSecretsStore")
            .field("max_epochs", &"***")
            .field("past_epoch_trees", &"***")
            .field("message_secrets", &"***")
            .finish()
    }
}

/// Sorts the past epoch trees, which `resize` used to persist rotated.
fn epoch_trees_oldest_first<'de, D>(deserializer: D) -> Result<VecDeque<EpochTree>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let mut trees = VecDeque::<EpochTree>::deserialize(deserializer)?;
    trees.make_contiguous().sort_by_key(|tree| tree.epoch);
    Ok(trees)
}

const VECDEQUE_MAX_CAPACITY: usize = isize::MAX as usize;

// XXX: the VecDeque capacity is not checked elsewhere in this module.
/// Helper function to map a policy to a maximum number of past epochs
fn max_epochs(policy: &PastEpochDeletionPolicy) -> usize {
    // get the `max_epochs`, or the maximum capacity of a `VecDeque`
    let max_epochs = policy.max_epochs().unwrap_or(VECDEQUE_MAX_CAPACITY);

    // cap at max capacity
    max_epochs.min(VECDEQUE_MAX_CAPACITY)
}

impl MessageSecretsStore {
    /// Create a new store that can hold up to `max_past_epochs` message secrets.
    /// If `max_past_epochs` is 0, only the current epoch is being stored.
    pub(crate) fn new_with_secret(
        policy: &PastEpochDeletionPolicy,
        message_secrets: MessageSecrets,
    ) -> Self {
        // max or the limit of the storage size
        let max_epochs = max_epochs(policy);

        Self {
            max_epochs,
            past_epoch_trees: VecDeque::new(),
            message_secrets: message_secrets.with_timestamp(SystemTime::now()),
        }
    }

    /// Resize the store.
    pub(crate) fn resize(&mut self, policy: &PastEpochDeletionPolicy) {
        // max or the limit of the storage size
        let max_past_epochs = max_epochs(policy);

        self.max_epochs = max_past_epochs;

        let excess = self.past_epoch_trees.len().saturating_sub(max_past_epochs);
        self.past_epoch_trees.drain(0..excess);
    }

    /// Set the `message_secrets` to a provided `MessageSecrets`, and return
    /// the previous one.
    pub(crate) fn replace_current_message_secrets(
        &mut self,
        message_secrets: MessageSecrets,
    ) -> MessageSecrets {
        let mut message_secrets = message_secrets.with_timestamp(SystemTime::now());
        std::mem::swap(&mut self.message_secrets, &mut message_secrets);

        message_secrets
    }

    /// Add a secret tree for a given epoch `group_epoch`.
    /// Note that this does not take the epoch into account and pops out the
    /// oldest element.
    pub(crate) fn add_past_epoch_tree(
        &mut self,
        group_epoch: impl Into<GroupEpoch>,
        message_secrets: MessageSecrets,
        leaves: Vec<Member>,
    ) {
        // Don't store the tree if it's not intended
        if self.max_epochs == 0 {
            return;
        }
        if self.past_epoch_trees.len() >= self.max_epochs {
            self.past_epoch_trees.rotate_left(1);
            self.past_epoch_trees.truncate(self.max_epochs - 1);
        }

        self.past_epoch_trees.push_back(EpochTree {
            epoch: group_epoch.into().as_u64(),
            message_secrets,
            leaves,
        });
        debug_assert!(
            self.max_epochs >= self.past_epoch_trees.len(),
            "Only {} past secrets must be stored but we found {}",
            self.max_epochs,
            self.past_epoch_trees.len()
        );
    }

    /// Seeds this (freshly created) store's past epochs from `past_store`,
    /// the store of a previous incarnation of the same group, when a client
    /// rejoins the group via an external commit.
    ///
    /// `past_epoch` is the epoch of `past_store`'s current message secrets
    /// and `past_leaves` are the members of the group at that epoch; together
    /// they are folded in as one more past epoch. `rejoin_epoch` is the epoch
    /// the external commit creates. `past_context_matches` says whether the
    /// past state's group context equals the group context the external
    /// commit is built against; the caller compares the two.
    ///
    /// Only secrets for epochs before the epoch the external commit was
    /// built against (`rejoin_epoch - 1`) are carried over as past epochs,
    /// and only if they fall within this store's own retention window
    /// measured against `rejoin_epoch`, i.e. the window a member that had
    /// stayed caught up would have. Secrets for the pre-rejoin epoch itself
    /// instead replace this store's current message secrets, which until
    /// then are placeholder secrets derived from an all-zero epoch secret
    /// that cannot decrypt anything (see #767): from the past state's
    /// current message secrets if it is exactly at the pre-rejoin epoch with
    /// a matching group context, or from its retained tree for that epoch if
    /// it had moved beyond the group state the external commit is built
    /// against (e.g. because the `GroupInfo` was stale). Merging the
    /// external commit then retains the pre-rejoin epoch like any other past
    /// epoch, bounded by this store's policy.
    pub(crate) fn inherit_past_epochs(
        &mut self,
        past_store: MessageSecretsStore,
        past_epoch: impl Into<GroupEpoch>,
        past_leaves: Vec<Member>,
        rejoin_epoch: impl Into<GroupEpoch>,
        past_context_matches: bool,
    ) {
        debug_assert!(
            self.past_epoch_trees.is_empty(),
            "past epochs must be inherited into a freshly created store"
        );
        let past_epoch = past_epoch.into().as_u64();
        let rejoin_epoch = rejoin_epoch.into().as_u64();
        // The epoch of the group state the external commit was built against.
        // An external commit always advances the epoch, so `rejoin_epoch` is
        // at least 1; returning without inheriting anything is safe either
        // way.
        let Some(pre_rejoin_epoch) = rejoin_epoch.checked_sub(1) else {
            return;
        };

        let MessageSecretsStore {
            mut past_epoch_trees,
            message_secrets,
            // The retention window is this store's, not the past store's.
            max_epochs: _,
        } = past_store;

        match past_epoch.cmp(&pre_rejoin_epoch) {
            // The past state had fallen behind the group; its current
            // secrets become one more past epoch.
            Ordering::Less => past_epoch_trees.push_back(EpochTree {
                epoch: past_epoch,
                message_secrets,
                leaves: past_leaves,
            }),
            // The past state is exactly at the epoch the external commit was
            // built against, so its current secrets are the real message
            // secrets for the epoch this store carries placeholder secrets
            // for — unless the group contexts differ, in which case the past
            // state sits on a fork and its secrets for this epoch cannot
            // decrypt anything sealed on this branch.
            Ordering::Equal => {
                if past_context_matches {
                    self.message_secrets = message_secrets;
                }
            }
            // The past state had moved beyond the group state the external
            // commit was built against (e.g. because the `GroupInfo` was
            // stale). Its current secrets are of no use on this branch, but
            // its retained tree for the pre-rejoin epoch — if it still holds
            // one — takes the placeholder's place. Leaving that tree in the
            // deque instead would collide with the entry the merge pushes
            // for the same epoch.
            Ordering::Greater => {
                if let Some(position) = past_epoch_trees
                    .iter()
                    .position(|tree| tree.epoch == pre_rejoin_epoch)
                {
                    if let Some(tree) = past_epoch_trees.remove(position) {
                        self.message_secrets = tree.message_secrets;
                    }
                }
            }
        }

        // Keep only epochs within this store's retention window relative to
        // the epoch the rejoining member ends up in. The pre-rejoin epoch is
        // excluded: it lives in the current message secrets now and is
        // pushed by the merge, so an entry for it here would be a duplicate.
        past_epoch_trees.retain(|tree| {
            tree.epoch < pre_rejoin_epoch
                && tree.epoch.saturating_add(self.max_epochs as u64) >= rejoin_epoch
        });

        // Defense in depth: a well-formed past store cannot exceed this
        // store's capacity after the filter above, but if it does, drop the
        // oldest entries, as the store itself does when an epoch is added at
        // capacity.
        if past_epoch_trees.len() > self.max_epochs {
            let excess = past_epoch_trees.len() - self.max_epochs;
            past_epoch_trees.drain(0..excess);
        }
        self.past_epoch_trees = past_epoch_trees;
    }

    /// Get a mutable reference to a secret tree for a given epoch `group_epoch`.
    /// If no message secrets are found for that epoch, `None` is returned.
    pub(crate) fn secrets_for_epoch_mut(
        &mut self,
        group_epoch: impl Into<GroupEpoch>,
    ) -> Option<&mut MessageSecrets> {
        let epoch = group_epoch.into().as_u64();
        for epoch_tree in self.past_epoch_trees.iter_mut() {
            if epoch_tree.epoch == epoch {
                return Some(&mut epoch_tree.message_secrets);
            }
        }
        None
    }

    /// Get a reference to a secret tree for a given epoch `group_epoch`.
    /// If no message secrets are found for that epoch, `None` is returned.
    pub(crate) fn secrets_for_epoch(
        &self,
        group_epoch: impl Into<GroupEpoch>,
    ) -> Option<&MessageSecrets> {
        let epoch = group_epoch.into().as_u64();
        for epoch_tree in self.past_epoch_trees.iter() {
            if epoch_tree.epoch == epoch {
                return Some(&epoch_tree.message_secrets);
            }
        }
        None
    }

    /// Get a mutable reference to a secret tree for a given epoch `group_epoch`.
    /// Return a mutable reference to the [`MessageSecrets`] and a slice to the
    /// [`Member`]s of the epoch.
    pub(crate) fn secrets_and_leaves_for_epoch(
        &self,
        group_epoch: impl Into<GroupEpoch>,
    ) -> Option<(&MessageSecrets, &[Member])> {
        let epoch = group_epoch.into().as_u64();
        for epoch_tree in self.past_epoch_trees.iter() {
            if epoch_tree.epoch == epoch {
                return Some((&epoch_tree.message_secrets, &epoch_tree.leaves));
            }
        }
        None
    }

    /// Returns a `HashMap` that maps a `LeafNodeIndex` to the correct
    /// [`Member`] in the given `group_epoch`.
    pub(crate) fn leaves_for_epoch(
        &self,
        group_epoch: impl Into<GroupEpoch>,
    ) -> HashMap<LeafNodeIndex, &Member> {
        let epoch = group_epoch.into().as_u64();
        for epoch_tree in self.past_epoch_trees.iter() {
            if epoch_tree.epoch == epoch {
                return epoch_tree
                    .leaves
                    .iter()
                    .map(|m| (m.index, m))
                    .collect::<HashMap<LeafNodeIndex, &Member>>();
            }
        }
        HashMap::new()
    }

    /// Check if the provided epoch contains a leaf index.
    pub(crate) fn epoch_has_leaf(
        &self,
        group_epoch: GroupEpoch,
        leaf_index: LeafNodeIndex,
    ) -> bool {
        self.past_epoch_trees.iter().any(|t| {
            t.epoch == group_epoch.0
                && t.leaves
                    .iter()
                    .any(|Member { index, .. }| *index == leaf_index)
        })
    }

    /// Get a mutable reference to the message secrets of the current epoch.
    pub(crate) fn message_secrets_mut(&mut self) -> &mut MessageSecrets {
        &mut self.message_secrets
    }

    /// Get a reference to the message secrets of the current epoch.
    pub(crate) fn message_secrets(&self) -> &MessageSecrets {
        &self.message_secrets
    }

    fn delete_past_epoch_secrets_older_than_duration(&mut self, duration: std::time::Duration) {
        // first, compare to the timestamp of the current message secrets
        if let Some(added_at) = self.message_secrets.timestamp() {
            if let Ok(elapsed) = SystemTime::now().duration_since(added_at) {
                if elapsed > duration {
                    // delete all
                    self.past_epoch_trees.clear();
                    return;
                }
            }
        }

        // find the first past epoch tree with a timestamp past the duration
        let found = self
            .past_epoch_trees
            .iter()
            .enumerate()
            .rev()
            .find(|(_idx, tree)| {
                let Some(added_at) = tree.message_secrets.timestamp() else {
                    return false;
                };

                let Ok(elapsed) = SystemTime::now().duration_since(added_at) else {
                    return false;
                };

                elapsed > duration
            })
            .map(|(idx, _tree)| idx);

        if let Some(found_idx) = found {
            // delete all before and including the index
            self.past_epoch_trees.drain(0..found_idx + 1);
        } else {

            // keep all
        }
    }

    fn delete_past_epoch_secrets_before_timestamp(&mut self, cutoff: SystemTime) {
        // first, compare to timestamp of the current message secrets
        if let Some(added_at) = self.message_secrets.timestamp() {
            if added_at < cutoff {
                // delete all
                self.past_epoch_trees.clear();
                return;
            }
        }

        // find the first past epoch tree with an earlier non-None timestamp
        let found = self
            .past_epoch_trees
            .iter()
            .enumerate()
            .rev()
            .find(|(_idx, tree)| {
                let Some(added_at) = tree.message_secrets.timestamp() else {
                    return false;
                };

                added_at < cutoff
            })
            .map(|(idx, _tree)| idx);

        if let Some(found_idx) = found {
            // delete all before and including the index
            self.past_epoch_trees.drain(0..found_idx + 1);
        } else {
            // keep all
        }
    }

    pub(crate) fn delete_past_epoch_secrets(&mut self, policy: PastEpochDeletion) {
        // handle different types of past epoch deletion
        if let Some(config) = policy.config {
            match config {
                PastEpochDeletionTimeConfig::DeleteAllWithoutTimestamp => {
                    self.past_epoch_trees
                        .retain(|tree| tree.message_secrets.timestamp().is_some());
                }
                PastEpochDeletionTimeConfig::BeforeTimestamp(timestamp) => {
                    self.delete_past_epoch_secrets_before_timestamp(timestamp)
                }
                PastEpochDeletionTimeConfig::OlderThanDuration(duration) => {
                    self.delete_past_epoch_secrets_older_than_duration(duration)
                }
            };
            // ensure at most `max_past_epochs` entries are included
            if let Some(max_past_epochs) = policy.max_past_epochs {
                if let Some(i) = self.past_epoch_trees.len().checked_sub(max_past_epochs) {
                    self.past_epoch_trees.drain(0..i);
                }
            }
        } else {
            // delete all
            self.past_epoch_trees.clear();
        }
    }

    #[cfg(all(test, feature = "sqlite-provider", feature = "libcrux-provider"))]
    /// Helper function for testing, to iterate over all past epoch secrets
    pub(crate) fn iter_past_epoch_trees(&self) -> impl Iterator<Item = &EpochTree> {
        self.past_epoch_trees.iter()
    }

    #[cfg(test)]
    /// Helper function for testing, to get the number of past epoch trees
    pub(crate) fn num_past_epoch_trees(&self) -> usize {
        self.past_epoch_trees.len()
    }

    #[cfg(test)]
    /// Helper function for testing, to get the stored epochs in queue order
    pub(crate) fn past_epochs(&self) -> Vec<u64> {
        self.past_epoch_trees
            .iter()
            .map(|tree| tree.epoch)
            .collect()
    }

    #[cfg(test)]
    /// Helper function for testing, `resize` as it was before the fix
    pub(crate) fn resize_as_before_the_fix(&mut self, policy: &PastEpochDeletionPolicy) {
        let max_past_epochs = max_epochs(policy);

        let old_size = self.max_epochs;
        self.max_epochs = max_past_epochs;
        if old_size > max_past_epochs {
            let num_epochs_out = old_size - max_past_epochs;
            self.past_epoch_trees
                .rotate_left(num_epochs_out.min(self.past_epoch_trees.len()));
            self.past_epoch_trees.truncate(max_past_epochs);
        }
    }
}
