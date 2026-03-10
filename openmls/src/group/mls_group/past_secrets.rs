use std::collections::{HashMap, VecDeque};

use crate::schedule::message_secrets::MessageSecrets;

use super::*;

// Internal helper struct
/// A wrapper for all data associated with a `MessageSecrets`
/// NOTE: this struct can be deserialized directly from data
/// that was serialized from a `MessageSecrets`.
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
#[cfg_attr(feature = "crypto-debug", derive(Debug))]
pub(crate) struct MessageSecretsWithTimestamp {
    /// When the secrets were added to the store
    /// `None` if no timestamp is available
    /// NOTE: SystemTime is not guaranteed to be monotonic.
    #[serde(default)]
    added_at: Option<std::time::SystemTime>,
    /// The message secrets
    #[serde(flatten)]
    message_secrets: MessageSecrets,
}

impl MessageSecrets {
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn with_timestamp(
        self,
        timestamp: impl Into<Option<std::time::SystemTime>>,
    ) -> MessageSecretsWithTimestamp {
        MessageSecretsWithTimestamp {
            message_secrets: self,
            added_at: timestamp.into(),
        }
    }
}

impl EpochTree {
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn timestamp(&self) -> Option<std::time::SystemTime> {
        self.message_secrets.added_at
    }
}

// Internal helper struct
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
#[cfg_attr(feature = "crypto-debug", derive(Debug))]
pub(crate) struct EpochTree {
    epoch: u64,
    leaves: Vec<Member>,
    message_secrets: MessageSecretsWithTimestamp,
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
    past_epoch_trees: VecDeque<EpochTree>,
    // The message secrets of the current epoch.
    message_secrets: MessageSecretsWithTimestamp,
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

/// Helper function to map a policy to a maximum number of past epochs
fn max_epochs(policy: &PastEpochDeletionPolicy) -> usize {
    // get the `max_epochs`, or, if no maximum is set, set to `isize::MAX`, the capacity of a
    // VecDeque
    let max_epochs = policy.max_epochs().unwrap_or(isize::MAX as usize);

    // cap at `isize::MAX`
    max_epochs.min(isize::MAX as usize)
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
            message_secrets: MessageSecretsWithTimestamp {
                added_at: Some(std::time::SystemTime::now()),
                message_secrets,
            },
        }
    }

    /// Resize the store.
    pub(crate) fn resize(&mut self, policy: &PastEpochDeletionPolicy) {
        // max or the limit of the storage size
        let max_past_epochs = max_epochs(policy);

        let old_size = self.max_epochs;
        self.max_epochs = max_past_epochs;
        if old_size > max_past_epochs {
            let num_epochs_out = old_size - max_past_epochs;
            self.past_epoch_trees.rotate_left(num_epochs_out);
            self.past_epoch_trees.truncate(max_past_epochs);
        }
    }

    pub(crate) fn replace_current_message_secrets(
        &mut self,
        message_secrets: MessageSecrets,
    ) -> MessageSecretsWithTimestamp {
        let mut message_secrets = MessageSecretsWithTimestamp {
            added_at: Some(std::time::SystemTime::now()),
            message_secrets,
        };
        std::mem::swap(&mut self.message_secrets, &mut message_secrets);

        message_secrets
    }

    /// Add a secret tree for a given epoch `group_epoch`.
    /// Note that this does not take the epoch into account and pops out the
    /// oldest element.
    pub(crate) fn add_past_epoch_tree(
        &mut self,
        group_epoch: impl Into<GroupEpoch>,
        message_secrets: MessageSecretsWithTimestamp,
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

    /// Get a mutable reference to a secret tree for a given epoch `group_epoch`.
    /// If no message secrets are found for that epoch, `None` is returned.
    pub(crate) fn secrets_for_epoch_mut(
        &mut self,
        group_epoch: impl Into<GroupEpoch>,
    ) -> Option<&mut MessageSecrets> {
        let epoch = group_epoch.into().as_u64();
        for epoch_tree in self.past_epoch_trees.iter_mut() {
            if epoch_tree.epoch == epoch {
                return Some(&mut epoch_tree.message_secrets.message_secrets);
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
                return Some(&epoch_tree.message_secrets.message_secrets);
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
                return Some((
                    &epoch_tree.message_secrets.message_secrets,
                    &epoch_tree.leaves,
                ));
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
        &mut self.message_secrets.message_secrets
    }

    /// Get a reference to the message secrets of the current epoch.
    pub(crate) fn message_secrets(&self) -> &MessageSecrets {
        &self.message_secrets.message_secrets
    }

    pub(crate) fn delete_past_epoch_secrets_older_than(
        &mut self,
        duration: std::time::Duration,
        max_past_epochs: Option<usize>,
    ) {
        // retain entries that are older than the duration.
        self.past_epoch_trees.retain(|tree| {
            let Some(added_at) = tree.message_secrets.added_at else {
                // TODO: handle trees with None timestamp
                // TODO: log here
                return true;
            };
            let Ok(elapsed) = std::time::SystemTime::now().duration_since(added_at) else {
                // TODO: handle secrets timestamps in the future
                // TODO: log here
                return true;
            };

            // retain entried where elapsed is less than the provided duration
            elapsed < duration
        });

        // ensure at most `max_past_epochs` entries are included
        if let Some(max_past_epochs) = max_past_epochs {
            if let Some(i) = self.past_epoch_trees.len().checked_sub(max_past_epochs) {
                self.past_epoch_trees.drain(0..i);
            }
        }
    }

    pub(crate) fn delete_past_epoch_secrets_before(
        &mut self,
        cutoff: std::time::SystemTime,
        max_past_epochs: Option<usize>,
    ) {
        // retain entries where added_at is after or equal to the cutoff.
        self.past_epoch_trees.retain(|tree| {
            let Some(added_at) = tree.message_secrets.added_at else {
                // TODO: handle trees with None timestamp
                // TODO: log here
                return true;
            };
            added_at >= cutoff
        });

        // ensure at most `max_past_epochs` entries are included
        if let Some(max_past_epochs) = max_past_epochs {
            if let Some(i) = self.past_epoch_trees.len().checked_sub(max_past_epochs) {
                self.past_epoch_trees.drain(0..i);
            }
        }
    }

    pub(crate) fn delete_past_epoch_secrets(&mut self, min_past_epochs: Option<usize>) {
        // ensure at least `min_past_epochs` entries are included
        if let Some(min_past_epochs) = min_past_epochs {
            if let Some(i) = self.past_epoch_trees.len().checked_sub(min_past_epochs) {
                self.past_epoch_trees.drain(0..i);
            } else {
                // keep all
            }
        } else {
            self.past_epoch_trees.clear();
        }
    }

    #[cfg(test)]
    /// Helper function for testing, to iterate over all past epoch secrets
    pub(crate) fn iter_past_epoch_trees(&self) -> impl Iterator<Item = &EpochTree> {
        self.past_epoch_trees.iter()
    }

    #[cfg(test)]
    /// Helper function for testing, to get the number of past epoch trees
    pub(crate) fn num_past_epoch_trees(&self) -> usize {
        self.past_epoch_trees.len()
    }
}
