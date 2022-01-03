use std::collections::VecDeque;

use crate::schedule::message_secrets::MessageSecrets;

use super::*;

// Internal helper struct
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
struct EpochTree {
    epoch: u64,
    message_secrets: MessageSecrets,
}

/// Can store message secrets for up to `max_epochs`. The trees are added with [`self::add()`] and can be queried
/// with [`Self::get_epoch()`].
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct MessageSecretsStore {
    // Maximum size of the `past_epoch_trees` list.
    max_epochs: usize,
    // Past message secrets.
    past_epoch_trees: VecDeque<EpochTree>,
    // The message secrets of the current epoch.
    message_secrets: MessageSecrets,
}

impl MessageSecretsStore {
    /// Create a new store that can hold up to `max_past_epochs` message secrets.
    /// If `max_past_epochs` is 0, only the current epoch is being stored.
    pub(crate) fn new_with_secret(max_epochs: usize, message_secrets: MessageSecrets) -> Self {
        Self {
            max_epochs,
            past_epoch_trees: VecDeque::new(),
            message_secrets,
        }
    }

    /// Resize the store.
    pub(crate) fn resize(&mut self, max_past_epochs: usize) {
        self.max_epochs = max_past_epochs;
        while self.past_epoch_trees.len() > self.max_epochs {
            self.past_epoch_trees.pop_front();
        }
    }

    /// Add a secret tree for a given epoch `group_epoch`.
    /// Note that this does not take the epoch into account and pops out the
    /// oldest element.
    pub fn add(&mut self, group_epoch: GroupEpoch, message_secrets: MessageSecrets) {
        // Don't store the tree if it's not intended
        if self.max_epochs == 0 {
            return;
        }
        while self.past_epoch_trees.len() >= self.max_epochs {
            self.past_epoch_trees.pop_front();
        }
        self.past_epoch_trees.push_back(EpochTree {
            epoch: group_epoch.0,
            message_secrets,
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
    pub fn secrets_for_epoch_mut(
        &mut self,
        group_epoch: GroupEpoch,
    ) -> Option<&mut MessageSecrets> {
        let GroupEpoch(epoch) = group_epoch;
        for epoch_tree in self.past_epoch_trees.iter_mut() {
            if epoch_tree.epoch == epoch {
                return Some(&mut epoch_tree.message_secrets);
            }
        }
        None
    }

    /// Get a reference to a secret tree for a given epoch `group_epoch`.
    /// If no message secrets are found for that epoch, `None` is returned.
    pub fn secrets_for_epoch(&self, group_epoch: GroupEpoch) -> Option<&MessageSecrets> {
        let GroupEpoch(epoch) = group_epoch;
        for epoch_tree in self.past_epoch_trees.iter() {
            if epoch_tree.epoch == epoch {
                return Some(&epoch_tree.message_secrets);
            }
        }
        None
    }

    /// Get a mutable reference to the message secrets of the current epoch.
    pub(crate) fn message_secrets_mut(&mut self) -> &mut MessageSecrets {
        &mut self.message_secrets
    }

    /// Get a reference to the message secrets of the current epoch.
    pub(crate) fn message_secrets(&self) -> &MessageSecrets {
        &self.message_secrets
    }
}
