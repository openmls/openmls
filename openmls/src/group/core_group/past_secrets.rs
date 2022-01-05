use std::collections::VecDeque;

use crate::schedule::message_secrets::MessageSecrets;

use super::*;

// Internal helper struct
#[derive(Debug, Serialize, Deserialize)]
struct EpochTree {
    epoch: u64,
    message_secrets: MessageSecrets,
}

/// Can store message secrets for up to `max_epochs`. The trees are added with [`self::add()`] and can be queried
/// with [`Self::get_epoch()`].
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MessageSecretsStore {
    max_epochs: usize,
    epoch_trees: VecDeque<EpochTree>,
}

impl MessageSecretsStore {
    /// Create a new store that can hold up to `max_epochs` message secrets.
    /// If `max_epochs` is 0, no secret trees will be stored.
    pub(crate) fn new(max_epochs: usize) -> Self {
        Self {
            max_epochs,
            epoch_trees: VecDeque::new(),
        }
    }

    /// Add a secret tree for a given epoch `group_epoch`.
    pub(crate) fn add(&mut self, group_epoch: GroupEpoch, message_secrets: MessageSecrets) {
        // Don't store the tree if it's not intended
        if self.max_epochs == 0 {
            return;
        }
        let GroupEpoch(epoch) = group_epoch;
        let epoch_tree = EpochTree {
            epoch,
            message_secrets,
        };
        while self.epoch_trees.len() >= self.max_epochs {
            self.epoch_trees.pop_front();
        }
        self.epoch_trees.push_back(epoch_tree);
    }

    /// Get a mutable reference to a secret tree for a given epoch `group_epoch`.
    /// If no message secrets are found for that epoch, `None` is returned.
    pub(crate) fn secrets_for_epoch(
        &mut self,
        group_epoch: GroupEpoch,
    ) -> Option<&mut MessageSecrets> {
        let GroupEpoch(epoch) = group_epoch;
        for epoch_tree in self.epoch_trees.iter_mut() {
            if epoch_tree.epoch == epoch {
                return Some(&mut epoch_tree.message_secrets);
            }
        }
        None
    }
}
