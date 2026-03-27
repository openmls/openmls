use std::collections::{HashMap, VecDeque};

use crate::schedule::message_secrets::MessageSecrets;

use super::*;

/// A slimmed-down version of [`Member`] for past epoch storage.
/// Only contains fields needed for past-epoch message verification:
/// `credential` and `signature_key` (for signature verification) and `index`
/// (for sender lookup). The `encryption_key` is not needed for past epochs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PastEpochMember {
    pub index: LeafNodeIndex,
    pub credential: Credential,
    pub signature_key: Vec<u8>,
}

impl From<Member> for PastEpochMember {
    fn from(member: Member) -> Self {
        Self {
            index: member.index,
            credential: member.credential,
            signature_key: member.signature_key,
        }
    }
}

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
    #[cfg(test)]
    pub(crate) fn with_timestamp(
        self,
        timestamp: impl Into<Option<std::time::SystemTime>>,
    ) -> MessageSecretsWithTimestamp {
        MessageSecretsWithTimestamp {
            message_secrets: self,
            added_at: timestamp.into(),
        }
    }

    /// Helper function to create a `MessageSecrets` with `None` timestamp
    #[cfg(test)]
    pub(crate) fn without_timestamp(self) -> MessageSecretsWithTimestamp {
        MessageSecretsWithTimestamp {
            message_secrets: self,
            added_at: None,
        }
    }
}

impl EpochTree {
    #[cfg(test)]
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
    leaves: Vec<PastEpochMember>,
    message_secrets: MessageSecretsWithTimestamp,
}

/// Can store message secrets for up to `max_epochs`. The trees are added with
/// [`self::add()`] and can be queried with [`Self::get_epoch()`].
///
/// Serialization uses a deduplicated member pool: members shared across epochs
/// are stored once in `member_pool`, and each epoch references them by index.
/// Deserialization accepts both the new pooled format and the legacy format
/// (where each epoch has inline `leaves`).
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
#[cfg_attr(feature = "crypto-debug", derive(Debug))]
pub(crate) struct MessageSecretsStore {
    // Maximum size of the `past_epoch_trees` list.
    pub(crate) max_epochs: usize,
    // Past message secrets.
    // NOTE: these are in order of addition (latest at end).
    past_epoch_trees: VecDeque<EpochTree>,
    // The message secrets of the current epoch.
    message_secrets: MessageSecretsWithTimestamp,
}

/// Serialization helper: epoch tree with pool indices instead of inline members.
#[derive(Serialize)]
struct CompactEpochTreeRef<'a> {
    epoch: u64,
    leaf_indices: Vec<u32>,
    message_secrets: &'a MessageSecretsWithTimestamp,
}

/// Deserialization helper for the pooled format.
#[derive(Deserialize)]
struct CompactEpochTree {
    epoch: u64,
    leaf_indices: Vec<u32>,
    message_secrets: MessageSecretsWithTimestamp,
}

/// Serialization format with deduplicated member pool.
#[derive(Serialize)]
struct PooledStoreRef<'a> {
    max_epochs: usize,
    member_pool: Vec<PastEpochMember>,
    past_epoch_trees: VecDeque<CompactEpochTreeRef<'a>>,
    message_secrets: &'a MessageSecretsWithTimestamp,
}

/// Deserialization format with deduplicated member pool.
#[derive(Deserialize)]
struct PooledStore {
    max_epochs: usize,
    member_pool: Vec<PastEpochMember>,
    past_epoch_trees: VecDeque<CompactEpochTree>,
    message_secrets: MessageSecretsWithTimestamp,
}

/// Legacy serialization format with inline members per epoch.
#[derive(Deserialize)]
struct LegacyStore {
    max_epochs: usize,
    past_epoch_trees: VecDeque<EpochTree>,
    message_secrets: MessageSecretsWithTimestamp,
}

impl Serialize for MessageSecretsStore {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Build deduplicated member pool
        let mut pool: Vec<PastEpochMember> = Vec::new();
        let mut compact_trees: VecDeque<CompactEpochTreeRef<'_>> =
            VecDeque::with_capacity(self.past_epoch_trees.len());

        for tree in &self.past_epoch_trees {
            let mut leaf_indices = Vec::with_capacity(tree.leaves.len());
            for member in &tree.leaves {
                let idx = pool.iter().position(|m| m == member).unwrap_or_else(|| {
                    pool.push(member.clone());
                    pool.len() - 1
                });
                leaf_indices.push(idx as u32);
            }
            compact_trees.push_back(CompactEpochTreeRef {
                epoch: tree.epoch,
                leaf_indices,
                message_secrets: &tree.message_secrets,
            });
        }

        PooledStoreRef {
            max_epochs: self.max_epochs,
            member_pool: pool,
            past_epoch_trees: compact_trees,
            message_secrets: &self.message_secrets,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MessageSecretsStore {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Format {
            Pooled(PooledStore),
            Legacy(LegacyStore),
        }

        match Format::deserialize(deserializer)? {
            Format::Pooled(pooled) => {
                let mut past_epoch_trees = VecDeque::with_capacity(pooled.past_epoch_trees.len());
                for compact in pooled.past_epoch_trees {
                    let leaves: Vec<PastEpochMember> = compact
                        .leaf_indices
                        .iter()
                        .map(|&idx| {
                            pooled
                                .member_pool
                                .get(idx as usize)
                                .cloned()
                                .ok_or_else(|| {
                                    serde::de::Error::custom(format!(
                                        "member pool index {idx} out of bounds (pool size: {})",
                                        pooled.member_pool.len()
                                    ))
                                })
                        })
                        .collect::<Result<_, _>>()?;
                    past_epoch_trees.push_back(EpochTree {
                        epoch: compact.epoch,
                        leaves,
                        message_secrets: compact.message_secrets,
                    });
                }
                Ok(MessageSecretsStore {
                    max_epochs: pooled.max_epochs,
                    past_epoch_trees,
                    message_secrets: pooled.message_secrets,
                })
            }
            Format::Legacy(legacy) => Ok(MessageSecretsStore {
                max_epochs: legacy.max_epochs,
                past_epoch_trees: legacy.past_epoch_trees,
                message_secrets: legacy.message_secrets,
            }),
        }
    }
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
            self.past_epoch_trees
                .rotate_left(num_epochs_out.min(self.past_epoch_trees.len()));
            self.past_epoch_trees.truncate(max_past_epochs);
        }
    }

    /// Set the `message_secrets` to a provided `MessageSecrets`, and return
    /// the previous one.
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
        leaves: Vec<PastEpochMember>,
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
    ) -> Option<(&MessageSecrets, &[PastEpochMember])> {
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
    ) -> HashMap<LeafNodeIndex, &PastEpochMember> {
        let epoch = group_epoch.into().as_u64();
        for epoch_tree in self.past_epoch_trees.iter() {
            if epoch_tree.epoch == epoch {
                return epoch_tree
                    .leaves
                    .iter()
                    .map(|m| (m.index, m))
                    .collect::<HashMap<LeafNodeIndex, &PastEpochMember>>();
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
                    .any(|PastEpochMember { index, .. }| *index == leaf_index)
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

    fn delete_past_epoch_secrets_older_than_duration(&mut self, duration: std::time::Duration) {
        // first, compare to the timestamp of the current message secrets
        if let Some(added_at) = self.message_secrets.added_at {
            if let Ok(elapsed) = std::time::SystemTime::now().duration_since(added_at) {
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
                let Some(added_at) = tree.message_secrets.added_at else {
                    return false;
                };

                let Ok(elapsed) = std::time::SystemTime::now().duration_since(added_at) else {
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

    fn delete_past_epoch_secrets_before_timestamp(&mut self, cutoff: std::time::SystemTime) {
        // first, compare to timestamp of the current message secrets
        if let Some(added_at) = self.message_secrets.added_at {
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
                let Some(added_at) = tree.message_secrets.added_at else {
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
                        .retain(|tree| tree.message_secrets.added_at.is_some());
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
