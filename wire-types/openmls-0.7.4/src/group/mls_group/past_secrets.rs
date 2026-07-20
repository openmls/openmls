use std::collections::VecDeque;

use crate::schedule::message_secrets::MessageSecrets;

use super::*;

// Internal helper struct
#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "crypto-debug", derive(Debug))]
struct EpochTree {
    epoch: u64,
    message_secrets: MessageSecrets,
    leaves: Vec<Member>,
}

/// Can store message secrets for up to `max_epochs`. The trees are added with [`self::add()`] and can be queried
/// with [`Self::get_epoch()`].
#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "crypto-debug", derive(Debug))]
pub(crate) struct MessageSecretsStore {
    // Maximum size of the `past_epoch_trees` list.
    pub(crate) max_epochs: usize,
    // Past message secrets.
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
