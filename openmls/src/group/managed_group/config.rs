use super::*;

use serde::{Deserialize, Serialize};

/// Specifies the configuration parameters for a managed group
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedGroupConfig {
    /// Defines whether handshake messages (Proposals & Commits) are encrypted.
    /// Application are always encrypted regardless. `Plaintext`: Handshake messages
    /// are returned as MlsPlaintext messages `Ciphertext`: Handshake messages are
    /// returned as MlsCiphertext messages
    pub(crate) handshake_message_format: WireFormat,
    /// Defines the update policy
    pub(crate) update_policy: UpdatePolicy,
    /// Size of padding in bytes
    pub(crate) padding_size: usize,
    /// Number of resumtion secrets to keep
    pub(crate) number_of_resumption_secrets: usize,
    /// Flag to indicate the Ratchet Tree Extension should be used
    pub(crate) use_ratchet_tree_extension: bool,
    /// Callbacks
    #[serde(skip)]
    pub(crate) callbacks: ManagedGroupCallbacks,
}

impl ManagedGroupConfig {
    pub fn new(
        handshake_message_format: WireFormat,
        update_policy: UpdatePolicy,
        padding_size: usize,
        number_of_resumption_secrets: usize,
        use_ratchet_tree_extension: bool,
        callbacks: ManagedGroupCallbacks,
    ) -> Self {
        ManagedGroupConfig {
            handshake_message_format,
            update_policy,
            padding_size,
            number_of_resumption_secrets,
            use_ratchet_tree_extension,
            callbacks,
        }
    }
    pub fn padding_size(&self) -> usize {
        self.padding_size
    }
    pub fn callbacks(&self) -> &ManagedGroupCallbacks {
        &self.callbacks
    }
    pub(crate) fn set_callbacks(&mut self, callbacks: &ManagedGroupCallbacks) {
        self.callbacks = *callbacks;
    }

    #[cfg(test)]
    pub fn test_default() -> Self {
        let handshake_message_format = WireFormat::MlsPlaintext;
        let update_policy = UpdatePolicy::default();
        let callbacks = ManagedGroupCallbacks::default();
        Self::new(
            handshake_message_format,
            update_policy,
            0,
            0,
            true,
            callbacks,
        )
    }
}

/// Specifies in which intervals the own leaf node should be updated
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdatePolicy {
    /// Maximum time before an update in seconds
    pub(crate) maximum_time: u32,
    /// Maximum messages that are sent before an update in seconds
    pub(crate) maximum_sent_messages: u32,
    /// Maximum messages that are received before an update in seconds
    pub(crate) maximum_received_messages: u32,
}

impl Default for UpdatePolicy {
    fn default() -> Self {
        UpdatePolicy {
            maximum_time: 2_592_000, // 30 days in seconds
            maximum_sent_messages: 100,
            maximum_received_messages: 1_000,
        }
    }
}
