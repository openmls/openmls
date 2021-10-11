use super::*;

use serde::{Deserialize, Serialize};

/// Specifies the configuration parameters for a managed group
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedGroupConfig {
    /// Defines whether handshake messages (Proposals & Commits) are encrypted.
    /// Application are always encrypted regardless. `Plaintext`: Handshake messages
    /// are returned as MlsPlaintext messages `Ciphertext`: Handshake messages are
    /// returned as MlsCiphertext messages
    pub(crate) wire_format: WireFormat,
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
    /// Creates a new ManagedGroupConfig with default values.
    /// Use the `with_*()` builder functions to set different values for
    /// the properties.
    pub fn new() -> Self {
        ManagedGroupConfig {
            wire_format: WireFormat::MlsCiphertext,
            update_policy: UpdatePolicy::default(),
            padding_size: 0,
            number_of_resumption_secrets: 0,
            use_ratchet_tree_extension: false,
            callbacks: ManagedGroupCallbacks::default(),
        }
    }
    /// Sets the `wire_format` property of the ManagedGroupConfig.
    pub fn with_wire_format(mut self, wire_format: WireFormat) -> Self {
        self.wire_format = wire_format;
        self
    }
    /// Sets the `update_policy` property of the ManagedGroupConfig.
    pub fn with_update_policy(mut self, update_policy: UpdatePolicy) -> Self {
        self.update_policy = update_policy;
        self
    }
    /// Sets the `padding_size` property of the ManagedGroupConfig.
    pub fn with_padding_size(mut self, padding_size: usize) -> Self {
        self.padding_size = padding_size;
        self
    }
    /// Sets the `number_of_resumption_secrets` property of the ManagedGroupConfig.
    pub fn with_number_of_resumtion_secrets(mut self, number_of_resumption_secrets: usize) -> Self {
        self.number_of_resumption_secrets = number_of_resumption_secrets;
        self
    }
    /// Sets the `use_ratchet_tree_extension` property of the ManagedGroupConfig.
    pub fn with_use_ratchet_tree_extension(mut self, use_ratchet_tree_extension: bool) -> Self {
        self.use_ratchet_tree_extension = use_ratchet_tree_extension;
        self
    }
    /// Sets the `callbacks` property of the ManagedGroupConfig.
    pub fn with_callbacks(mut self, callbacks: ManagedGroupCallbacks) -> Self {
        self.callbacks = callbacks;
        self
    }

    #[cfg(test)]
    pub fn test_default() -> Self {
        Self::new().with_wire_format(WireFormat::MlsPlaintext)
    }

    /// Gets the [`ManagedGroupConfig`] wire format.
    pub fn wire_format(&self) -> WireFormat {
        self.wire_format
    }

    /// Get a reference to the [`ManagedGroupConfig`] padding size.
    pub fn padding_size(&self) -> usize {
        self.padding_size
    }

    /// Get a reference to the [`ManagedGroupConfig`] update policy.
    pub fn update_policy(&self) -> &UpdatePolicy {
        &self.update_policy
    }

    /// Get a reference to the [`ManagedGroupConfig`] number of resumption secrets.
    pub fn number_of_resumption_secrets(&self) -> &usize {
        &self.number_of_resumption_secrets
    }

    /// Get a reference to the [`ManagedGroupConfig`] use ratchet tree extension.
    pub fn use_ratchet_tree_extension(&self) -> &bool {
        &self.use_ratchet_tree_extension
    }

    /// Get a reference to the [`ManagedGroupConfig`] use rcallbacks.
    pub fn callbacks(&self) -> &ManagedGroupCallbacks {
        &self.callbacks
    }
}

impl Default for ManagedGroupConfig {
    fn default() -> Self {
        Self::new()
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
