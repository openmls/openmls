use super::*;

use serde::{Deserialize, Serialize};

/// Specifies the configuration parameters for a [`ManagedGroup`]
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
}

impl ManagedGroupConfig {
    /// Returns a builder for [`ManagedGroupConfig`]
    pub fn builder() -> ManagedGroupConfigBuilder {
        ManagedGroupConfigBuilder::new()
    }

    /// Get the [`ManagedGroupConfig`] wire format.
    pub fn wire_format(&self) -> WireFormat {
        self.wire_format
    }

    /// Get the [`ManagedGroupConfig`] padding size.
    pub fn padding_size(&self) -> usize {
        self.padding_size
    }

    /// Get a reference to the [`ManagedGroupConfig`] update policy.
    pub fn update_policy(&self) -> &UpdatePolicy {
        &self.update_policy
    }

    /// Get the [`ManagedGroupConfig`] number of resumption secrets.
    pub fn number_of_resumption_secrets(&self) -> usize {
        self.number_of_resumption_secrets
    }

    /// Get the [`ManagedGroupConfig`] boolean flag that indicates whether ratchet_tree_extension should be used.
    pub fn use_ratchet_tree_extension(&self) -> bool {
        self.use_ratchet_tree_extension
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn test_default() -> Self {
        Self::builder()
            .wire_format(WireFormat::MlsPlaintext)
            .build()
    }
}

impl Default for ManagedGroupConfig {
    fn default() -> Self {
        ManagedGroupConfig {
            wire_format: WireFormat::MlsCiphertext,
            update_policy: UpdatePolicy::default(),
            padding_size: 0,
            number_of_resumption_secrets: 0,
            use_ratchet_tree_extension: false,
        }
    }
}

#[derive(Default)]
pub struct ManagedGroupConfigBuilder {
    config: ManagedGroupConfig,
}
impl ManagedGroupConfigBuilder {
    pub fn new() -> Self {
        ManagedGroupConfigBuilder {
            config: ManagedGroupConfig::default(),
        }
    }

    /// Sets the `wire_format` property of the ManagedGroupConfig.
    pub fn wire_format(mut self, wire_format: WireFormat) -> Self {
        self.config.wire_format = wire_format;
        self
    }

    /// Sets the `update_policy` property of the ManagedGroupConfig.
    pub fn update_policy(mut self, update_policy: UpdatePolicy) -> Self {
        self.config.update_policy = update_policy;
        self
    }

    /// Sets the `padding_size` property of the ManagedGroupConfig.
    pub fn padding_size(mut self, padding_size: usize) -> Self {
        self.config.padding_size = padding_size;
        self
    }

    /// Sets the `number_of_resumption_secrets` property of the ManagedGroupConfig.
    pub fn number_of_resumtion_secrets(mut self, number_of_resumption_secrets: usize) -> Self {
        self.config.number_of_resumption_secrets = number_of_resumption_secrets;
        self
    }

    /// Sets the `use_ratchet_tree_extension` property of the ManagedGroupConfig.
    pub fn use_ratchet_tree_extension(mut self, use_ratchet_tree_extension: bool) -> Self {
        self.config.use_ratchet_tree_extension = use_ratchet_tree_extension;
        self
    }

    pub fn build(self) -> ManagedGroupConfig {
        self.config
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
