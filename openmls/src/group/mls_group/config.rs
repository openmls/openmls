use super::*;

use serde::{Deserialize, Serialize};

/// Specifies the configuration parameters for a [`MlsGroup`]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MlsGroupConfig {
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
    /// Required capabilities (extensions and proposal types)
    pub(crate) required_capabilities: RequiredCapabilitiesExtension,
}

impl MlsGroupConfig {
    /// Returns a builder for [`MlsGroupConfig`]
    pub fn builder() -> MlsGroupConfigBuilder {
        MlsGroupConfigBuilder::new()
    }

    /// Get the [`MlsGroupConfig`] wire format.
    pub fn wire_format(&self) -> WireFormat {
        self.wire_format
    }

    /// Get the [`MlsGroupConfig`] padding size.
    pub fn padding_size(&self) -> usize {
        self.padding_size
    }

    /// Get a reference to the [`MlsGroupConfig`] update policy.
    pub fn update_policy(&self) -> &UpdatePolicy {
        &self.update_policy
    }

    /// Get the [`MlsGroupConfig`] number of resumption secrets.
    pub fn number_of_resumption_secrets(&self) -> usize {
        self.number_of_resumption_secrets
    }

    /// Get the [`MlsGroupConfig`] boolean flag that indicates whether ratchet_tree_extension should be used.
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

impl Default for MlsGroupConfig {
    fn default() -> Self {
        MlsGroupConfig {
            wire_format: WireFormat::MlsCiphertext,
            update_policy: UpdatePolicy::default(),
            padding_size: 0,
            number_of_resumption_secrets: 0,
            use_ratchet_tree_extension: false,
            required_capabilities: RequiredCapabilitiesExtension::default(),
        }
    }
}

#[derive(Default)]
pub struct MlsGroupConfigBuilder {
    config: MlsGroupConfig,
}
impl MlsGroupConfigBuilder {
    pub fn new() -> Self {
        MlsGroupConfigBuilder {
            config: MlsGroupConfig::default(),
        }
    }

    /// Sets the `wire_format` property of the MlsGroupConfig.
    pub fn wire_format(mut self, wire_format: WireFormat) -> Self {
        self.config.wire_format = wire_format;
        self
    }

    /// Sets the `update_policy` property of the MlsGroupConfig.
    pub fn update_policy(mut self, update_policy: UpdatePolicy) -> Self {
        self.config.update_policy = update_policy;
        self
    }

    /// Sets the `padding_size` property of the MlsGroupConfig.
    pub fn padding_size(mut self, padding_size: usize) -> Self {
        self.config.padding_size = padding_size;
        self
    }

    /// Sets the `number_of_resumption_secrets` property of the MlsGroupConfig.
    pub fn number_of_resumtion_secrets(mut self, number_of_resumption_secrets: usize) -> Self {
        self.config.number_of_resumption_secrets = number_of_resumption_secrets;
        self
    }

    /// Sets the `use_ratchet_tree_extension` property of the MlsGroupConfig.
    pub fn use_ratchet_tree_extension(mut self, use_ratchet_tree_extension: bool) -> Self {
        self.config.use_ratchet_tree_extension = use_ratchet_tree_extension;
        self
    }

    pub fn build(self) -> MlsGroupConfig {
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
