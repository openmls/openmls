use crate::tree::sender_ratchet::SenderRatchetConfiguration;

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
    /// Size of padding in bytes
    pub(crate) padding_size: usize,
    /// Maximum number of past epochs for which application messages
    /// can be decrypted. The default is 0.
    pub(crate) max_past_epochs: usize,
    /// Number of resumtion secrets to keep
    pub(crate) number_of_resumption_secrets: usize,
    /// Flag to indicate the Ratchet Tree Extension should be used
    pub(crate) use_ratchet_tree_extension: bool,
    /// Required capabilities (extensions and proposal types)
    pub(crate) required_capabilities: RequiredCapabilitiesExtension,
    /// Sender ratchet configuration
    pub(crate) sender_ratchet_configuration: SenderRatchetConfiguration,
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

    /// Get the [`MlsGroupConfig`] max past epochs.
    pub fn max_past_epochs(&self) -> usize {
        self.max_past_epochs
    }

    /// Get the [`MlsGroupConfig`] number of resumption secrets.
    pub fn number_of_resumption_secrets(&self) -> usize {
        self.number_of_resumption_secrets
    }

    /// Get the [`MlsGroupConfig`] boolean flag that indicates whether ratchet_tree_extension should be used.
    pub fn use_ratchet_tree_extension(&self) -> bool {
        self.use_ratchet_tree_extension
    }

    /// Get the [`MlsGroupConfig`] sender ratchet configuration.
    pub fn sender_ratchet_configuration(&self) -> &SenderRatchetConfiguration {
        &self.sender_ratchet_configuration
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
            padding_size: 0,
            max_past_epochs: 0,
            number_of_resumption_secrets: 0,
            use_ratchet_tree_extension: false,
            required_capabilities: RequiredCapabilitiesExtension::default(),
            sender_ratchet_configuration: SenderRatchetConfiguration::default(),
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

    /// Sets the `padding_size` property of the MlsGroupConfig.
    pub fn padding_size(mut self, padding_size: usize) -> Self {
        self.config.padding_size = padding_size;
        self
    }

    /// Sets the `max_past_epochs` property of the MlsGroupConfig.
    /// This allows application messages from previous epochs to be decrypted.
    ///
    /// **WARNING**
    ///
    /// This feature enables the storage of message secrets from past epochs.
    /// It is a tradeoff between functionality and forward secrecy and should only be enabled
    /// if the Delivery Service cannot guarantee that application messages will be sent in
    /// the same epoch in which they were generated. The number for `max_epochs` should be
    /// as low as possible.
    pub fn max_past_epochs(mut self, max_past_epochs: usize) -> Self {
        self.config.max_past_epochs = max_past_epochs;
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

    /// Sets the `sender_ratchet_configuration` property of the MlsGroupConfig.
    /// See [`SenderRatchetConfiguration`] for more information.
    pub fn sender_ratchet_configuration(
        mut self,
        sender_ratchet_configuration: SenderRatchetConfiguration,
    ) -> Self {
        self.config.sender_ratchet_configuration = sender_ratchet_configuration;
        self
    }

    pub fn build(self) -> MlsGroupConfig {
        self.config
    }
}
