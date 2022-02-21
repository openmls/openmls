//! Configuration module for [`MlsGroup`] configurations.

use super::*;
use crate::tree::sender_ratchet::SenderRatchetConfiguration;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

/// Specifies the configuration parameters for a [`MlsGroup`]. Refer to
/// the [User Manual](https://openmls.tech/book/user_manual/group_config.html) for more information about the different configuration values.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct MlsGroupConfig {
    /// Defines the wire format policy for outgoing and incoming handshake messages.
    /// Application are always encrypted regardless.
    pub(crate) wire_format_policy: WireFormatPolicy,
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

    /// Returns the [`MlsGroupConfig`] wire format policy.
    pub fn wire_format_policy(&self) -> WireFormatPolicy {
        self.wire_format_policy
    }

    /// Returns the [`MlsGroupConfig`] padding size.
    pub fn padding_size(&self) -> usize {
        self.padding_size
    }

    /// Returns the [`MlsGroupConfig`] max past epochs.
    pub fn max_past_epochs(&self) -> usize {
        self.max_past_epochs
    }

    /// Returns the [`MlsGroupConfig`] number of resumption secrets.
    pub fn number_of_resumption_secrets(&self) -> usize {
        self.number_of_resumption_secrets
    }

    /// Returns the [`MlsGroupConfig`] boolean flag that indicates whether ratchet_tree_extension should be used.
    pub fn use_ratchet_tree_extension(&self) -> bool {
        self.use_ratchet_tree_extension
    }

    /// Returns the [`MlsGroupConfig`] sender ratchet configuration.
    pub fn sender_ratchet_configuration(&self) -> &SenderRatchetConfiguration {
        &self.sender_ratchet_configuration
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn test_default() -> Self {
        Self::builder()
            .wire_format_policy(WireFormatPolicy::new(
                OutgoingWireFormatPolicy::AlwaysPlaintext,
                IncomingWireFormatPolicy::Mixed,
            ))
            .build()
    }
}

/// Builder for an [`MlsGroupConfig`].
#[derive(Default)]
pub struct MlsGroupConfigBuilder {
    config: MlsGroupConfig,
}
impl MlsGroupConfigBuilder {
    /// Creates a new builder with default values.
    pub fn new() -> Self {
        MlsGroupConfigBuilder {
            config: MlsGroupConfig::default(),
        }
    }

    /// Sets the `wire_format` property of the MlsGroupConfig.
    pub fn wire_format_policy(mut self, wire_format_policy: WireFormatPolicy) -> Self {
        self.config.wire_format_policy = wire_format_policy;
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

    /// Finalizes the builder and retursn an `[MlsGroupConfig`].
    pub fn build(self) -> MlsGroupConfig {
        self.config
    }
}

/// Defines what wire format is acceptable for incoming handshake messages.
/// Note that application messages must always be encrypted.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum IncomingWireFormatPolicy {
    /// Handshake messages must always be MlsCiphertext
    AlwaysCiphertext,
    /// Handshake messages must always be MlsPlaintext
    AlwaysPlaintext,
    /// Handshake messages can either be MlsCiphertext or MlsPlaintext
    Mixed,
}

impl IncomingWireFormatPolicy {
    pub(crate) fn is_compatible_with(&self, wire_format: WireFormat) -> bool {
        match self {
            IncomingWireFormatPolicy::AlwaysCiphertext => wire_format == WireFormat::MlsCiphertext,
            IncomingWireFormatPolicy::AlwaysPlaintext => wire_format == WireFormat::MlsPlaintext,
            IncomingWireFormatPolicy::Mixed => {
                wire_format == WireFormat::MlsCiphertext || wire_format == WireFormat::MlsPlaintext
            }
        }
    }
}

/// Defines what wire format should be used for outgoing handshake messages.
/// Note that application messages must always be encrypted.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum OutgoingWireFormatPolicy {
    /// Handshake messages must always be MlsCiphertext
    AlwaysCiphertext,
    /// Handshake messages must always be MlsPlaintext
    AlwaysPlaintext,
}

/// Defines what wire format is desired for outgoing handshake messages.
/// Note that application messages must always be encrypted.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct WireFormatPolicy {
    outgoing: OutgoingWireFormatPolicy,
    incoming: IncomingWireFormatPolicy,
}

impl WireFormatPolicy {
    /// Creates a new wire format policy from an [`OutgoingWireFormatPolicy`] and an [`IncomingWireFormatPolicy`].
    pub fn new(outgoing: OutgoingWireFormatPolicy, incoming: IncomingWireFormatPolicy) -> Self {
        Self { outgoing, incoming }
    }

    /// Returns a reference to the wire format policy's outgoing wire format policy.
    pub fn outgoing(&self) -> OutgoingWireFormatPolicy {
        self.outgoing
    }

    /// Returns a reference to the wire format policy's incoming wire format policy.
    pub fn incoming(&self) -> IncomingWireFormatPolicy {
        self.incoming
    }

    /// Set the wire format policy's outgoing wire format policy.
    pub fn set_outgoing(&mut self, outgoing: OutgoingWireFormatPolicy) {
        self.outgoing = outgoing;
    }

    /// Set the wire format policy's incoming wire format policy.
    pub fn set_incoming(&mut self, incoming: IncomingWireFormatPolicy) {
        self.incoming = incoming;
    }
}

impl Default for WireFormatPolicy {
    fn default() -> Self {
        *PURE_CIPHERTEXT_WIRE_FORMAT_POLICY
    }
}

impl From<OutgoingWireFormatPolicy> for WireFormat {
    fn from(outgoing: OutgoingWireFormatPolicy) -> Self {
        match outgoing {
            OutgoingWireFormatPolicy::AlwaysCiphertext => WireFormat::MlsCiphertext,
            OutgoingWireFormatPolicy::AlwaysPlaintext => WireFormat::MlsPlaintext,
        }
    }
}

lazy_static! {
    /// All valid wire format policy combinations
    pub static ref ALL_VALID_WIRE_FORMAT_POLICIES: Vec<WireFormatPolicy> = vec![
        *PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        *PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
        *MIXED_PLAINTEXT_WIRE_FORMAT_POLICY,
        *MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY,
    ];
}

lazy_static! {
    /// Pure plaintext wire format policy.
    pub static ref PURE_PLAINTEXT_WIRE_FORMAT_POLICY: WireFormatPolicy = WireFormatPolicy::new(
        OutgoingWireFormatPolicy::AlwaysPlaintext,
        IncomingWireFormatPolicy::AlwaysPlaintext,
    );
}

lazy_static! {
    /// Pure ciphertext wire format policy.
    pub static ref PURE_CIPHERTEXT_WIRE_FORMAT_POLICY: WireFormatPolicy = WireFormatPolicy::new(
        OutgoingWireFormatPolicy::AlwaysCiphertext,
        IncomingWireFormatPolicy::AlwaysCiphertext,
    );
}

lazy_static! {
    /// Mixed plaintext wire format policy combination.
    pub static ref MIXED_PLAINTEXT_WIRE_FORMAT_POLICY: WireFormatPolicy = WireFormatPolicy::new(
        OutgoingWireFormatPolicy::AlwaysPlaintext,
        IncomingWireFormatPolicy::Mixed,
    );
}

lazy_static! {
    /// Mixed ciphertext wire format policy combination.
    pub static ref MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY: WireFormatPolicy = WireFormatPolicy::new(
        OutgoingWireFormatPolicy::AlwaysCiphertext,
        IncomingWireFormatPolicy::Mixed,
    );
}
