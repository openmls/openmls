//! Configuration module for [`MlsGroup`] configurations.
//!
//! ## Building an MlsGroupCreateConfig
//! The [`MlsGroupCreateConfigBuilder`] makes it easy to build configurations for the
//! [`MlsGroup`].
//!
//! ```
//! use openmls::prelude::*;
//!
//! let group_config = MlsGroupCreateConfig::builder()
//!     .use_ratchet_tree_extension(true)
//!     .build();
//! ```
//!
//! See [`MlsGroupCreateConfigBuilder`](MlsGroupCreateConfigBuilder#implementations) for
//! all options that can be configured.
//!
//! ### Wire format policies
//! Only some combination of possible wire formats are valid within OpenMLS.
//! The [`WIRE_FORMAT_POLICIES`] lists all valid options that can be set.
//!
//! ```
//! use openmls::prelude::*;
//!
//! let group_config = MlsGroupCreateConfig::builder()
//!     .wire_format_policy(MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY)
//!     .build();
//! ```

use super::*;
use crate::{
    extensions::errors::InvalidExtensionError,
    key_packages::Lifetime,
    tree::sender_ratchet::SenderRatchetConfiguration,
    treesync::{errors::LeafNodeValidationError, node::leaf_node::Capabilities},
};
use serde::{Deserialize, Serialize};

/// The [`MlsGroupJoinConfig`] contains all configuration parameters that are
/// relevant to group operation at runtime. It is used to configure the group's
/// behaviour when joining an existing group. To configure a newly created
/// group, use [`MlsGroupCreateConfig`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsGroupJoinConfig {
    /// Defines the wire format policy for outgoing and incoming handshake messages.
    /// Application are always encrypted regardless.
    pub(crate) wire_format_policy: WireFormatPolicy,
    /// Size of padding in bytes
    pub(crate) padding_size: usize,
    /// Maximum number of past epochs for which application messages
    /// can be decrypted. The default is 0.
    pub(crate) max_past_epochs: usize,
    /// Number of resumption secrets to keep
    pub(crate) number_of_resumption_psks: usize,
    /// Flag to indicate the Ratchet Tree Extension should be used
    pub(crate) use_ratchet_tree_extension: bool,
    /// Sender ratchet configuration
    pub(crate) sender_ratchet_configuration: SenderRatchetConfiguration,
}

impl MlsGroupJoinConfig {
    /// Returns a builder for [`MlsGroupJoinConfig`].
    pub fn builder() -> MlsGroupJoinConfigBuilder {
        MlsGroupJoinConfigBuilder::new()
    }

    /// Returns the wire format policy set in this  [`MlsGroupJoinConfig`].
    pub fn wire_format_policy(&self) -> WireFormatPolicy {
        self.wire_format_policy
    }

    /// Returns the padding size set in this  [`MlsGroupJoinConfig`].
    pub fn padding_size(&self) -> usize {
        self.padding_size
    }

    /// Returns the [`SenderRatchetConfiguration`] set in this  [`MlsGroupJoinConfig`].
    pub fn sender_ratchet_configuration(&self) -> &SenderRatchetConfiguration {
        &self.sender_ratchet_configuration
    }
}

/// Specifies configuration for the creation of an [`MlsGroup`]. Refer to the
/// [User Manual](https://book.openmls.tech/user_manual/group_config.html) for
/// more information about the different configuration values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsGroupCreateConfig {
    /// Capabilities advertised in the creator's leaf node
    pub(crate) capabilities: Capabilities,
    /// Lifetime of the own leaf node
    pub(crate) lifetime: Lifetime,
    /// Ciphersuite and protocol version
    pub(crate) ciphersuite: Ciphersuite,
    /// Configuration parameters relevant to group operation at runtime
    pub(crate) join_config: MlsGroupJoinConfig,
    /// List of initial group context extensions
    pub(crate) group_context_extensions: Extensions,
    /// List of initial leaf node extensions
    pub(crate) leaf_node_extensions: Extensions,
}

impl Default for MlsGroupCreateConfig {
    fn default() -> Self {
        Self {
            capabilities: Capabilities::default(),
            lifetime: Lifetime::default(),
            ciphersuite: Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            join_config: MlsGroupJoinConfig::default(),
            group_context_extensions: Extensions::default(),
            leaf_node_extensions: Extensions::default(),
        }
    }
}

/// Builder struct for an [`MlsGroupJoinConfig`].
#[derive(Default)]
pub struct MlsGroupJoinConfigBuilder {
    join_config: MlsGroupJoinConfig,
}

impl MlsGroupJoinConfigBuilder {
    /// Creates a new builder with default values.
    fn new() -> Self {
        Self {
            join_config: MlsGroupJoinConfig::default(),
        }
    }

    /// Sets the `wire_format` property of the [`MlsGroupJoinConfig`].
    pub fn wire_format_policy(mut self, wire_format_policy: WireFormatPolicy) -> Self {
        self.join_config.wire_format_policy = wire_format_policy;
        self
    }

    /// Sets the `padding_size` property of the [`MlsGroupJoinConfig`].
    pub fn padding_size(mut self, padding_size: usize) -> Self {
        self.join_config.padding_size = padding_size;
        self
    }

    /// Sets the `max_past_epochs` property of the [`MlsGroupJoinConfig`].
    pub fn max_past_epochs(mut self, max_past_epochs: usize) -> Self {
        self.join_config.max_past_epochs = max_past_epochs;
        self
    }

    /// Sets the `number_of_resumption_psks` property of the [`MlsGroupJoinConfig`].
    pub fn number_of_resumption_psks(mut self, number_of_resumption_psks: usize) -> Self {
        self.join_config.number_of_resumption_psks = number_of_resumption_psks;
        self
    }

    /// Sets the `use_ratchet_tree_extension` property of the [`MlsGroupJoinConfig`].
    pub fn use_ratchet_tree_extension(mut self, use_ratchet_tree_extension: bool) -> Self {
        self.join_config.use_ratchet_tree_extension = use_ratchet_tree_extension;
        self
    }

    /// Sets the `sender_ratchet_configuration` property of the [`MlsGroupJoinConfig`].
    pub fn sender_ratchet_configuration(
        mut self,
        sender_ratchet_configuration: SenderRatchetConfiguration,
    ) -> Self {
        self.join_config.sender_ratchet_configuration = sender_ratchet_configuration;
        self
    }

    /// Finalizes the builder and returns an [`MlsGroupJoinConfig`].
    pub fn build(self) -> MlsGroupJoinConfig {
        self.join_config
    }
}

impl MlsGroupCreateConfig {
    /// Returns a builder for [`MlsGroupCreateConfig`]
    pub fn builder() -> MlsGroupCreateConfigBuilder {
        MlsGroupCreateConfigBuilder::new()
    }

    /// Returns the [`MlsGroupCreateConfig`] wire format policy.
    pub fn wire_format_policy(&self) -> WireFormatPolicy {
        self.join_config.wire_format_policy
    }

    /// Returns the [`MlsGroupCreateConfig`] padding size.
    pub fn padding_size(&self) -> usize {
        self.join_config.padding_size
    }

    /// Returns the [`MlsGroupCreateConfig`] max past epochs.
    pub fn max_past_epochs(&self) -> usize {
        self.join_config.max_past_epochs
    }

    /// Returns the [`MlsGroupCreateConfig`] number of resumption psks.
    pub fn number_of_resumption_psks(&self) -> usize {
        self.join_config.number_of_resumption_psks
    }

    /// Returns the [`MlsGroupCreateConfig`] boolean flag that indicates whether ratchet_tree_extension should be used.
    pub fn use_ratchet_tree_extension(&self) -> bool {
        self.join_config.use_ratchet_tree_extension
    }

    /// Returns the [`MlsGroupCreateConfig`] sender ratchet configuration.
    pub fn sender_ratchet_configuration(&self) -> &SenderRatchetConfiguration {
        &self.join_config.sender_ratchet_configuration
    }

    /// Returns the [`Extensions`] set as the initial group context.
    /// This does not contain the initial group context extensions
    /// added from builder calls to `external_senders` or `required_capabilities`.
    pub fn group_context_extensions(&self) -> &Extensions {
        &self.group_context_extensions
    }

    /// Returns the [`MlsGroupCreateConfig`] lifetime configuration.
    pub fn lifetime(&self) -> &Lifetime {
        &self.lifetime
    }

    /// Returns the [`Ciphersuite`].
    pub fn ciphersuite(&self) -> Ciphersuite {
        self.ciphersuite
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn test_default(ciphersuite: Ciphersuite) -> Self {
        Self::builder()
            .wire_format_policy(WireFormatPolicy::new(
                OutgoingWireFormatPolicy::AlwaysPlaintext,
                IncomingWireFormatPolicy::Mixed,
            ))
            .ciphersuite(ciphersuite)
            .build()
    }

    /// Returns the [`MlsGroupJoinConfig`] of groups created with this create config.
    pub fn join_config(&self) -> &MlsGroupJoinConfig {
        &self.join_config
    }
}

/// Builder for an [`MlsGroupCreateConfig`].
#[derive(Default, Debug)]
pub struct MlsGroupCreateConfigBuilder {
    config: MlsGroupCreateConfig,
}

impl MlsGroupCreateConfigBuilder {
    /// Creates a new builder with default values.
    fn new() -> Self {
        MlsGroupCreateConfigBuilder {
            config: MlsGroupCreateConfig::default(),
        }
    }

    /// Sets the `wire_format` property of the MlsGroupCreateConfig.
    pub fn wire_format_policy(mut self, wire_format_policy: WireFormatPolicy) -> Self {
        self.config.join_config.wire_format_policy = wire_format_policy;
        self
    }

    /// Sets the `padding_size` property of the MlsGroupCreateConfig.
    pub fn padding_size(mut self, padding_size: usize) -> Self {
        self.config.join_config.padding_size = padding_size;
        self
    }

    /// Sets the `max_past_epochs` property of the MlsGroupCreateConfig.
    /// This allows application messages from previous epochs to be decrypted.
    ///
    /// **WARNING**
    ///
    /// This feature enables the storage of message secrets from past epochs.
    /// It is a trade-off between functionality and forward secrecy and should only be enabled
    /// if the Delivery Service cannot guarantee that application messages will be sent in
    /// the same epoch in which they were generated. The number for `max_epochs` should be
    /// as low as possible.
    pub fn max_past_epochs(mut self, max_past_epochs: usize) -> Self {
        self.config.join_config.max_past_epochs = max_past_epochs;
        self
    }

    /// Sets the `number_of_resumption_psks` property of the MlsGroupCreateConfig.
    pub fn number_of_resumption_psks(mut self, number_of_resumption_psks: usize) -> Self {
        self.config.join_config.number_of_resumption_psks = number_of_resumption_psks;
        self
    }

    /// Sets the `use_ratchet_tree_extension` property of the MlsGroupCreateConfig.
    pub fn use_ratchet_tree_extension(mut self, use_ratchet_tree_extension: bool) -> Self {
        self.config.join_config.use_ratchet_tree_extension = use_ratchet_tree_extension;
        self
    }

    /// Sets the `capabilities` of the group creator's leaf node.
    pub fn capabilities(mut self, capabilities: Capabilities) -> Self {
        self.config.capabilities = capabilities;
        self
    }

    /// Sets the `sender_ratchet_configuration` property of the MlsGroupCreateConfig.
    /// See [`SenderRatchetConfiguration`] for more information.
    pub fn sender_ratchet_configuration(
        mut self,
        sender_ratchet_configuration: SenderRatchetConfiguration,
    ) -> Self {
        self.config.join_config.sender_ratchet_configuration = sender_ratchet_configuration;
        self
    }

    /// Sets the `lifetime` property of the MlsGroupCreateConfig.
    pub fn lifetime(mut self, lifetime: Lifetime) -> Self {
        self.config.lifetime = lifetime;
        self
    }

    /// Sets the `ciphersuite` property of the MlsGroupCreateConfig.
    pub fn ciphersuite(mut self, ciphersuite: Ciphersuite) -> Self {
        self.config.ciphersuite = ciphersuite;
        self
    }

    /// Sets initial group context extensions.
    pub fn with_group_context_extensions(
        mut self,
        extensions: Extensions,
    ) -> Result<Self, InvalidExtensionError> {
        let is_valid_in_group_context = extensions.application_id().is_none()
            && extensions.ratchet_tree().is_none()
            && extensions.external_pub().is_none();
        if !is_valid_in_group_context {
            return Err(InvalidExtensionError::IllegalInGroupContext);
        }
        self.config.group_context_extensions = extensions;
        Ok(self)
    }

    /// Sets extensions of the group creator's [`LeafNode`].
    pub fn with_leaf_node_extensions(
        mut self,
        extensions: Extensions,
    ) -> Result<Self, LeafNodeValidationError> {
        // None of the default extensions are leaf node extensions, so only
        // unknown extensions can be leaf node extensions.
        let is_valid_in_leaf_node = extensions
            .iter()
            .all(|e| matches!(e.extension_type(), ExtensionType::Unknown(_)));
        if !is_valid_in_leaf_node {
            log::error!("Leaf node extensions must be unknown extensions.");
            return Err(LeafNodeValidationError::UnsupportedExtensions);
        }

        // Make sure that the extension type is supported in this context.
        // This means that the leaf node needs to have support listed in the
        // the capabilities (https://validation.openmls.tech/#valn0107).
        if !self.config.capabilities.contains_extensions(&extensions) {
            return Err(LeafNodeValidationError::ExtensionsNotInCapabilities);
        }

        self.config.leaf_node_extensions = extensions;
        Ok(self)
    }

    /// Finalizes the builder and retursn an `[MlsGroupCreateConfig`].
    pub fn build(self) -> MlsGroupCreateConfig {
        self.config
    }
}

/// Defines what wire format is acceptable for incoming handshake messages.
/// Note that application messages must always be encrypted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncomingWireFormatPolicy {
    /// Handshake messages must always be PrivateMessage
    AlwaysCiphertext,
    /// Handshake messages must always be PublicMessage
    AlwaysPlaintext,
    /// Handshake messages can either be PrivateMessage or PublicMessage
    Mixed,
}

impl IncomingWireFormatPolicy {
    pub(crate) fn is_compatible_with(&self, wire_format: WireFormat) -> bool {
        match self {
            IncomingWireFormatPolicy::AlwaysCiphertext => wire_format == WireFormat::PrivateMessage,
            IncomingWireFormatPolicy::AlwaysPlaintext => wire_format == WireFormat::PublicMessage,
            IncomingWireFormatPolicy::Mixed => {
                wire_format == WireFormat::PrivateMessage
                    || wire_format == WireFormat::PublicMessage
            }
        }
    }
}

/// Defines what wire format should be used for outgoing handshake messages.
/// Note that application messages must always be encrypted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutgoingWireFormatPolicy {
    /// Handshake messages must always be PrivateMessage
    AlwaysCiphertext,
    /// Handshake messages must always be PublicMessage
    AlwaysPlaintext,
}

/// Defines what wire format is desired for outgoing handshake messages.
/// Note that application messages must always be encrypted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireFormatPolicy {
    outgoing: OutgoingWireFormatPolicy,
    incoming: IncomingWireFormatPolicy,
}

impl WireFormatPolicy {
    /// Creates a new wire format policy from an [`OutgoingWireFormatPolicy`]
    /// and an [`IncomingWireFormatPolicy`].
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn new(
        outgoing: OutgoingWireFormatPolicy,
        incoming: IncomingWireFormatPolicy,
    ) -> Self {
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
}

impl Default for WireFormatPolicy {
    fn default() -> Self {
        PURE_CIPHERTEXT_WIRE_FORMAT_POLICY
    }
}

impl From<OutgoingWireFormatPolicy> for WireFormat {
    fn from(outgoing: OutgoingWireFormatPolicy) -> Self {
        match outgoing {
            OutgoingWireFormatPolicy::AlwaysCiphertext => WireFormat::PrivateMessage,
            OutgoingWireFormatPolicy::AlwaysPlaintext => WireFormat::PublicMessage,
        }
    }
}

/// All valid wire format policy combinations.
/// - [`PURE_PLAINTEXT_WIRE_FORMAT_POLICY`]
/// - [`PURE_CIPHERTEXT_WIRE_FORMAT_POLICY`]
/// - [`MIXED_PLAINTEXT_WIRE_FORMAT_POLICY`]
/// - [`MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY`]
pub const WIRE_FORMAT_POLICIES: [WireFormatPolicy; 4] = [
    PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
    MIXED_PLAINTEXT_WIRE_FORMAT_POLICY,
    MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY,
];

/// Incoming and outgoing wire formats are always plaintext.
pub const PURE_PLAINTEXT_WIRE_FORMAT_POLICY: WireFormatPolicy = WireFormatPolicy {
    outgoing: OutgoingWireFormatPolicy::AlwaysPlaintext,
    incoming: IncomingWireFormatPolicy::AlwaysPlaintext,
};

/// Incoming and outgoing wire formats are always ciphertext.
pub const PURE_CIPHERTEXT_WIRE_FORMAT_POLICY: WireFormatPolicy = WireFormatPolicy {
    outgoing: OutgoingWireFormatPolicy::AlwaysCiphertext,
    incoming: IncomingWireFormatPolicy::AlwaysCiphertext,
};

/// Incoming wire formats can be mixed while outgoing wire formats are always
/// plaintext.
pub const MIXED_PLAINTEXT_WIRE_FORMAT_POLICY: WireFormatPolicy = WireFormatPolicy {
    outgoing: OutgoingWireFormatPolicy::AlwaysPlaintext,
    incoming: IncomingWireFormatPolicy::Mixed,
};

/// Incoming wire formats can be mixed while outgoing wire formats are always
/// ciphertext.
pub const MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY: WireFormatPolicy = WireFormatPolicy {
    outgoing: OutgoingWireFormatPolicy::AlwaysCiphertext,
    incoming: IncomingWireFormatPolicy::Mixed,
};
