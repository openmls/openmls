//! Configuration module for [`MlsGroup`] configurations.

use super::*;
use crate::{
    key_packages::Lifetime, tree::sender_ratchet::SenderRatchetConfiguration,
    treesync::node::leaf_node::Capabilities,
};
use serde::{Deserialize, Serialize};

/// The [`MlsGroupJoinConfig`] contains all configuration parameters that are
/// relevant to group operation at runtime. It is used to configure the group's
/// behaviour when joining an existing group. To configure a newly created
/// group, use [`MlsGroupCreateConfig`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
