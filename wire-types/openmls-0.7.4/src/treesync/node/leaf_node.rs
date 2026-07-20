//! This module contains the [`LeafNode`] struct and its implementation.
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

use super::encryption_keys::EncryptionKey;
use crate::{
    ciphersuite::{Signature, SignaturePublicKey},
    credentials::Credential,
    extensions::Extensions,
    key_packages::Lifetime,
};

mod capabilities;

pub use capabilities::*;

/// This struct implements the MLS leaf node.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     HPKEPublicKey encryption_key;
///     SignaturePublicKey signature_key;
///     Credential credential;
///     Capabilities capabilities;
///
///     LeafNodeSource leaf_node_source;
///     select (LeafNode.leaf_node_source) {
///         case key_package:
///             Lifetime lifetime;
///
///         case update:
///             struct{};
///
///         case commit:
///             opaque parent_hash<V>;
///     };
///
///     Extension extensions<V>;
///     /* SignWithLabel(., "LeafNodeTBS", LeafNodeTBS) */
///     opaque signature<V>;
/// } LeafNode;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub struct LeafNode {
    payload: LeafNodePayload,
    signature: Signature,
}

#[cfg(feature = "migration-export")]
impl LeafNode {
    /// Returns the `encryption_key`.
    pub fn encryption_key(&self) -> &EncryptionKey {
        &self.payload.encryption_key
    }
}

/// The payload of a [`LeafNode`]
///
/// ```text
/// struct {
///     HPKEPublicKey encryption_key;
///     SignaturePublicKey signature_key;
///     Credential credential;
///     Capabilities capabilities;
///
///     LeafNodeSource leaf_node_source;
///     select (LeafNode.leaf_node_source) {
///         case key_package:
///             Lifetime lifetime;
///
///         case update:
///             struct{};
///
///         case commit:
///             opaque parent_hash<V>;
///     };
///
///     Extension extensions<V>;
///     ...
/// } LeafNode;
/// ```
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
struct LeafNodePayload {
    encryption_key: EncryptionKey,
    signature_key: SignaturePublicKey,
    credential: Credential,
    capabilities: Capabilities,
    leaf_node_source: LeafNodeSource,
    extensions: Extensions,
}

/// The source of the `LeafNode`.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
#[repr(u8)]
pub enum LeafNodeSource {
    /// The leaf node was added to the group as part of a key package.
    #[tls_codec(discriminant = 1)]
    KeyPackage(Lifetime),
    /// The leaf node was added through an Update proposal.
    Update,
    /// The leaf node was added via a Commit.
    Commit(ParentHash),
}

pub type ParentHash = VLBytes;

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct LeafNodeIn {
    payload: LeafNodePayload,
    signature: Signature,
}
