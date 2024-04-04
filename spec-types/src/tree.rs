use crate::credential::CredentialType;
use crate::extensions::{ExtensionType, Extensions};
use crate::keys::EncryptionKey;
use crate::proposals::ProposalType;
use crate::{credential::Credential, keys::SignaturePublicKey};
use crate::{Ciphersuite, Lifetime, ProtocolVersion, Signature};

use crate::VLBytes;
use serde::{Deserialize, Serialize};

/// A ratchet tree made of unverified nodes. This is used for deserialization
/// and verification.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct RatchetTree(pub Vec<Option<Node>>);

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[repr(u8)]
pub enum Node {
    /// A leaf node.
    LeafNode(LeafNode),
    /// A parent node.
    ParentNode(ParentNode),
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct LeafNodeIndex(pub u32);

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct UnmergedLeaves {
    pub list: Vec<LeafNodeIndex>,
}

/// This struct implements the MLS parent node. It contains its public key,
/// parent hash and unmerged leaves. Additionally, it may contain the private
/// key corresponding to the public key.
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct ParentNode {
    pub encryption_key: EncryptionKey,
    pub parent_hash: VLBytes,
    pub unmerged_leaves: UnmergedLeaves,
}

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
// TODO(#1242): Do not derive `TlsDeserialize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafNode {
    pub payload: LeafNodePayload,
    pub signature: Signature,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafNodePayload {
    pub encryption_key: EncryptionKey,
    pub signature_key: SignaturePublicKey,
    pub credential: Credential,
    pub capabilities: Capabilities,
    pub leaf_node_source: LeafNodeSource,
    pub extensions: Extensions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum LeafNodeSource {
    KeyPackage(Lifetime),
    Update,
    Commit(ParentHash),
}

pub type ParentHash = VLBytes;

/// Capabilities of [`LeafNode`]s.
///
/// ```text
/// struct {
///     ProtocolVersion versions<V>;
///     CipherSuite ciphersuites<V>;
///     ExtensionType extensions<V>;
///     ProposalType proposals<V>;
///     CredentialType credentials<V>;
/// } Capabilities;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub versions: Vec<ProtocolVersion>,
    pub ciphersuites: Vec<Ciphersuite>,
    pub extensions: Vec<ExtensionType>,
    pub proposals: Vec<ProposalType>,
    pub credentials: Vec<CredentialType>,
}
