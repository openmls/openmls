use super::credential::CredentialType;
use super::extensions::{ExtensionType, Extensions};
use super::keys::EncryptionKey;
use super::proposals::ProposalType;
use super::{credential::Credential, keys::SignaturePublicKey};
use super::{Ciphersuite, Lifetime, ProtocolVersion, Signature};

use tls_codec::VLBytes;

/// A ratchet tree made of unverified nodes. This is used for deserialization
/// and verification.
#[derive(PartialEq, Eq, Debug)]
pub struct RatchetTree(pub(super) Vec<Option<Node>>);

#[derive(Debug, PartialEq, Eq, Clone)]
#[repr(u8)]
pub enum Node {
    /// A leaf node.
    LeafNode(LeafNode),
    /// A parent node.
    ParentNode(ParentNode),
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct LeafNodeIndex(pub(super) u32);

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct UnmergedLeaves {
    pub(super) list: Vec<LeafNodeIndex>,
}

/// This struct implements the MLS parent node. It contains its public key,
/// parent hash and unmerged leaves. Additionally, it may contain the private
/// key corresponding to the public key.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct ParentNode {
    pub(super) encryption_key: EncryptionKey,
    pub(super) parent_hash: VLBytes,
    pub(super) unmerged_leaves: UnmergedLeaves,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafNode {
    pub(super) payload: LeafNodePayload,
    pub(super) signature: Signature,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafNodePayload {
    pub(super) encryption_key: EncryptionKey,
    pub(super) signature_key: SignaturePublicKey,
    pub(super) credential: Credential,
    pub(super) capabilities: Capabilities,
    pub(super) leaf_node_source: LeafNodeSource,
    pub(super) extensions: Extensions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    pub(super) versions: Vec<ProtocolVersion>,
    pub(super) ciphersuites: Vec<Ciphersuite>,
    pub(super) extensions: Vec<ExtensionType>,
    pub(super) proposals: Vec<ProposalType>,
    pub(super) credentials: Vec<CredentialType>,
}
