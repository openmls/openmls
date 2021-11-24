use tls_codec::TlsByteVecU8;
use tls_codec::{Size, TlsDeserialize, TlsSerialize, TlsSize, TlsVecU32};

use crate::ciphersuite::*;
use crate::extensions::*;

use super::*;
use std::convert::TryFrom;

/// Node type. Can be either `Leaf` or `Parent`.
#[derive(
    PartialEq, Clone, Copy, Debug, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
#[repr(u8)]
pub enum NodeType {
    Leaf = 1,
    Parent = 2,
}

impl NodeType {
    /// Returns `true` if the node type is `Leaf` and `false` otherwise.
    pub fn is_leaf(&self) -> bool {
        self == &NodeType::Leaf
    }

    /// Returns `true` if the node type is `Parent` and `false` otherwise.
    pub fn is_parent(&self) -> bool {
        self == &NodeType::Parent
    }
}

impl TryFrom<u8> for NodeType {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Err("Invalid node type."),
            1 => Ok(NodeType::Leaf),
            2 => Ok(NodeType::Parent),
            _ => Err("Unknown node type."),
        }
    }
}

/// Ratchet tree node. A `Node` can either be a leaf node (in which case it
/// contains an optional `KeyPackage`), or a parent node (in which case it
/// contains an optional `ParentNode`).
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Node {
    pub(crate) node_type: NodeType,
    // The node only holds public values.
    // The private HPKE keys are stored in the `PrivateTree`.
    pub(crate) key_package: Option<KeyPackage>,
    pub(crate) node: Option<ParentNode>,
}

// The Node is defined as enum, not option. So unfortunately we have to implement
// (de)serialization by hand.

impl tls_codec::Size for Node {
    fn tls_serialized_len(&self) -> usize {
        self.node_type.tls_serialized_len()
            + match &self.key_package {
                Some(kp) => kp.tls_serialized_len(),
                None => 0,
            }
            + match &self.node {
                Some(n) => n.tls_serialized_len(),
                None => 0,
            }
    }
}

impl tls_codec::Serialize for Node {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.node_type.tls_serialize(writer)?;
        written += match &self.key_package {
            Some(kp) => kp.tls_serialize(writer)?,
            None => 0,
        };
        written += match &self.node {
            Some(n) => n.tls_serialize(writer)?,
            None => 0,
        };
        Ok(written)
    }
}

impl tls_codec::Deserialize for Node {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let node_type = NodeType::tls_deserialize(bytes)?;
        let (key_package, node) = match node_type {
            NodeType::Leaf => (Some(KeyPackage::tls_deserialize(bytes)?), None),
            NodeType::Parent => (None, Some(ParentNode::tls_deserialize(bytes)?)),
        };
        Ok(Self {
            node_type,
            key_package,
            node,
        })
    }
}

impl Node {
    /// Creates a new leaf node. It can either be blank or contain a
    /// `KeyPackage`.
    pub fn new_leaf(kp_option: Option<KeyPackage>) -> Self {
        Node {
            node_type: NodeType::Leaf,
            key_package: kp_option,
            node: None,
        }
    }

    /// Creates a new blank parent node.
    pub fn new_blank_parent_node() -> Self {
        Node {
            node_type: NodeType::Parent,
            key_package: None,
            node: None,
        }
    }

    /// Returns the public HPKE key of either node type.
    pub fn public_hpke_key(&self) -> Option<&HpkePublicKey> {
        match self.node_type {
            NodeType::Leaf => self.key_package.as_ref().map(|kp| kp.hpke_init_key()),
            NodeType::Parent => self
                .node
                .as_ref()
                .map(|parent_node| &parent_node.public_key),
        }
    }

    /// Blanks the node.
    pub fn blank(&mut self) {
        self.key_package = None;
        self.node = None;
    }

    /// Returns `true` if the node is blank and `false` otherwise.
    pub fn is_blank(&self) -> bool {
        self.key_package.is_none() && self.node.is_none()
    }

    /// Returns `true` if the node is a non-blank parent node and `false`
    /// otherwise.
    pub(crate) fn is_full_parent(&self) -> bool {
        self.node_type.is_parent() && self.node.is_some() && self.key_package.is_none()
    }

    /// Returns the parent hash of a node. Returns `None` if the node is blank.
    /// Otherwise returns the `parent_hash` field for parent nodes and
    /// optionally the `parent_hash` field of the `ParentHashExtension` of the
    /// leaf node if the extension is present.
    pub fn parent_hash(&self) -> Option<&[u8]> {
        if self.is_blank() {
            return None;
        }
        match self.node_type {
            NodeType::Parent => self.node.as_ref().map(|n| n.parent_hash.as_slice()),
            NodeType::Leaf => {
                if let Some(key_package) = &self.key_package {
                    let parent_hash_extension =
                        key_package.extension_with_type(ExtensionType::ParentHash);
                    match parent_hash_extension {
                        Some(phe) => {
                            let phe = match phe.as_parent_hash_extension() {
                                Ok(phe) => phe,
                                Err(_) => return None,
                            };
                            Some(phe.parent_hash())
                        }
                        None => None,
                    }
                } else {
                    None
                }
            }
        }
    }

    /// Get a reference to the key package in this node.
    pub fn key_package(&self) -> Option<&KeyPackage> {
        self.key_package.as_ref()
    }
}

/// Content of a parent node.
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct ParentNode {
    pub(crate) public_key: HpkePublicKey,
    pub(crate) parent_hash: TlsByteVecU8,
    pub(crate) unmerged_leaves: TlsVecU32<LeafIndex>,
}

impl ParentNode {
    /// Creates a new `ParentNode` from the provided values.
    pub fn new(
        public_key: HpkePublicKey,
        unmerged_leaves: &[LeafIndex],
        parent_hash: &[u8],
    ) -> Self {
        Self {
            public_key,
            unmerged_leaves: unmerged_leaves.into(),
            parent_hash: parent_hash.into(),
        }
    }
    /// Returns the node's HPKE public key
    pub fn public_key(&self) -> &HpkePublicKey {
        &self.public_key
    }
    /// Sets the node's parent hash
    pub fn set_parent_hash(&mut self, hash: Vec<u8>) {
        self.parent_hash = hash.into();
    }
    /// Returns the node's unmerged leaves
    pub fn unmerged_leaves(&self) -> &[LeafIndex] {
        self.unmerged_leaves.as_slice()
    }
    /// Adds a leaf to the node's unmerged leaves
    pub fn add_unmerged_leaf(&mut self, leaf: LeafIndex) {
        self.unmerged_leaves.push(leaf);
    }
}
