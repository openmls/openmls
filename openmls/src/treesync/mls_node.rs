use std::convert::TryFrom;

use tls_codec::{
    Size, TlsByteSliceU8, TlsByteVecU8, TlsDeserialize, TlsSerialize, TlsSize, TlsVecU32,
};

use crate::{binary_tree::LeafIndex, ciphersuite::HpkePublicKey, prelude::KeyPackage};

use super::node::{leaf_node::LeafNode, parent_node::ParentNode, Node};

/// Node type. Can be either `Leaf` or `Parent`.
#[derive(PartialEq, Clone, Copy, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum MlsNodeType {
    Leaf = 1,
    Parent = 2,
}

impl MlsNodeType {
    /// Returns `true` if the node type is `Leaf` and `false` otherwise.
    pub fn is_leaf(&self) -> bool {
        self == &MlsNodeType::Leaf
    }

    /// Returns `true` if the node type is `Parent` and `false` otherwise.
    pub fn is_parent(&self) -> bool {
        self == &MlsNodeType::Parent
    }
}

impl TryFrom<u8> for MlsNodeType {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Err("Invalid node type."),
            1 => Ok(MlsNodeType::Leaf),
            2 => Ok(MlsNodeType::Parent),
            _ => Err("Unknown node type."),
        }
    }
}

// The Node is defined as enum, not option. So unfortunately we have to implement
// (de)serialization by hand.
impl tls_codec::Size for Node {
    fn tls_serialized_len(&self) -> usize {
        1 // Length of MlsNodeType
            + match self {
                Node::LeafNode(kp) => kp.tls_serialized_len(),
                Node::ParentNode(n) => n.tls_serialized_len(),
            }
    }
}

impl tls_codec::Serialize for Node {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        match self {
            Node::LeafNode(kp) => {
                let written = MlsNodeType::Leaf.tls_serialize(writer)?;
                kp.tls_serialize(writer).map(|l| l + written)
            }
            Node::ParentNode(n) => {
                let written = MlsNodeType::Parent.tls_serialize(writer)?;
                n.tls_serialize(writer).map(|l| l + written)
            }
        }
    }
}

impl tls_codec::Deserialize for Node {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let node_type = MlsNodeType::tls_deserialize(bytes)?;
        let node = match node_type {
            MlsNodeType::Leaf => Node::LeafNode(LeafNode::tls_deserialize(bytes)?),
            MlsNodeType::Parent => Node::ParentNode(ParentNode::tls_deserialize(bytes)?),
        };
        Ok(node)
    }
}
