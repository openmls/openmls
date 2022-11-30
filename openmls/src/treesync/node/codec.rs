use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

use crate::ciphersuite::HpkePublicKey;

use super::{leaf_node::OpenMlsLeafNode, parent_node::ParentNode, Node};

/// Node type. Can be either `Leaf` or `Parent`.
#[derive(PartialEq, Clone, Copy, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
enum MlsNodeType {
    Leaf = 1,
    Parent = 2,
}

impl tls_codec::Size for Node {
    fn tls_serialized_len(&self) -> usize {
        1 // Length of MlsNodeType
            + match self {
                Node::LeafNode(kp) => kp.tls_serialized_len(),
                Node::ParentNode(n) => n.tls_serialized_len(),
            }
    }
}

// Implementations for `Node`

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
            MlsNodeType::Leaf => Node::LeafNode(OpenMlsLeafNode::tls_deserialize(bytes)?),
            MlsNodeType::Parent => Node::ParentNode(ParentNode::tls_deserialize(bytes)?),
        };
        Ok(node)
    }
}

// Implementations for `ParentNode`

impl tls_codec::Size for ParentNode {
    fn tls_serialized_len(&self) -> usize {
        self.public_key().tls_serialized_len()
            + self.parent_hash.tls_serialized_len()
            + self.unmerged_leaves.tls_serialized_len()
    }
}

impl tls_codec::Size for &ParentNode {
    fn tls_serialized_len(&self) -> usize {
        (*self).tls_serialized_len()
    }
}

impl tls_codec::Serialize for &ParentNode {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.public_key().tls_serialize(writer)?;
        written += self.parent_hash.tls_serialize(writer)?;
        self.unmerged_leaves
            .tls_serialize(writer)
            .map(|l| l + written)
    }
}

impl tls_codec::Deserialize for ParentNode {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let public_key = HpkePublicKey::tls_deserialize(bytes)?;
        let parent_hash = VLBytes::tls_deserialize(bytes)?;
        let unmerged_leaves = Vec::tls_deserialize(bytes)?;
        Ok(Self::new(public_key, parent_hash, unmerged_leaves))
    }
}
