use std::convert::TryFrom;
use std::ops::{Index, IndexMut};
use tls_codec::{Size, TlsDeserialize, TlsSerialize, TlsSize};

use super::*;

/// NodeIndex is an index to the nodes of a tree, both parent and leaf nodes.
#[derive(
    Debug,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Copy,
    Clone,
    Hash,
    Default,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsSize,
)]
pub struct NodeIndex(u32);

impl NodeIndex {
    pub fn as_u32(self) -> u32 {
        self.0
    }
    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
    pub fn is_leaf(&self) -> bool {
        self.0 % 2 == 0
    }
    pub fn is_parent(&self) -> bool {
        self.0 % 2 == 1
    }
}

impl From<u32> for NodeIndex {
    fn from(i: u32) -> NodeIndex {
        NodeIndex(i)
    }
}

impl From<usize> for NodeIndex {
    fn from(i: usize) -> NodeIndex {
        NodeIndex(i as u32)
    }
}

impl From<LeafIndex> for NodeIndex {
    fn from(node_index: LeafIndex) -> NodeIndex {
        NodeIndex(node_index.as_u32() * 2)
    }
}

/// LeafIndex is an index to the leaves of a tree.
#[derive(
    Debug,
    Default,
    Ord,
    PartialOrd,
    Hash,
    Eq,
    PartialEq,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
pub struct LeafIndex(pub(crate) u32);

impl LeafIndex {
    pub fn as_u32(self) -> u32 {
        self.0
    }
    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl From<u32> for LeafIndex {
    fn from(i: u32) -> LeafIndex {
        LeafIndex(i)
    }
}

impl From<usize> for LeafIndex {
    fn from(i: usize) -> LeafIndex {
        LeafIndex(i as u32)
    }
}

impl From<LeafIndex> for u32 {
    fn from(i: LeafIndex) -> u32 {
        i.as_u32()
    }
}

impl From<LeafIndex> for usize {
    fn from(i: LeafIndex) -> usize {
        i.as_usize()
    }
}

impl TryFrom<NodeIndex> for LeafIndex {
    type Error = &'static str;
    fn try_from(node_index: NodeIndex) -> Result<Self, Self::Error> {
        // A node with an odd index must be a parent node and therefore cannot be
        // converted to a leaf node
        if node_index.is_parent() {
            Err("Cannot convert a parent node index to a leaf node index.")
        } else {
            Ok(LeafIndex((node_index.as_u32() + 1) / 2))
        }
    }
}

// === Implement Index trait to index Vec<Node> with NodeIndex and LeafIndex ===

impl Index<LeafIndex> for Vec<Node> {
    type Output = Node;

    /// This converts a `LeafIndex`, which points to a particular leaf in the
    /// vector of leaves in a tree, to a `NodeIndex`, i.e. it makes it point the
    /// same leaf, but in the array representing the tree as opposed to the one
    /// only containing the leaves.
    fn index(&self, leaf_index: LeafIndex) -> &Self::Output {
        &self[NodeIndex::from(leaf_index).as_usize()]
    }
}

impl IndexMut<LeafIndex> for Vec<Node> {
    fn index_mut(&mut self, leaf_index: LeafIndex) -> &mut Self::Output {
        &mut self[NodeIndex::from(leaf_index).as_usize()]
    }
}

impl Index<NodeIndex> for Vec<Node> {
    type Output = Node;

    fn index(&self, node_index: NodeIndex) -> &Self::Output {
        &self[node_index.as_usize()]
    }
}

impl IndexMut<NodeIndex> for Vec<Node> {
    fn index_mut(&mut self, node_index: NodeIndex) -> &mut Self::Output {
        &mut self[node_index.as_usize()]
    }
}

impl Index<&NodeIndex> for Vec<Node> {
    type Output = Node;

    fn index(&self, node_index: &NodeIndex) -> &Self::Output {
        &self[node_index.as_usize()]
    }
}

impl IndexMut<&NodeIndex> for Vec<Node> {
    fn index_mut(&mut self, node_index: &NodeIndex) -> &mut Self::Output {
        &mut self[node_index.as_usize()]
    }
}
