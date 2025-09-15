//! This module contains types and methods around the [`Node`] enum. The
//! variants of the enum are `LeafNode` and [`ParentNode`], both of which are
//! defined in the respective [`leaf_node`] and [`parent_node`] submodules.
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use self::{leaf_node::LeafNodeIn, parent_node::ParentNode};

use super::LeafNode;

mod codec;
pub(crate) mod encryption_keys;
pub(crate) mod leaf_node;
pub(crate) mod parent_node;

/// Container enum for leaf and parent nodes.
///
/// ```c
/// struct {
///     NodeType node_type;
///     select (Node.node_type) {
///         case leaf:   LeafNode leaf_node;
///         case parent: ParentNode parent_node;
///     };
/// } Node;
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsSize, TlsSerialize)]
#[repr(u8)]
pub enum Node {
    /// A leaf node.
    #[tls_codec(discriminant = 1)]
    LeafNode(Box<LeafNode>),
    /// A parent node.
    #[tls_codec(discriminant = 2)]
    ParentNode(Box<ParentNode>),
}

impl Node {
    pub(crate) fn leaf_node(leaf: LeafNode) -> Self {
        Self::LeafNode(Box::new(leaf))
    }

    pub(crate) fn parent_node(parent: ParentNode) -> Self {
        Self::ParentNode(Box::new(parent))
    }
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    TlsSize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
)]
#[repr(u8)]
pub enum NodeIn {
    /// A leaf node.
    #[tls_codec(discriminant = 1)]
    LeafNode(Box<LeafNodeIn>),
    /// A parent node.
    #[tls_codec(discriminant = 2)]
    ParentNode(Box<ParentNode>),
}

impl From<Node> for NodeIn {
    fn from(node: Node) -> Self {
        match node {
            Node::LeafNode(leaf_node) => NodeIn::LeafNode(Box::new((*leaf_node).into())),
            Node::ParentNode(parent_node) => NodeIn::ParentNode(parent_node),
        }
    }
}

// The following `From` implementation breaks abstraction layers and MUST
// NOT be made available outside of tests or "test-utils".
#[cfg(any(feature = "test-utils", test))]
impl From<NodeIn> for Node {
    fn from(node: NodeIn) -> Self {
        match node {
            NodeIn::LeafNode(leaf_node) => Node::LeafNode(Box::new((*leaf_node).into())),
            NodeIn::ParentNode(parent_node) => Node::ParentNode(parent_node),
        }
    }
}

/// Container enum with reference to a node in a tree.
pub(crate) enum NodeReference<'a> {
    Leaf(&'a LeafNode),
    Parent(&'a ParentNode),
}
