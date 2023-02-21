//! This module contains types and methods around the [`Node`] enum. The
//! variants of the enum are `LeafNode` and [`ParentNode`], both of which are
//! defined in the respective [`leaf_node`] and [`parent_node`] submodules.
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use self::{
    leaf_node::{LeafNode, OpenMlsLeafNode},
    parent_node::ParentNode,
};

mod codec;
pub(crate) mod encryption_keys;
pub(crate) mod leaf_node;
pub(crate) mod parent_node;

/// Container enum for leaf and parent nodes.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     NodeType node_type;
///     select (Node.node_type) {
///         case leaf:   LeafNode leaf_node;
///         case parent: ParentNode parent_node;
///     };
/// } Node;
/// ```
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsSize, TlsDeserialize, TlsSerialize,
)]
#[repr(u8)]
pub enum Node {
    /// A leaf node.
    #[tls_codec(discriminant = 1)]
    LeafNode(OpenMlsLeafNode),
    /// A parent node.
    #[tls_codec(discriminant = 2)]
    ParentNode(ParentNode),
}

/// Container enum with reference to a node in a tree.
pub(crate) enum NodeReference<'a> {
    Leaf(&'a OpenMlsLeafNode),
    Parent(&'a ParentNode),
}

#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsSize, TlsDeserialize, TlsSerialize,
)]
#[repr(u8)]
pub(crate) enum RawNode {
    #[tls_codec(discriminant = 1)]
    Leaf(LeafNode),
    Parent(ParentNode),
}

impl From<RawNode> for Node {
    fn from(raw_node: RawNode) -> Self {
        match raw_node {
            RawNode::Leaf(leaf) => Node::LeafNode(leaf.into()),
            RawNode::Parent(parent) => Node::ParentNode(parent),
        }
    }
}
