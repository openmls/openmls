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
