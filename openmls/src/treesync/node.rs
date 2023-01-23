//! This module contains types and methods around the [`Node`] enum. The
//! variants of the enum are `LeafNode` and [`ParentNode`], both of which are
//! defined in the respective [`leaf_node`] and [`parent_node`] submodules.
use serde::{Deserialize, Serialize};

use self::{leaf_node::OpenMlsLeafNode, parent_node::ParentNode};

mod codec;
pub(crate) mod encryption_keys;
pub(crate) mod leaf_node;
pub(crate) mod parent_node;

/// Container enum for leaf and parent nodes.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
#[allow(clippy::large_enum_variant)]
pub enum Node {
    LeafNode(OpenMlsLeafNode),
    ParentNode(ParentNode),
}

/// Container enum with reference to a node in a tree.
pub(crate) enum NodeReference<'a> {
    Leaf(&'a OpenMlsLeafNode),
    Parent(&'a ParentNode),
}
