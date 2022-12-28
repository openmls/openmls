//! This module contains types and methods around the [`Node`] enum. The
//! variants of the enum are `LeafNode` and [`ParentNode`], both of which are
//! defined in the respective [`leaf_node`] and [`parent_node`] submodules.
use serde::{Deserialize, Serialize};

use self::{leaf_node::OpenMlsLeafNode, parent_node::ParentNode};

mod codec;
pub(crate) mod leaf_node;
pub(crate) mod parent_node;

/// Container enum for leaf and parent nodes.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum Node {
    LeafNode(OpenMlsLeafNode),
    ParentNode(ParentNode),
}
