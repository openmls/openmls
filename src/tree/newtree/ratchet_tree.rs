use crate::tree::index::NodeIndex;

use super::binary_tree::BinaryTree;
use super::node::Node;

/// The `RatchetTree` is a wrapper around a `BinaryTree` that allows us to
/// perform a few MLS-specific operations on the tree.
pub(crate) struct RatchetTree {
    tree: BinaryTree<Node>,
}

#[allow(dead_code)]
impl RatchetTree {
    /// Trim the `RatchetTree`
    fn trim(&mut self) {
        unimplemented!()
    }

    /// Blank the node with index `index`.
    #[allow(unused_variables)]
    fn blank_member(&mut self, index: NodeIndex) {
        unimplemented!()
    }

    fn free_leaves(&self) -> Vec<NodeIndex> {
        unimplemented!()
    }

    /// Get the size of the tree.
    pub(crate) fn size(&self) -> usize {
        self.tree.size()
    }

    // Probably a few more helper functions.
}
