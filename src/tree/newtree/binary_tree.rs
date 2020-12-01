use crate::tree::index::NodeIndex;

/// A binary tree in the array (vector) representation used in the MLS spec.
/// Note, that this is not a full implementation of a binary tree, but rather
/// only enables the operations needed by MLS.
pub(crate) struct BinaryTree<T> {
    pub(crate) nodes: Vec<T>,
}

impl<T> From<Vec<T>> for BinaryTree<T> {
    fn from(nodes: Vec<T>) -> Self {
        BinaryTree { nodes }
    }
}

#[allow(unused_variables, dead_code)]
impl<T> BinaryTree<T> {
    /// Create a new, empty binary tree.
    pub(crate) fn new() -> Self {
        BinaryTree { nodes: Vec::new() }
    }

    /// Extend the tree by one leaf on the right.
    pub(crate) fn add(&mut self, node: T) {
        unimplemented!()
    }

    /// Replace the node at index `index`, consuming the new node and returning
    /// the old one.
    pub(crate) fn replace(&mut self, index: NodeIndex) -> T {
        unimplemented!()
    }

    /// Remove the rightmost leaf.
    pub(crate) fn pop_leaf(&mut self) -> T {
        unimplemented!()
    }

    /// Get the size of the tree.
    pub(crate) fn size(&self) -> usize {
        self.nodes.len()
    }

    // Probably a few more functions to manipulate the `BinaryTree`.
}
