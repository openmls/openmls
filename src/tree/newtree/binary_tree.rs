use crate::tree::index::NodeIndex;

/// A binary tree in the array (vector) representation used in the MLS spec.
/// Note, that this is not a full implementation of a binary tree, but rather
/// only enables the operations needed by MLS.
pub(crate) struct BinaryTree<T> {
    tree: Vec<T>,
}

impl<T> BinaryTree<T> {
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
}
