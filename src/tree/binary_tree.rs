use crate::{prelude::LeafIndex, tree::index::NodeIndex};

use super::TreeError;

/// A binary tree in the array (vector) representation used in the MLS spec.
/// Note, that this is not a full implementation of a binary tree, but rather
/// only enables the operations needed by MLS.
#[derive(Debug, Clone)]
pub struct BinaryTree<T> {
    pub(crate) nodes: Vec<T>,
}

impl<T> From<Vec<T>> for BinaryTree<T> {
    fn from(nodes: Vec<T>) -> Self {
        BinaryTree { nodes }
    }
}

impl<T> BinaryTree<T> {
    fn check_if_within_bounds(&self, node_index: &NodeIndex) -> Result<(), TreeError> {
        if node_index >= &self.size() {
            return Err(TreeError::InvalidArguments);
        };
        Ok(())
    }

    /// Extend the tree by the given nodes on the right.
    pub(crate) fn add(&mut self, nodes: Vec<T>) {
        self.nodes.extend(nodes)
    }

    /// Extend the tree by the given nodes on the right.
    pub(crate) fn truncate(&mut self, new_length: usize) {
        self.nodes.truncate(new_length)
    }

    /// Replace the node at index `index`, consuming the new node and returning
    /// the old one.
    pub(crate) fn replace(&mut self, node_index: NodeIndex, node: T) -> Result<T, TreeError> {
        self.check_if_within_bounds(&node_index)?;
        self.nodes.push(node);
        Ok(self.nodes.swap_remove(node_index.as_usize()))
    }

    /// Get the size of the tree.
    pub(crate) fn size(&self) -> NodeIndex {
        NodeIndex::from(self.nodes.len())
    }

    /// Get a reference to a node of the tree by index.
    pub(crate) fn node(&self, node_index: &NodeIndex) -> Result<&T, TreeError> {
        self.check_if_within_bounds(node_index)?;
        Ok(&self.nodes[node_index])
    }

    /// Get a mutable reference to a node of the tree by index.
    pub(crate) fn node_mut(&mut self, node_index: &NodeIndex) -> Result<&mut T, TreeError> {
        self.check_if_within_bounds(node_index)?;
        Ok(&mut self.nodes[node_index])
    }

    pub(crate) fn leaf(&self, leaf_index: &LeafIndex) -> Result<&T, TreeError> {
        self.node(&NodeIndex::from(leaf_index.clone()))
    }

    // Probably a few more functions to manipulate the `BinaryTree`.
}
