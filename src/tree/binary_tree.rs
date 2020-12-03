use crate::{prelude::LeafIndex, tree::index::NodeIndex};

use super::TreeError;

/// A binary tree in the array (vector) representation used in the MLS spec.
/// Note, that this is not a full implementation of a binary tree, but rather
/// only enables the operations needed by MLS.
#[derive(Debug, Clone)]
pub(crate) struct BinaryTree<T> {
    pub(crate) nodes: Vec<T>,
}

impl<T> From<Vec<T>> for BinaryTree<T> {
    fn from(nodes: Vec<T>) -> Self {
        BinaryTree { nodes }
    }
}

impl<T> BinaryTree<T> {
    fn check_if_within_bounds(&self, node_index: &NodeIndex) -> Result<(), TreeError> {
        if node_index < &self.size() {
            return Err(TreeError::InvalidArguments);
        };
        Ok(())
    }

    /// Create a new, empty binary tree.
    pub(crate) fn new() -> Self {
        BinaryTree { nodes: Vec::new() }
    }

    pub(crate) fn leaf_count(&self) -> LeafIndex {
        self.size().into()
    }

    /// Extend the tree by the given leaves on the right.
    pub(crate) fn add(&mut self, nodes: &[T]) {
        let num_new_nodes = nodes.len();
        let mut added_nodes: Vec<T> = Vec::with_capacity(num_new_nodes);

        if num_new_nodes > (2 * self.leaf_count().as_usize()) {
            self.nodes
                .reserve_exact(2 * ((num_new_nodes) - (self.leaf_count().as_usize())));
        }

        let mut leaf_index = self.size().as_usize() + 1;
        for node in nodes.iter() {
            added_nodes.extend(vec![
                Node::new_blank_parent_node(),
                Node::new_leaf(Some((*add_proposal).clone())),
            ]);
            let node_index = NodeIndex::from(leaf_index);
            added_members.push((node_index, add_proposal.credential().clone()));
            leaf_index += 2;
        }
        self.public_tree.extend(new_nodes);
        self.trim_tree();
        added_members
    }

    /// Replace the node at index `index`, consuming the new node and returning
    /// the old one.
    pub(crate) fn replace(&mut self, node_index: NodeIndex, node: T) -> Result<T, TreeError> {
        self.check_if_within_bounds(&node_index)?;
        self.nodes.push(node);
        Ok(self.nodes.swap_remove(node_index.as_usize()))
    }

    /// Remove the rightmost leaf.
    pub(crate) fn pop_leaf(&mut self) -> T {
        unimplemented!()
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
        // Check if index is within bounds.
        if node_index < &self.size() {
            return Err(TreeError::InvalidArguments);
        }
        Ok(&mut self.nodes[node_index])
    }

    pub(crate) fn leaf(&self, leaf_index: &LeafIndex) -> Result<&T, TreeError> {
        self.node(&NodeIndex::from(leaf_index.clone()))
    }

    // Probably a few more functions to manipulate the `BinaryTree`.
}
