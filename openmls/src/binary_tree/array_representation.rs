//! This module contains an implementation of a binary tree based on an array
//! representation.

use super::treemath::*;
use super::NodeIndex;
use super::TreeSize;

#[derive(Clone, Debug, PartialEq)]
/// A representation of a full, left-balanced binary tree that uses a simple
/// vector to store nodes.
pub(crate) struct ABinaryTree<T: Default + Clone> {
    nodes: Vec<T>,
}

impl<T: Default + Clone> ABinaryTree<T> {
    /// Check if a given index is still within the tree.
    pub(crate) fn node_in_tree(&self, node_index: NodeIndex) -> Result<(), ABinaryTreeError> {
        node_in_tree(node_index, self.size()).map_err(|_| ABinaryTreeError::OutOfBounds)
    }
}

impl<T: Default + Clone> ABinaryTree<T> {
    /// Create a tree from the given vector of nodes. The nodes are ordered in
    /// the array-representation. Throws a `InvalidNumberOfNodes` error if the
    /// number of nodes does not allow the creation of a full, left-balanced
    /// binary tree and an `OutOfRange` error if the number of given nodes
    /// exceeds the range of `NodeIndex`.
    pub(crate) fn new(nodes: &[T]) -> Result<Self, ABinaryTreeError> {
        if nodes.len() > NodeIndex::max_value() as usize {
            Err(ABinaryTreeError::OutOfRange)
        } else if nodes.len() % 2 != 1 {
            Err(ABinaryTreeError::InvalidNumberOfNodes)
        } else {
            Ok(ABinaryTree {
                nodes: nodes.to_vec(),
            })
        }
    }

    /// Obtain a reference to the data contained in the `Node` at index
    /// `node_index`, where the indexing corresponds to the array representation
    /// of the underlying binary tree. Returns an error if the index is outside
    /// of the tree.
    pub(crate) fn node(&self, node_index: NodeIndex) -> std::option::Option<&T> {
        self.nodes.get(node_index as usize)
    }

    /// Obtain a mutable reference to the data contained in the `Node` at index
    /// `node_index`, where the indexing corresponds to the array representation
    /// of the underlying binary tree. Returns an error if the index is outside
    /// of the tree.
    pub(crate) fn node_mut(&mut self, node_index: NodeIndex) -> std::option::Option<&mut T> {
        self.nodes.get_mut(node_index as usize)
    }

    /// Adds the given node as a new leaf to right side of the tree. To keep
    /// the tree full, a parent node is added using the `Default` constructor.
    /// Returns an `OutOfRange` error if the number of nodes exceeds the range
    /// of `NodeIndex`.
    pub(crate) fn add_leaf(&mut self, node: T) -> Result<(), ABinaryTreeError> {
        // Prevent the tree from becoming too large.
        if self.nodes.len() > NodeIndex::max_value() as usize - 2 {
            Err(ABinaryTreeError::OutOfRange)
        } else {
            self.nodes.push(T::default());
            self.nodes.push(node);
            Ok(())
        }
    }

    /// Remove the two rightmost nodes of the tree. This will throw a
    /// `NotEnoughNodes` error if there are not enough nodes to remove.
    pub(crate) fn remove(&mut self) -> Result<(), ABinaryTreeError> {
        // Check that there are enough nodes to remove.
        if self.nodes.len() < 2 {
            Err(ABinaryTreeError::NotEnoughNodes)
        } else {
            self.nodes.pop();
            self.nodes.pop();
            Ok(())
        }
    }

    /// Return the number of nodes in the tree.
    pub(crate) fn size(&self) -> NodeIndex {
        let len = self.nodes.len();
        debug_assert!(len <= u32::MAX as usize);
        self.nodes.len() as u32
    }

    /// Return the number of leaves in the tree.
    pub(crate) fn leaf_count(&self) -> TreeSize {
        (self.size() + 1) / 2
    }

    /// Compute the direct path from the node with the given index to the root
    /// node and return the vector of indices of the nodes on the direct path,
    /// where the indexing corresponds to the array representation of the
    /// underlying binary tree.
    pub(crate) fn direct_path(
        &self,
        node_index: NodeIndex,
    ) -> Result<Vec<NodeIndex>, ABinaryTreeError> {
        direct_path(node_index, self.size()).map_err(|_| ABinaryTreeError::OutOfBounds)
    }

    /// Compute the copath path from the node with the given index to the root
    /// node and return the vector of indices of the nodes on the copath, where
    /// the indexing corresponds to the array representation of the underlying
    /// binary tree.
    pub(crate) fn copath(&self, node_index: NodeIndex) -> Result<Vec<NodeIndex>, ABinaryTreeError> {
        copath(node_index, self.size()).map_err(|_| ABinaryTreeError::OutOfBounds)
    }

    /// Compute the lowest common ancestor of the nodes with the given indices,
    /// where the indexing corresponds to the array representation of the
    /// underlying binary tree. Returns an `OutOfBounds` error if either of the
    /// indices is out of the bounds of the tree.
    pub(crate) fn lowest_common_ancestor(
        &self,
        node_index_1: NodeIndex,
        node_index_2: NodeIndex,
    ) -> Result<NodeIndex, ABinaryTreeError> {
        self.node_in_tree(node_index_1)?;
        self.node_in_tree(node_index_2)?;
        Ok(lowest_common_ancestor(node_index_1, node_index_2))
    }
}

implement_error! {
    pub enum ABinaryTreeError {
        OutOfRange = "Adding nodes exceeds the maximum possible size of the tree.",
        NotEnoughNodes = "Not enough nodes to remove.",
        InvalidNumberOfNodes = "The given number of nodes does not allow the creation of a full, left-balanced binary tree.",
        OutOfBounds = "The given index is outside of the tree.",
    }
}
