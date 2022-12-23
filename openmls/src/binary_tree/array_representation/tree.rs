//! A binary tree implementation for use with MLS.
//!
//! # About
//!
//! This module contains an implementation of a binary tree based on an array
//! representation. The main [`ABinaryTree`] struct is generally immutable, but
//! allows the creation of an [`AbDiff`] struct, where changes can be made before
//! merging it back into an existing tree.

use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt::Debug};
use thiserror::Error;

use super::{
    diff::{AbDiff, StagedAbDiff},
    treemath::{LeafNodeIndex, TreeNodeIndex, TreeSize},
};

#[cfg_attr(test, derive(PartialEq))]
#[derive(Clone, Debug, Serialize, Deserialize)]
/// A representation of a full, left-balanced binary tree that uses a simple
/// vector to store nodes. Each tree has to consist of at least one node.
pub(crate) struct ABinaryTree<T: Clone + Debug + Default> {
    nodes: Vec<T>,
    default: T,
}

impl<T: Clone + Debug + Default> TryFrom<Vec<T>> for ABinaryTree<T> {
    type Error = ABinaryTreeError;

    fn try_from(nodes: Vec<T>) -> Result<Self, Self::Error> {
        Self::new(nodes)
    }
}

impl<T: Clone + Debug + Default> ABinaryTree<T> {
    /// Create a tree from the given vector of nodes. The vector of nodes can't
    /// be empty and has to yield a full, left-balanced binary tree. The nodes
    /// in the tree are ordered in the array-representation. This function
    /// throws a [`ABinaryTreeError::InvalidNumberOfNodes`] error if the number
    /// of nodes does not allow the creation of a full, left-balanced binary
    /// tree and an [`ABinaryTreeError::OutOfRange`] error if the number of
    /// given nodes exceeds the range of [`TreeNodeIndex`].
    pub(crate) fn new(nodes: Vec<T>) -> Result<Self, ABinaryTreeError> {
        // No more than 2^32 nodes
        if nodes.len() > u32::MAX as usize {
            return Err(ABinaryTreeError::OutOfRange);
        }
        if nodes.len() % 2 != 1 {
            return Err(ABinaryTreeError::InvalidNumberOfNodes);
        }
        Ok(ABinaryTree {
            nodes,
            default: T::default(),
        })
    }

    /// Obtain a reference to the data contained in the node at index
    /// `node_index`, where the indexing corresponds to the array representation
    /// of the underlying binary tree. Returns the default value if the node
    /// cannot be found.
    pub(in crate::binary_tree) fn node_by_index(&self, node_index: TreeNodeIndex) -> &T {
        debug_assert!(self.nodes.get(node_index.usize()).is_some());
        self.nodes.get(node_index.usize()).unwrap_or(&self.default)
    }

    /// Return the number of nodes in the tree.
    pub(crate) fn size(&self) -> TreeSize {
        // We can cast the size to a u32, because the maximum size of a
        // tree is 2^32.
        TreeSize::new(self.nodes.len() as u32)
    }

    /// Return the number of leaves in the tree.
    pub(crate) fn leaf_count(&self) -> u32 {
        // This works, because the tree always has at least one leaf.
        ((self.size().u32() - 1) / 2) + 1
    }

    /// Returns an iterator over a tuple of the node index and a reference to a
    /// node, sorted according to their position in the tree from left to right.
    pub(crate) fn nodes(&self) -> impl Iterator<Item = (TreeNodeIndex, &T)> {
        self.nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (TreeNodeIndex::new(index as u32), node))
    }

    /// Returns an iterator over a tuple of the leaf index and a reference to a
    /// leaf, sorted according to their position in the tree from left to right.
    pub(crate) fn leaves(&self) -> impl Iterator<Item = (LeafNodeIndex, &T)> {
        self.nodes
            .iter()
            .enumerate()
            // Only return the leaves, which are at the even indices
            .filter_map(|(index, leave)| {
                if index % 2 == 0 {
                    Some((LeafNodeIndex::new((index / 2) as u32), leave))
                } else {
                    None
                }
            })
    }

    /// Creates and returns an empty [`AbDiff`].
    pub(crate) fn empty_diff(&self) -> AbDiff<'_, T> {
        self.into()
    }

    /// Merges the changes applied to the [`StagedAbDiff`] into the tree.
    /// Depending on the changes made to the diff, this can either increase or
    /// decrease the size of the tree, although not beyond the minimum size of
    /// leaf or the maximum size of `u32::MAX`.
    pub(crate) fn merge_diff(&mut self, diff: StagedAbDiff<T>) {
        // If the size of the diff is smaller than the tree, truncate the tree
        // to the size of the diff.
        self.nodes.truncate(diff.tree_size().usize());

        // Iterate over the BTreeMap in order of indices.
        for (node_index, diff_node) in diff.diff().into_iter() {
            // Assert that the node index is within the range of the tree.
            debug_assert!(node_index.u32() <= self.size().u32());

            // If the node would extend the tree, push it to the vector of nodes.
            if node_index.u32() == self.size().u32() {
                self.nodes.push(diff_node);
            } else {
                // If the node_index points to somewhere within the size of the
                // tree, do a swap-remove.
                // Perform swap-remove.
                match self.nodes.get_mut(node_index.usize()) {
                    Some(n) => *n = diff_node,
                    None => {
                        // Panic in debug mode
                        debug_assert!(false);
                    }
                }
            }
        }
    }

    /// Return a reference to the leaf at the given `LeafNodeIndex`, or the default
    /// value if the leaf is not found.
    pub(crate) fn leaf(&self, leaf_index: LeafNodeIndex) -> &T {
        self.nodes
            .get(leaf_index.to_tree_index() as usize)
            .unwrap_or(&self.default)
    }
}

/// Binary Tree error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum ABinaryTreeError {
    /// Adding nodes exceeds the maximum possible size of the tree.
    #[error("Adding nodes exceeds the maximum possible size of the tree.")]
    OutOfRange,
    /// Not enough nodes to remove.
    #[error("Not enough nodes to remove.")]
    InvalidNumberOfNodes,
}
