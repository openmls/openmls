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

use super::diff::{AbDiff, StagedAbDiff};

use crate::binary_tree::{LeafIndex, TreeSize};

/// The [`NodeIndex`] is used to index nodes.
pub(in crate::binary_tree) type NodeIndex = u32;

/// Given a [`LeafIndex`], compute the position of the corresponding [`NodeIndex`].
pub(super) fn to_node_index(leaf_index: LeafIndex) -> NodeIndex {
    leaf_index * 2
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Clone, Debug, Serialize, Deserialize)]
/// A representation of a full, left-balanced binary tree that uses a simple
/// vector to store nodes. Each tree has to consist of at least one node.
pub(crate) struct ABinaryTree<T: Clone + Debug> {
    nodes: Vec<T>,
}

impl<T: Clone + Debug> TryFrom<Vec<T>> for ABinaryTree<T> {
    type Error = ABinaryTreeError;

    fn try_from(nodes: Vec<T>) -> Result<Self, Self::Error> {
        Self::new(nodes)
    }
}

impl<T: Clone + Debug> ABinaryTree<T> {
    /// Create a tree from the given vector of nodes. The vector of nodes can't
    /// be empty and has to yield a full, left-balanced binary tree. The nodes
    /// in the tree are ordered in the array-representation. This function
    /// throws a [`ABinaryTreeError::InvalidNumberOfNodes`] error if the number of nodes does not
    /// allow the creation of a full, left-balanced binary tree and an
    /// [`ABinaryTreeError::OutOfRange`] error if the number of given nodes exceeds the range of
    /// [`NodeIndex`].
    pub(crate) fn new(nodes: Vec<T>) -> Result<Self, ABinaryTreeError> {
        // No more than 2^32 nodes
        if nodes.len() > u32::MAX as usize {
            return Err(ABinaryTreeError::OutOfRange);
        }
        if nodes.len() % 2 != 1 {
            return Err(ABinaryTreeError::InvalidNumberOfNodes);
        }
        Ok(ABinaryTree { nodes })
    }

    /// Obtain a reference to the data contained in the node at index
    /// `node_index`, where the indexing corresponds to the array representation
    /// of the underlying binary tree. Returns [`ABinaryTreeError::OutOfBounds`]
    /// if the index is larger than the size of the tree.
    pub(in crate::binary_tree) fn node_by_index(
        &self,
        node_index: NodeIndex,
    ) -> Result<&T, ABinaryTreeError> {
        self.nodes
            .get(node_index as usize)
            .ok_or(ABinaryTreeError::OutOfBounds)
    }

    /// Return the number of nodes in the tree.
    pub(in crate::binary_tree) fn size(&self) -> NodeIndex {
        // We can cast the size to a NodeIndex, because the maximum size of a
        // tree is 2^32.
        self.nodes.len() as NodeIndex
    }

    /// Return the number of leaves in the tree.
    pub(crate) fn leaf_count(&self) -> TreeSize {
        // This works, because the tree always has at least one leaf.
        ((self.size() - 1) / 2) + 1
    }

    /// Returns an iterator over a tuple of the leaf index and a reference to a
    /// leaf, sorted according to their position in the tree from left to right.
    pub(crate) fn leaves(&self) -> impl Iterator<Item = (LeafIndex, &T)> {
        self.nodes
            .iter()
            .enumerate()
            // Only return the leaves, which are at the even indices
            .filter_map(|(index, leave)| {
                if index % 2 == 0 {
                    Some(((index / 2) as LeafIndex, leave))
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
        self.nodes.truncate(diff.tree_size() as usize);

        // Iterate over the BTreeMap in order of indices.
        for (node_index, diff_node) in diff.diff().into_iter() {
            // Assert that the node index is within the range of the tree.
            debug_assert!(node_index <= self.size());

            // If the node would extend the tree, push it to the vector of nodes.
            if node_index == self.size() {
                self.nodes.push(diff_node);
            } else {
                // If the node_index points to somewhere within the size of the
                // tree, do a swap-remove.
                // Perform swap-remove.
                self.nodes[node_index as usize] = diff_node;
            }
        }
    }

    /// Export the nodes of the tree in the array representation.
    pub(crate) fn nodes(&self) -> &[T] {
        &self.nodes
    }

    /// Return a reference to the leaf at the given `LeafIndex`.
    ///
    /// Returns an error if the leaf is outside of the tree.
    pub(crate) fn leaf(&self, leaf_index: LeafIndex) -> Result<&T, ABinaryTreeError> {
        self.nodes
            .get(to_node_index(leaf_index) as usize)
            .ok_or(ABinaryTreeError::OutOfBounds)
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
    /// The given index is outside of the tree.
    #[error("The given index is outside of the tree.")]
    OutOfBounds,
}
