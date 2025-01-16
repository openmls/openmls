//! A binary tree implementation for use with MLS.
//!
//! # About
//!
//! This module contains an implementation of a binary tree based on an array
//! representation. The main [`ABinaryTree`] struct is generally immutable, but
//! allows the creation of an [`AbDiff`] struct, where changes can be made before
//! merging it back into an existing tree.

use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    diff::{AbDiff, StagedAbDiff},
    treemath::{common_direct_path, LeafNodeIndex, ParentNodeIndex, TreeSize, MAX_TREE_SIZE},
};

#[derive(Clone, Debug)]
pub(crate) enum TreeNode<L, P>
where
    L: Clone + Debug + Default,
    P: Clone + Debug + Default,
{
    Leaf(L),
    Parent(P),
}

#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq))]
#[derive(Clone, Debug, Serialize, Deserialize)]
/// A representation of a full, left-balanced binary tree that uses a simple
/// vector to store nodes. Each tree has to consist of at least one node.
pub(crate) struct ABinaryTree<L: Clone + Debug + Default, P: Clone + Debug + Default> {
    leaf_nodes: Vec<L>,
    parent_nodes: Vec<P>,
    default_leaf: L,
    default_parent: P,
}

impl<L: Clone + Debug + Default, P: Clone + Debug + Default> ABinaryTree<L, P> {
    /// Create a tree from the given vector of nodes. The vector of nodes can't
    /// be empty and has to yield a full, left-balanced binary tree. The nodes
    /// in the tree are ordered in the array-representation. This function
    /// throws a [`ABinaryTreeError::InvalidNumberOfNodes`] error if the number
    /// of nodes does not allow the creation of a full, left-balanced binary
    /// tree and an [`ABinaryTreeError::OutOfRange`] error if the number of
    /// given nodes exceeds the range of [`TreeNodeIndex`].
    pub(crate) fn new(nodes: Vec<TreeNode<L, P>>) -> Result<Self, ABinaryTreeError> {
        // No more than 2^30 nodes
        if nodes.len() > MAX_TREE_SIZE as usize {
            return Err(ABinaryTreeError::OutOfRange);
        }
        if nodes.len() % 2 != 1 {
            return Err(ABinaryTreeError::InvalidNumberOfNodes);
        }
        let mut leaf_nodes = Vec::new();
        let mut parent_nodes = Vec::new();

        // Split the nodes intow two vectors, one for the leaf nodes and one for
        // the parent nodes.
        for (i, node) in nodes.into_iter().enumerate() {
            match node {
                TreeNode::Leaf(l) => {
                    if i % 2 == 0 {
                        leaf_nodes.push(l)
                    } else {
                        return Err(ABinaryTreeError::WrongNodeType);
                    }
                }
                TreeNode::Parent(p) => {
                    if i % 2 == 1 {
                        parent_nodes.push(p)
                    } else {
                        return Err(ABinaryTreeError::WrongNodeType);
                    }
                }
            }
        }

        Ok(ABinaryTree {
            leaf_nodes,
            parent_nodes,
            default_leaf: L::default(),
            default_parent: P::default(),
        })
    }

    /// Obtain a reference to the data contained in the leaf node at index
    /// `leaf_index`, where the indexing corresponds to the array representation
    /// of the underlying binary tree. Returns the default value if the node
    /// cannot be found.
    pub(in crate::binary_tree) fn leaf_by_index(&self, leaf_index: LeafNodeIndex) -> &L {
        self.leaf_nodes
            .get(leaf_index.usize())
            .unwrap_or(&self.default_leaf)
    }

    /// Obtain a reference to the data contained in the parent node at index
    /// `parent_index`, where the indexing corresponds to the array
    /// representation of the underlying binary tree. Returns the default value
    /// if the node cannot be found.
    pub(crate) fn parent_by_index(&self, parent_index: ParentNodeIndex) -> &P {
        self.parent_nodes
            .get(parent_index.usize())
            .unwrap_or(&self.default_parent)
    }

    /// Return the number of nodes in the tree.
    pub(crate) fn tree_size(&self) -> TreeSize {
        // We can cast the size to a u32, because the maximum size of a
        // tree is 2^30.
        TreeSize::new((self.leaf_nodes.len() + self.parent_nodes.len()) as u32)
    }

    /// Return the number of leaf nodes in the tree.
    pub(crate) fn leaf_count(&self) -> u32 {
        // This works, because the tree always has at least one leaf.
        self.leaf_nodes.len() as u32
    }

    /// Return the number of parent nodes in the tree.
    pub(crate) fn parent_count(&self) -> u32 {
        // This works, because the tree always has at least one leaf.
        self.parent_nodes.len() as u32
    }

    /// Returns an iterator over a tuple of the leaf index and a reference to a
    /// leaf, sorted according to their position in the tree from left to right.
    pub(crate) fn leaves(&self) -> impl Iterator<Item = (LeafNodeIndex, &L)> {
        self.leaf_nodes
            .iter()
            .enumerate()
            .map(|(index, leave)| (LeafNodeIndex::new(index as u32), leave))
    }

    /// Returns an iterator over a tuple of the parent index and a reference to
    /// a parent, sorted according to their position in the tree from left to
    /// right.
    pub(crate) fn parents(&self) -> impl Iterator<Item = (ParentNodeIndex, &P)> {
        self.parent_nodes
            .iter()
            .enumerate()
            .map(|(index, leave)| (ParentNodeIndex::new(index as u32), leave))
    }

    /// Creates and returns an empty [`AbDiff`].
    pub(crate) fn empty_diff(&self) -> AbDiff<'_, L, P> {
        self.into()
    }

    /// Merges the changes applied to the [`StagedAbDiff`] into the tree.
    /// Depending on the changes made to the diff, this can either increase or
    /// decrease the size of the tree, although not beyond the minimum size of
    /// leaf or the maximum size of `u32::MAX`.
    pub(crate) fn merge_diff(&mut self, diff: StagedAbDiff<L, P>) {
        let tree_size = diff.tree_size();

        let (leaf_diff, parent_diff) = diff.into_diffs();

        // Resize the tree to the new size.
        self.leaf_nodes
            .resize_with(tree_size.leaf_count() as usize, Default::default);
        self.parent_nodes
            .resize_with(tree_size.parent_count() as usize, Default::default);

        // Merge leaves
        // Iterate over the BTreeMap in order of indices.
        for (leaf_index, diff_leaf) in leaf_diff.into_iter() {
            // Assert that the node index is within the range of the tree.
            debug_assert!(leaf_index.u32() < self.leaf_count());

            match self.leaf_nodes.get_mut(leaf_index.usize()) {
                Some(n) => *n = diff_leaf,
                None => {
                    // Panic in debug mode
                    debug_assert!(false);
                }
            }
        }

        // Merge parents
        // Iterate over the BTreeMap in order of indices.
        for (parent_index, diff_parent) in parent_diff.into_iter() {
            // Assert that the node index is within the range of the tree.
            debug_assert!(parent_index.u32() < self.parent_count());

            match self.parent_nodes.get_mut(parent_index.usize()) {
                Some(n) => *n = diff_parent,
                None => {
                    // Panic in debug mode
                    debug_assert!(false);
                }
            }
        }
    }

    /// Return a reference to the leaf at the given `LeafNodeIndex`, or the default
    /// value if the leaf is not found.
    pub(crate) fn leaf(&self, leaf_index: LeafNodeIndex) -> &L {
        self.leaf_nodes
            .get(leaf_index.usize())
            .unwrap_or(&self.default_leaf)
    }

    /// Returns a vector of [`ParentNodeIndex`]es, where the first reference is to
    /// the root of the shared subtree of the two given leaf indices followed by
    /// references to the nodes in the direct path of said subtree root.
    pub(crate) fn subtree_path(
        &self,
        leaf_index_1: LeafNodeIndex,
        leaf_index_2: LeafNodeIndex,
    ) -> Vec<ParentNodeIndex> {
        common_direct_path(leaf_index_1, leaf_index_2, self.tree_size())
    }

    pub(crate) fn parent(&self, parent_index: ParentNodeIndex) -> &P {
        self.parent_nodes
            .get(parent_index.usize())
            .unwrap_or(&self.default_parent)
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
    /// Wrong node type.
    #[error("Wrong node type.")]
    WrongNodeType,
}
