//! An implementation of a diff functionality for the [`ABinaryTree`] struct.
//!
//! # About
//!
//! This module provides the [`AbDiff`] and [`StagedAbDiff`] structs that allow
//! performing changes to an [`ABinaryTree`] instance without immediately applying
//! the them. Instead, the changes can be applied to the diff and the results
//! examined before merging the given diff back into the tree (or not).
//!
//! # Don't Panic!
//!
//! Functions in this module should never panic. However, if there is a bug in
//! the implementation, a function will return an unrecoverable
//! [`LibraryError`](ABinaryTreeDiffError::LibraryError). This means that some
//! functions that are not expected to fail and throw an error, will still
//! return a [`Result`] since they may throw a
//! [`LibraryError`](ABinaryTreeDiffError::LibraryError).

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt::Debug};
use thiserror::Error;

use crate::{binary_tree::TreeSize, error::LibraryError};

use super::{
    sorted_iter::sorted_iter,
    tree::{ABinaryTree, ABinaryTreeError},
    treemath::{
        common_direct_path, direct_path, left, lowest_common_ancestor, right, root, sibling,
        LeafNodeIndex, ParentNodeIndex, TreeNodeIndex,
    },
};

// Crate types

/// The [`StagedAbDiff`] can be created from an [`AbDiff`] instance. It's sole
/// purpose is to be subsequently merged into an existing [`ABinaryTree`]
/// instance. The difference between [`StagedAbDiff`] and an [`AbDiff`] is that a
/// [`StagedAbDiff`] is immutable and does not contain a reference to the original
/// tree. Since it only contains the actual diff without reference to the
/// original content, it can't provide the same information as the [`AbDiff`] it
/// was created from. However, the lack of the internal reference means that its
/// lifetime is not tied to that of the original tree.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StagedAbDiff<T: Clone + Debug + Default> {
    diff: BTreeMap<TreeNodeIndex, T>,
    size: TreeSize,
}

impl<'a, T: Clone + Debug + Default> From<AbDiff<'a, T>> for StagedAbDiff<T> {
    fn from(diff: AbDiff<'a, T>) -> Self {
        StagedAbDiff {
            diff: diff.diff,
            size: diff.size,
        }
    }
}

impl<T: Clone + Debug + Default> StagedAbDiff<T> {
    /// Return the actual diff inside of this StagedAbDiff
    pub(super) fn diff(self) -> BTreeMap<TreeNodeIndex, T> {
        self.diff
    }

    /// Return the projected size of the tree after a merge with the diff.
    pub(super) fn tree_size(&self) -> TreeSize {
        self.size
    }
}

/// The [`AbDiff`] represents a set of differences (i.e. a "Diff") for an
/// [`ABinaryTree`]. It can be created from an [`ABinaryTree`] instance and then
/// accessed mutably or immutably. Any changes are saved by the [`AbDiff`] applied
/// to the original [`ABinaryTree`] instance by converting it to a [`StagedAbDiff`]
/// and subsequently merging it.
pub(crate) struct AbDiff<'a, T: Clone + Debug + Default> {
    original_tree: &'a ABinaryTree<T>,
    diff: BTreeMap<TreeNodeIndex, T>,
    size: TreeSize,
    default: T,
}

impl<'a, T: Clone + Debug + Default> From<&'a ABinaryTree<T>> for AbDiff<'a, T> {
    fn from(tree: &'a ABinaryTree<T>) -> AbDiff<'a, T> {
        AbDiff {
            original_tree: tree,
            diff: BTreeMap::new(),
            size: tree.size(),
            default: T::default(),
        }
    }
}

impl<'a, T: Clone + Debug + Default> AbDiff<'a, T> {
    // Functions handling interactions with leaves.
    ///////////////////////////////////////////////

    /// Extend the diff by a leaf and its new parent node.
    ///
    /// Returns an error if adding either of the two nodes increases the size of
    /// the diff beyond [`u32::MAX`].
    pub(crate) fn add_leaf(
        &mut self,
        parent_node: T,
        new_leaf: T,
    ) -> Result<LeafNodeIndex, ABinaryTreeDiffError> {
        // Prevent the tree from becoming too large.
        if self.size() >= u32::MAX - 1 {
            return Err(ABinaryTreeDiffError::TreeTooLarge);
        }
        let original_size = self.size();
        let previous_parent = self
            .diff
            .insert(TreeNodeIndex::new(original_size), parent_node);
        debug_assert!(previous_parent.is_none());
        let previous_leaf = self
            .diff
            .insert(TreeNodeIndex::new(original_size + 1), new_leaf);
        debug_assert!(previous_leaf.is_none());
        // Increase size
        self.size += 2;
        Ok(LeafNodeIndex::new(self.leaf_count() - 1))
    }

    /// Removes a leaf from the diff. To keep the binary tree (diff) balanced,
    /// this also removes the parent of the leaf.
    ///
    /// Returns an error if the diff only has one leaf left.
    pub(crate) fn remove_leaf(&mut self) -> Result<(), ABinaryTreeDiffError> {
        self.remove_node()?;
        self.remove_node()
    }

    /// Replace the content of the node at the given leaf index with new
    /// content.
    ///
    /// Returns an error if the given leaf index is larger than the leaf count
    /// of the diff.
    pub(crate) fn replace_leaf(&mut self, leaf_index: LeafNodeIndex, new_leaf: T) {
        self.replace_node(leaf_index.into(), new_leaf);
    }

    /// Returns an iterator over a tuple of the leaf index and a reference to a
    /// leaf, sorted according to their position in the tree from left to right.
    pub(crate) fn leaves(&self) -> impl Iterator<Item = (LeafNodeIndex, &T)> {
        let original_leaves = self.original_tree.leaves().peekable();
        let diff_leaves = self
            .diff
            .iter()
            .filter_map(|(index, leaf)| match index {
                TreeNodeIndex::Leaf(leaf_index) => Some((*leaf_index, leaf)),
                TreeNodeIndex::Parent(_) => None,
            })
            .peekable();

        // Combine the original leaves with the leaves from the diff. Since
        // both iterators are sorted, we can just iterate over them and
        // don't need additional sorting. If one of the iterators is
        // exhausted, we just add the remaining leaves from the other
        // iterator. We also make sure that we don't add leaves from the
        // original leaves that are also in the diff.

        // Harmonize the iterator types
        let a_iter = Box::new(diff_leaves) as Box<dyn Iterator<Item = (LeafNodeIndex, &T)>>;
        let b_iter = Box::new(original_leaves) as Box<dyn Iterator<Item = (LeafNodeIndex, &T)>>;

        // We only compare indices, not the actual leaves
        let cmp = |&(x, _): &(LeafNodeIndex, &T)| x;

        sorted_iter(a_iter, b_iter, cmp, self.size as usize)
    }

    // Functions related to the direct paths of leaves
    //////////////////////////////////////////////////

    /// Returns a vector of [`ParentNodeIndex`] instances, each one referencing a
    /// node in the direct path of the given [`LeafNodeIndex`], ordered from the
    /// parent of the corresponding leaf to the root of the tree.
    pub(crate) fn direct_path(&self, leaf_index: LeafNodeIndex) -> Vec<ParentNodeIndex> {
        direct_path(leaf_index, self.size())
    }

    /// Sets all nodes in the direct path to a copy of the given node. This
    /// function will throw an [`ABinaryTreeDiffError::OutOfBounds`] error if
    /// the given index does not correspond to a leaf in the diff.
    pub(crate) fn set_direct_path_to_node(&mut self, leaf_index: LeafNodeIndex, node: &T) {
        let direct_path = self.direct_path(leaf_index);
        for node_index in &direct_path {
            self.replace_node(TreeNodeIndex::Parent(*node_index), node.clone());
        }
    }

    /// Sets the nodes in the direct path of the given leaf index to the nodes
    /// given in the `path`.
    pub(crate) fn set_direct_path(&mut self, leaf_index: LeafNodeIndex, path: Vec<T>) {
        let direct_path = direct_path(leaf_index, self.size());
        debug_assert_eq!(path.len(), direct_path.len());
        for (node_index, node) in direct_path.iter().zip(path.into_iter()) {
            self.replace_node(TreeNodeIndex::Parent(*node_index), node);
        }
    }

    // Functions related to the shared subtree of two given leaves
    //////////////////////////////////////////////////////////////

    /// Given two leaf indices, returns the position of the shared subtree root
    /// in the direct path of the first leaf index.
    ///
    /// Returns an error if both leaf indices are identical or if one of the
    /// leaf indices does not correspond to a leaf in the diff.
    pub(crate) fn subtree_root_position(
        &self,
        leaf_index_1: LeafNodeIndex,
        leaf_index_2: LeafNodeIndex,
    ) -> Result<usize, ABinaryTreeDiffError> {
        // If the given leaf indices are identical, the shared subtree root is
        // the index itself. Since the index of the leaf itself doesn't appear
        // in the direct path, we can't return anything meaningful. This check
        // also ensures that the tree is large enough such that the direct path
        // is never empty, since if there is a second leaf index (that is within
        // the bound of the tree), there is a non-leaf root node that is in the
        // direct path of all leaves.
        debug_assert!(leaf_index_1 != leaf_index_2);
        debug_assert!(leaf_index_1.to_tree_index() < self.size);
        debug_assert!(leaf_index_2.to_tree_index() < self.size);

        let subtree_root_node_index = lowest_common_ancestor(leaf_index_1, leaf_index_2);
        let leaf_index_1_direct_path = self.direct_path(leaf_index_1);

        leaf_index_1_direct_path
            .iter()
            .position(|&direct_path_node_index| direct_path_node_index == subtree_root_node_index)
            // The shared subtree root has to be in the direct path of both nodes.
            .ok_or_else(|| LibraryError::custom("index should be in the direct path").into())
    }

    /// Returns [`TreeNodeIndex`] to the copath node of the `leaf_index_1` that is
    /// in the direct path of `leaf_index_2`.
    pub(crate) fn subtree_root_copath_node(
        &self,
        leaf_index_1: LeafNodeIndex,
        leaf_index_2: LeafNodeIndex,
    ) -> TreeNodeIndex {
        debug_assert!(leaf_index_1 != leaf_index_2);
        debug_assert!(leaf_index_1.to_tree_index() < self.size);
        debug_assert!(leaf_index_2.to_tree_index() < self.size);

        // We want to return the position of the lowest common ancestor in the
        // direct path of `leaf_index_1` (i.e. the sender_leaf_index).
        let subtree_root_node_index = lowest_common_ancestor(leaf_index_1, leaf_index_2);

        // Figure out which child is the relevant copath node.
        if leaf_index_2 < leaf_index_1 {
            left(subtree_root_node_index)
        } else {
            right(subtree_root_node_index, self.size())
        }
    }

    /// Returns a vector of [`ParentNodeIndex`]es, where the first reference is to
    /// the root of the shared subtree of the two given leaf indices followed by
    /// references to the nodes in the direct path of said subtree root.
    pub(crate) fn subtree_path(
        &self,
        leaf_index_1: LeafNodeIndex,
        leaf_index_2: LeafNodeIndex,
    ) -> Vec<ParentNodeIndex> {
        common_direct_path(leaf_index_1, leaf_index_2, self.size())
    }

    // Functions pertaining to the whole diff
    /////////////////////////////////////////

    /// Returns an iterator over a tuple of the node index and a reference to a
    /// node, sorted according to their position in the tree from left to right.
    pub(crate) fn nodes(&self) -> impl Iterator<Item = (TreeNodeIndex, &T)> {
        let original_nodes = self.original_tree.nodes().peekable();
        let diff_nodes = self
            .diff
            .iter()
            .map(|(index, node)| (*index, node))
            .peekable();

        // Combine the original nodes with the nodes from the diff. Since
        // both iterators are sorted, we can just iterate over them and
        // don't need additional sorting. If one of the iterators is
        // exhausted, we just add the remaining nodes from the other
        // iterator. We also make sure that we don't add nodes from the
        // original nodes that are also in the diff.

        // Harmonize the iterator types
        let a_iter = Box::new(diff_nodes) as Box<dyn Iterator<Item = (TreeNodeIndex, &T)>>;
        let b_iter = Box::new(original_nodes) as Box<dyn Iterator<Item = (TreeNodeIndex, &T)>>;

        // We only compare indices, not the actual nodes
        let cmp = |&(x, _): &(TreeNodeIndex, &T)| x;

        sorted_iter(a_iter, b_iter, cmp, self.size as usize)
    }

    /// Returns the leaf count of the diff.
    pub(crate) fn leaf_count(&self) -> u32 {
        ((self.size - 1) / 2) + 1
    }

    /// Returns the size of the diff tree.
    pub(crate) fn size(&self) -> u32 {
        self.size
    }

    // Functions around individual [`TreeNodeIndex`]es
    ///////////////////////////////////////////////

    /// Returns a reference to the node pointed to by the [`TreeNodeIndex`].
    /// Returns an Error if the [`TreeNodeIndex`] points to a node outside of the
    /// bounds of the tree. This can happen, for example, if the node was
    /// removed while shrinking the diff after the creation of the
    /// [`TreeNodeIndex`].
    pub(crate) fn node(&self, node_index: TreeNodeIndex) -> &T {
        self.node_by_index(node_index)
    }

    /// Returns a mutable reference to the node pointed to by the
    /// [`TreeNodeIndex`]. Returns an Error if the [`TreeNodeIndex`] points to a
    /// node outside of the bounds of the tree. This can happen, for example, if
    /// the node was removed while shrinking the diff after the creation of the
    /// [`TreeNodeIndex`].
    pub(crate) fn node_mut(&mut self, node_index: TreeNodeIndex) -> &mut T {
        self.node_mut_by_index(node_index)
    }

    /// Return a [`TreeNodeIndex`] to the root node of the diff. Since the diff
    /// always consists of at least one node, this operation cannot fail.
    pub(crate) fn root(&self) -> TreeNodeIndex {
        root(self.size())
    }

    /// Returns a [`TreeNodeIndex`] to the sibling of the referenced node. Returns
    /// an error when the given [`TreeNodeIndex`] points to the root node or to a
    /// node not in the tree.
    pub(crate) fn sibling(&self, node_index: TreeNodeIndex) -> TreeNodeIndex {
        sibling(node_index, self.size())
    }

    /// Returns a [`TreeNodeIndex`] to the left child of the referenced node.
    /// Returns an error when the given [`TreeNodeIndex`] points to a leaf node or
    /// to a node not in the tree.
    pub(crate) fn left_child(&self, node_index: ParentNodeIndex) -> TreeNodeIndex {
        left(node_index)
    }

    /// Returns a [`TreeNodeIndex`] to the right child of the referenced node.
    /// Returns an error when the given [`TreeNodeIndex`] points to a leaf node or
    /// to a node not in the tree.
    pub(crate) fn right_child(&self, node_index: ParentNodeIndex) -> TreeNodeIndex {
        right(node_index, self.size())
    }

    // Private helper functions below.
    //////////////////////////////////

    // Node access functions

    /// Returns a reference to the node at index `node_index`.
    fn node_by_index(&self, node_index: TreeNodeIndex) -> &T {
        // Check if it's in the diff.
        if let Some(node) = self.diff.get(&node_index) {
            return node;
        }
        // If it isn't in the diff, it must be in the tree.
        self.original_tree.node_by_index(node_index)
    }

    /// Returns a mutable reference to the node in the diff at index
    /// `node_index`. If the diff doesn't have a node at that index, it clones
    /// the node to the diff and returns a mutable reference to that node.
    fn node_mut_by_index(&mut self, node_index: TreeNodeIndex) -> &mut T {
        // We then check if the node is already in the diff. (Not using `if let
        // ...` here, because the borrow checker doesn't like that).
        if self.diff.contains_key(&node_index) {
            return self
                .diff
                .get_mut(&node_index)
                // We just checked that this index exists, so this must be Some.
                .unwrap_or(&mut self.default);
            // If not, we take a copy from the original tree and put it in the
            // diff before returning a mutable reference to it.
        }
        let tree_node = self.original_tree.node_by_index(node_index);
        self.replace_node(node_index, tree_node.clone());
        self.diff
            .get_mut(&node_index)
            // We just inserted this into the diff, so this should be Some.
            .unwrap_or(&mut self.default)
    }

    // Helper functions for node addition and removal

    /// This function is used to place a node at the given index such that any
    /// previous node in the tree at the same position is replaced upon merging
    /// the diff. This function also overrides any previously made changes to
    /// that node as part of modifying this diff.
    fn replace_node(&mut self, node_index: TreeNodeIndex, node: T) {
        self.diff.insert(node_index, node);
    }

    /// Removes a node from the right edge of the diff, thus decreasing the size
    /// of the diff by one. Throws an error if this would make the diff too
    /// small (i.e. < 1 node).
    fn remove_node(&mut self) -> Result<(), ABinaryTreeDiffError> {
        // First make sure that the tree isn't getting too small.
        if self.size() <= 1 {
            return Err(ABinaryTreeDiffError::TreeTooSmall);
        }
        let removed = self.diff.remove(&TreeNodeIndex::new(&self.size() - 1));
        if self.size() > self.original_tree.size() {
            // If the diff extended the tree, there should be a node to remove
            // here.
            debug_assert!(removed.is_some());
        }
        // There should be a node here to remove.
        // We decrease the size to signal that a node was removed from the diff.
        self.size -= 1;
        Ok(())
    }

    // Index checking

    #[cfg(test)]
    pub(crate) fn deref_vec(
        &self,
        node_index_vec: Vec<TreeNodeIndex>,
    ) -> Result<Vec<&T>, ABinaryTreeDiffError> {
        let mut node_vec = Vec::new();
        for node_index in node_index_vec {
            let node = self.node(node_index);
            node_vec.push(node);
        }
        Ok(node_vec)
    }
}

/// Binary Tree Diff error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum ABinaryTreeDiffError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Maximum tree size reached.
    #[error("Maximum tree size reached.")]
    TreeTooLarge,
    /// Minimum tree size reached.
    #[error("Minimum tree size reached.")]
    TreeTooSmall,
    /// Error while executing folding function.
    #[error("Error while executing folding function.")]
    FoldingError,
    /// See [`ABinaryTreeError`] for more details.
    #[error(transparent)]
    ABinaryTreeError(#[from] ABinaryTreeError),
}
