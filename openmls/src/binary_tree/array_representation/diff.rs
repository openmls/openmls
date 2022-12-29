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

use crate::{binary_tree::array_representation::treemath::MAX_TREE_SIZE, error::LibraryError};

use super::{
    sorted_iter::sorted_iter,
    tree::{ABinaryTree, ABinaryTreeError, TreeNode},
    treemath::{
        common_direct_path, copath, direct_path, left, lowest_common_ancestor, right, root,
        LeafNodeIndex, ParentNodeIndex, TreeNodeIndex, TreeSize,
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
pub(crate) struct StagedAbDiff<L: Clone + Debug + Default, P: Clone + Debug + Default> {
    leaf_diff: BTreeMap<LeafNodeIndex, L>,
    parent_diff: BTreeMap<ParentNodeIndex, P>,
    size: TreeSize,
}

impl<'a, L: Clone + Debug + Default, P: Clone + Debug + Default> From<AbDiff<'a, L, P>>
    for StagedAbDiff<L, P>
{
    fn from(diff: AbDiff<'a, L, P>) -> Self {
        StagedAbDiff {
            leaf_diff: diff.leaf_diff,
            parent_diff: diff.parent_diff,
            size: diff.size,
        }
    }
}

impl<L: Clone + Debug + Default, P: Clone + Debug + Default> StagedAbDiff<L, P> {
    /// Return the leaf and parent diffs as a tuple.
    pub(super) fn into_diffs(self) -> (BTreeMap<LeafNodeIndex, L>, BTreeMap<ParentNodeIndex, P>) {
        (self.leaf_diff, self.parent_diff)
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
pub(crate) struct AbDiff<'a, L: Clone + Debug + Default, P: Clone + Debug + Default> {
    original_tree: &'a ABinaryTree<L, P>,
    leaf_diff: BTreeMap<LeafNodeIndex, L>,
    parent_diff: BTreeMap<ParentNodeIndex, P>,
    size: TreeSize,
    default_leaf: L,
    default_parent: P,
}

impl<'a, L: Clone + Debug + Default, P: Clone + Debug + Default> From<&'a ABinaryTree<L, P>>
    for AbDiff<'a, L, P>
{
    fn from(tree: &'a ABinaryTree<L, P>) -> AbDiff<'a, L, P> {
        AbDiff {
            original_tree: tree,
            leaf_diff: BTreeMap::new(),
            parent_diff: BTreeMap::new(),
            size: tree.size(),
            default_leaf: L::default(),
            default_parent: P::default(),
        }
    }
}

impl<'a, L: Clone + Debug + Default, P: Clone + Debug + Default> AbDiff<'a, L, P> {
    // Functions handling interactions with leaves.
    ///////////////////////////////////////////////

    /// Extend the diff by a leaf and its new parent node.
    ///
    /// Returns an error if adding either of the two nodes increases the size of
    /// the diff beyond [`MAX_TREE_SIZE`].
    pub(crate) fn add_leaf(
        &mut self,
        parent_node: P,
        new_leaf: L,
    ) -> Result<LeafNodeIndex, ABinaryTreeDiffError> {
        // Prevent the tree from becoming too large.
        if self.size().u32() >= MAX_TREE_SIZE {
            return Err(ABinaryTreeDiffError::TreeTooLarge);
        }
        let new_leaf_index = LeafNodeIndex::new(self.leaf_count());
        let new_parent_index = ParentNodeIndex::new(self.parent_count());
        let previous_leaf = self.leaf_diff.insert(new_leaf_index, new_leaf);
        let previous_parent = self.parent_diff.insert(new_parent_index, parent_node);

        debug_assert!(previous_parent.is_none());
        debug_assert!(previous_leaf.is_none());

        // Increase the tree size
        self.size.inc();
        Ok(new_leaf_index)
    }

    /// Removes a leaf from the diff. To keep the binary tree (diff) balanced,
    /// this also removes the parent of the leaf.
    ///
    /// Returns an error if the diff only has one leaf left.
    pub(crate) fn remove_leaf(&mut self) -> Result<(), ABinaryTreeDiffError> {
        // First make sure that the tree isn't getting too small.
        if self.size().u32() <= 1 {
            return Err(ABinaryTreeDiffError::TreeTooSmall);
        }

        // Remove leaf
        let removed_leaf = self
            .leaf_diff
            .remove(&LeafNodeIndex::new(&self.leaf_count() - 1));
        if self.leaf_count() > self.original_tree.leaf_count() {
            // If the diff extended the tree, there should be a node to remove
            // here.
            debug_assert!(removed_leaf.is_some());
        }

        // Remove parent
        let removed_parent = self
            .parent_diff
            .remove(&ParentNodeIndex::new(&self.parent_count() - 1));
        if self.parent_count() > self.original_tree.parent_count() {
            // If the diff extended the tree, there should be a node to remove
            // here.
            debug_assert!(removed_parent.is_some());
        }

        // We decrease the size to signal that a node was removed from the diff.
        self.size.dec();
        Ok(())
    }

    /// Replace the content of the leaf node at the given leaf index with new
    /// content.
    pub(crate) fn replace_leaf(&mut self, leaf_index: LeafNodeIndex, new_leaf: L) {
        self.leaf_diff.insert(leaf_index, new_leaf);
    }

    /// Replace the content of the parent node at the given leaf index with new
    /// content.
    pub(crate) fn replace_parent(&mut self, parent_index: ParentNodeIndex, node: P) {
        self.parent_diff.insert(parent_index, node);
    }

    /// Returns an iterator over a tuple of the leaf index and a reference to a
    /// leaf, sorted according to their position in the tree from left to right.
    pub(crate) fn leaves(&self) -> impl Iterator<Item = (LeafNodeIndex, &L)> {
        let original_leaves = self.original_tree.leaves().peekable();
        let diff_leaves = self
            .leaf_diff
            .iter()
            .map(|(index, leaf)| (*index, leaf))
            .peekable();

        // Combine the original leaves with the leaves from the diff. Since both
        // iterators are sorted, we can just iterate over them and don't need
        // additional sorting. If one of the iterators is exhausted, we just add
        // the remaining leaves from the other iterator. We also make sure that
        // we don't add leaves from the original leaves that are also in the
        // diff.

        // Harmonize the iterator types
        let a_iter = Box::new(diff_leaves) as Box<dyn Iterator<Item = (LeafNodeIndex, &L)>>;
        let b_iter = Box::new(original_leaves) as Box<dyn Iterator<Item = (LeafNodeIndex, &L)>>;

        // We only compare indices, not the actual leaves
        let cmp = |&(x, _): &(LeafNodeIndex, &L)| x;

        sorted_iter(a_iter, b_iter, cmp, self.leaf_count() as usize)
    }

    pub(crate) fn parents(&self) -> impl Iterator<Item = (ParentNodeIndex, &P)> {
        let original_parents = self.original_tree.parents().peekable();
        let diff_parents = self
            .parent_diff
            .iter()
            .map(|(index, parent)| (*index, parent))
            .peekable();

        // Combine the original parents with the parents from the diff. Since
        // both iterators are sorted, we can just iterate over them and don't
        // need additional sorting. If one of the iterators is exhausted, we
        // just add the remaining parents from the other iterator. We also make
        // sure that we don't add parents from the original parents that are
        // also in the diff.

        // Harmonize the iterator types
        let a_iter = Box::new(diff_parents) as Box<dyn Iterator<Item = (ParentNodeIndex, &P)>>;
        let b_iter = Box::new(original_parents) as Box<dyn Iterator<Item = (ParentNodeIndex, &P)>>;

        // We only compare indices, not the actual parents
        let cmp = |&(x, _): &(ParentNodeIndex, &P)| x;

        sorted_iter(a_iter, b_iter, cmp, self.parent_count() as usize)
    }

    // Functions related to the direct paths of leaves
    //////////////////////////////////////////////////

    /// Returns a vector of [`ParentNodeIndex`] instances, each one referencing a
    /// node in the direct path of the given [`LeafNodeIndex`], ordered from the
    /// parent of the corresponding leaf to the root of the tree.
    pub(crate) fn direct_path(&self, leaf_index: LeafNodeIndex) -> Vec<ParentNodeIndex> {
        direct_path(leaf_index, self.size())
    }

    /// Sets all nodes in the direct path to a copy of the given node.
    pub(crate) fn set_direct_path_to_node(&mut self, leaf_index: LeafNodeIndex, node: &P) {
        let direct_path = self.direct_path(leaf_index);
        for node_index in &direct_path {
            self.replace_parent(*node_index, node.clone());
        }
    }

    /// Sets the nodes in the direct path of the given leaf index to the nodes
    /// given in the `path`.
    pub(crate) fn set_direct_path(&mut self, leaf_index: LeafNodeIndex, path: Vec<P>) {
        let direct_path = direct_path(leaf_index, self.size());
        debug_assert_eq!(path.len(), direct_path.len());
        for (node_index, node) in direct_path.iter().zip(path.into_iter()) {
            self.replace_parent(*node_index, node);
        }
    }

    /// Returns the copath of a leaf node.
    pub(crate) fn copath(&self, leaf_index: LeafNodeIndex) -> Vec<TreeNodeIndex> {
        copath(leaf_index, self.size())
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
        debug_assert!(leaf_index_1.u32() < self.size.leaf_count());
        debug_assert!(leaf_index_2.u32() < self.size.leaf_count());

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
        debug_assert!(leaf_index_1.u32() < self.size.leaf_count());
        debug_assert!(leaf_index_2.u32() < self.size.leaf_count());

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

    /// Exports the nodes
    pub(crate) fn export_nodes(&self) -> Vec<TreeNode<L, P>> {
        let mut nodes = Vec::new();

        let leaves = self.leaves().map(|(_, node)| node);
        let parents = self.parents().map(|(_, node)| node);

        // Interleave the leaves and parents.
        for (leaf, parent) in leaves.zip(parents) {
            nodes.push(TreeNode::Leaf(leaf.clone()));
            nodes.push(TreeNode::Parent(parent.clone()));
        }

        // Add the least leaf
        if let Some(last_leaf) = self.leaves().map(|(_, node)| node).last() {
            nodes.push(TreeNode::Leaf(last_leaf.clone()));
        }

        nodes
    }

    /// Returns the leaf count of the diff.
    pub(crate) fn leaf_count(&self) -> u32 {
        ((self.size.u32() - 1) / 2) + 1
    }

    /// Returns the parent count of the diff.
    pub(crate) fn parent_count(&self) -> u32 {
        (self.size.u32() - 1) / 2
    }

    /// Returns the size of the diff tree.
    pub(crate) fn size(&self) -> TreeSize {
        self.size
    }

    // Functions around individual [`TreeNodeIndex`]es
    ///////////////////////////////////////////////

    /// Returns a reference to the leaf node pointed to by the
    /// [`LeafNodeIndex`].
    pub(crate) fn leaf(&self, leaf_index: LeafNodeIndex) -> &L {
        self.leaf_by_index(leaf_index)
    }

    /// Returns a reference to the parent node pointed to by the
    /// [`ParentNodeIndex`].
    pub(crate) fn parent(&self, parent_index: ParentNodeIndex) -> &P {
        self.parent_by_index(parent_index)
    }

    /// Returns a mutable reference to the leaf node pointed to by the
    /// [`LeafNodeIndex`].
    pub(crate) fn leaf_mut(&mut self, leaf_index: LeafNodeIndex) -> &mut L {
        self.leaf_mut_by_index(leaf_index)
    }

    /// Returns a mutable reference to the parent node pointed to by the
    /// [`ParentNodeIndex`].
    pub(crate) fn parent_mut(&mut self, parent_index: ParentNodeIndex) -> &mut P {
        self.parent_mut_by_index(parent_index)
    }

    /// Return a [`TreeNodeIndex`] to the root node of the diff. Since the diff
    /// always consists of at least one node, this operation cannot fail.
    pub(crate) fn root(&self) -> TreeNodeIndex {
        root(self.size())
    }

    /// Returns a [`TreeNodeIndex`] to the left child of the referenced node.
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

    /// Returns a reference to the leaf node at index `leaf_index`.
    fn leaf_by_index(&self, leaf_index: LeafNodeIndex) -> &L {
        // Check if it's in the diff.
        if let Some(node) = self.leaf_diff.get(&leaf_index) {
            return node;
        }
        // If it isn't in the diff, it must be in the tree.
        self.original_tree.leaf_by_index(leaf_index)
    }

    /// Returns a reference to the parent node at index `parent_index`.
    fn parent_by_index(&self, parent_index: ParentNodeIndex) -> &P {
        // Check if it's in the diff.
        if let Some(node) = self.parent_diff.get(&parent_index) {
            return node;
        }
        // If it isn't in the diff, it must be in the tree.
        self.original_tree.parent_by_index(parent_index)
    }

    /// Returns a mutable reference to the leaf node in the diff at index
    /// `leaf_index`. If the diff doesn't have a node at that index, it clones
    /// the node to the diff and returns a mutable reference to that node.
    fn leaf_mut_by_index(&mut self, leaf_index: LeafNodeIndex) -> &mut L {
        // We then check if the node is already in the diff. (Not using `if let
        // ...` here, because the borrow checker doesn't like that).
        if self.leaf_diff.contains_key(&leaf_index) {
            return self
                .leaf_diff
                .get_mut(&leaf_index)
                // We just checked that this index exists, so this must be Some.
                .unwrap_or(&mut self.default_leaf);
            // If not, we take a copy from the original tree and put it in the
            // diff before returning a mutable reference to it.
        }
        let tree_node = self.original_tree.leaf_by_index(leaf_index);
        self.replace_leaf(leaf_index, tree_node.clone());
        self.leaf_diff
            .get_mut(&leaf_index)
            // We just inserted this into the diff, so this should be Some.
            .unwrap_or(&mut self.default_leaf)
    }

    /// Returns a mutable reference to the parent node in the diff at index
    /// `parent_index`. If the diff doesn't have a node at that index, it clones
    /// the node to the diff and returns a mutable reference to that node.
    fn parent_mut_by_index(&mut self, parent_index: ParentNodeIndex) -> &mut P {
        // We then check if the node is already in the diff. (Not using `if let
        // ...` here, because the borrow checker doesn't like that).
        if self.parent_diff.contains_key(&parent_index) {
            return self
                .parent_diff
                .get_mut(&parent_index)
                // We just checked that this index exists, so this must be Some.
                .unwrap_or(&mut self.default_parent);
            // If not, we take a copy from the original tree and put it in the
            // diff before returning a mutable reference to it.
        }
        let tree_node = self.original_tree.parent_by_index(parent_index);
        self.replace_parent(parent_index, tree_node.clone());
        self.parent_diff
            .get_mut(&parent_index)
            // We just inserted this into the diff, so this should be Some.
            .unwrap_or(&mut self.default_parent)
    }

    // Index checking

    #[cfg(test)]
    pub(crate) fn deref_vec(
        &self,
        parent_index_vec: Vec<ParentNodeIndex>,
    ) -> Result<Vec<&P>, ABinaryTreeDiffError> {
        let mut parent_vec = Vec::new();
        for parent_index in parent_index_vec {
            let node = self.parent(parent_index);
            parent_vec.push(node);
        }
        Ok(parent_vec)
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
    /// See [`ABinaryTreeError`] for more details.
    #[error(transparent)]
    ABinaryTreeError(#[from] ABinaryTreeError),
}
