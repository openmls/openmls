//! This module provides the `AbDiff` and `StagedAbDiff` structs that allow
//! performing changes to an `ABinaryTree` instance without immediately applying
//! the them. Instead, the changes can be applied to the diff and the results
//! examined before merging the given diff back into the tree (or not).
//!
//! ### Don't Panic!
//!
//! Functions in this module should never panic. However, if there is a bug in
//! the implementation, a function will return an unrecoverable `LibraryError`.
//! This means that some functions that are not expected to fail and throw an
//! error, will still return a `Result` since they may throw a `LibraryError`.

use std::collections::BTreeMap;

use std::fmt::Debug;

use crate::binary_tree::{array_representation::treemath::sibling, LeafIndex, TreeSize};

use super::{
    tree::{to_node_index, ABinaryTree, ABinaryTreeError, NodeIndex},
    treemath::{direct_path, left, lowest_common_ancestor, right, root, TreeMathError},
};

/// The `StagedAbDiff` can be created from an `AbDiff` instance. It's sole
/// purpose is to be subsequently merged into an existing `ABinaryTree`
/// instance. The difference between `StagedAbDiff` and an `AbDiff` is that a
/// `StagedAbDiff` is immutable and does not contain a reference to the original
/// tree. Since it only contains the actual diff without reference to the
/// original content, it can't provide the same information as the `AbDiff` it
/// was created from. However, the lack of the internal reference means that its
/// lifetime is not tied to that of the original tree.
#[derive(Debug)]
pub(crate) struct StagedAbDiff<T: Clone + Debug> {
    diff: BTreeMap<NodeIndex, T>,
    size: TreeSize,
}

impl<'a, T: Clone + Debug> From<AbDiff<'a, T>> for StagedAbDiff<T> {
    fn from(diff: AbDiff<'a, T>) -> Self {
        StagedAbDiff {
            diff: diff.diff,
            size: diff.size,
        }
    }
}

impl<T: Clone + Debug> StagedAbDiff<T> {
    pub(super) fn diff(self) -> BTreeMap<NodeIndex, T> {
        self.diff
    }

    pub(super) fn size(&self) -> TreeSize {
        self.size
    }
}

/// A `NodeReference` represents the position of a node in an `AbDiff`. It can
/// be used to access the node at that position or to navigate to other,
/// neighbouring nodes via the `sibling`, `left_child` and `right_child`
/// functions of the `AbDiff`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct NodeReference {
    node_index: NodeIndex,
}

impl NodeReference {
    /// Creates a new `NodeReference` to a node at the given index. Returns an
    /// error if the given index is outside the bounds of the diff.
    pub(super) fn try_from_node_index<T: Clone + Debug>(
        diff: &AbDiff<T>,
        node_index: NodeIndex,
    ) -> Result<Self, ABinaryTreeDiffError> {
        if node_index >= diff.size() {
            return Err(ABinaryTreeDiffError::OutOfBounds);
        }
        Ok(NodeReference { node_index })
    }
}

/// The `AbDiff` represents a set of differences (i.e. a "Diff") for an
/// `ABinaryTree`. It can be created from an `ABinaryTree` instance and then
/// accessed mutably or immutably. Any changes are saved by the `AbDiff` applied
/// to the original `ABinaryTree` instance by converting it to a `StagedAbDiff`
/// and subsequently merging it.
pub(crate) struct AbDiff<'a, T: Clone + Debug> {
    original_tree: &'a ABinaryTree<T>,
    diff: BTreeMap<NodeIndex, T>,
    size: TreeSize,
}

impl<'a, T: Clone + Debug> From<&'a ABinaryTree<T>> for AbDiff<'a, T> {
    fn from(tree: &'a ABinaryTree<T>) -> Self {
        AbDiff {
            original_tree: tree,
            diff: BTreeMap::new(),
            size: tree.size(),
        }
    }
}

impl<'a, T: Clone + Debug> AbDiff<'a, T> {
    // Functions handling interactions with leaves.
    ///////////////////////////////////////////////

    /// Extend the diff by a leaf and its new parent node. Returns an error if
    /// adding either of the two nodes increases the size of the diff beyond
    /// `NodeIndex::max_value()`.
    pub(crate) fn add_leaf(
        &mut self,
        parent_node: T,
        new_leaf: T,
    ) -> Result<LeafIndex, ABinaryTreeDiffError> {
        self.add_node(self.size(), parent_node)?;
        self.add_node(self.size(), new_leaf)?;
        Ok(self.leaf_count() - 1)
    }

    /// Removes a leaf from the diff. To keep the binary tree (diff) balanced,
    /// this also removes the parent of the leaf. Returns an error if the diff
    /// only has one leaf left.
    pub(crate) fn remove_leaf(&mut self) -> Result<(), ABinaryTreeDiffError> {
        self.remove_node()?;
        self.remove_node()
    }

    /// Replace the content of the node at the given leaf index with new
    /// content. Returns an error if the given leaf index is larger than the
    /// leaf count of the diff.
    pub(crate) fn replace_leaf(
        &mut self,
        leaf_index: LeafIndex,
        new_leaf: T,
    ) -> Result<(), ABinaryTreeDiffError> {
        if leaf_index >= self.leaf_count() {
            return Err(ABinaryTreeDiffError::OutOfBounds);
        }
        let node_index = to_node_index(leaf_index);
        self.add_node(node_index, new_leaf)?;
        Ok(())
    }

    /// Obtain a `NodeReference` to the leaf with the given `LeafIndex`. Returns
    /// an error if the given leaf index does not correspond to a leaf in the
    /// diff.
    pub(crate) fn leaf(
        &'a self,
        leaf_index: LeafIndex,
    ) -> Result<NodeReference, ABinaryTreeDiffError> {
        let node_index = to_node_index(leaf_index);
        NodeReference::try_from_node_index(self, node_index)
    }

    /// Returns references to the leaves of the diff in order from left to
    /// right. This function should not throw an error. However, it might throw
    /// an `OutOfBounds` error if there is a bug in the implementation.
    pub(crate) fn leaves(&'a self) -> Result<Vec<NodeReference>, ABinaryTreeDiffError> {
        let mut leaf_references = Vec::new();
        for leaf_index in 0..self.leaf_count() {
            let node_index = to_node_index(leaf_index);
            let node_ref = NodeReference::try_from_node_index(self, node_index)?;
            leaf_references.push(node_ref);
        }
        Ok(leaf_references)
    }

    // Functions related to the direct paths of leaves
    //////////////////////////////////////////////////

    /// Returns a vector of `NodeReference` instances, each one referencing a
    /// node in the direct path of the given `LeafIndex`, ordered from the
    /// parent of the corresponding leaf to the root of the tree.
    pub(crate) fn direct_path(
        &'a self,
        leaf_index: LeafIndex,
    ) -> Result<Vec<NodeReference>, ABinaryTreeDiffError> {
        let node_index = to_node_index(leaf_index);
        let direct_path_indices = direct_path(node_index, self.size())?;
        let mut direct_path = Vec::new();
        for node_index in direct_path_indices {
            let node_ref = NodeReference::try_from_node_index(self, node_index)?;
            direct_path.push(node_ref);
        }
        Ok(direct_path)
    }

    /// Sets all nodes in the direct path to a copy of the given node. This
    /// function will throw an `OutOfBounds` error if the given index does not
    /// correspond to a leaf in the diff.
    pub(crate) fn set_direct_path_to_node(
        &mut self,
        leaf_index: LeafIndex,
        node: &T,
    ) -> Result<(), ABinaryTreeDiffError> {
        let node_index = to_node_index(leaf_index);
        let direct_path = direct_path(node_index, self.size())?;
        for node_index in &direct_path {
            self.add_node(*node_index, node.clone())?;
        }
        Ok(())
    }

    /// Sets the nodes in the direct path of the given leaf index to the nodes
    /// given in the `path`. Returns an error if the given `leaf_index` does not
    /// correspond to a leaf in the diff or if the given `path` does not have
    /// the same length as the leaf's direct path.
    pub(crate) fn set_direct_path(
        &mut self,
        leaf_index: LeafIndex,
        path: Vec<T>,
    ) -> Result<(), ABinaryTreeDiffError> {
        let node_index = to_node_index(leaf_index);
        let direct_path = direct_path(node_index, self.size())?;
        if path.len() != direct_path.len() {
            return Err(ABinaryTreeDiffError::PathLengthMismatch);
        }
        for (node_index, node) in direct_path.iter().zip(path.into_iter()) {
            self.add_node(*node_index, node)?;
        }
        Ok(())
    }

    // Functions related to the shared subtree of two given leaves
    //////////////////////////////////////////////////////////////

    /// Given two leaf indices, returns the position of the shared subtree root
    /// in the direct path of the first leaf index. Returns an error if both
    /// leaf indices are identical or if one of the leaf indices does not
    /// correspond to a leaf in the diff.
    pub(crate) fn subtree_root_position(
        &self,
        leaf_index_1: LeafIndex,
        leaf_index_2: LeafIndex,
    ) -> Result<usize, ABinaryTreeDiffError> {
        // If the given leaf indices are identical, the shared subtree root is
        // the index itself. Since the index of the leaf itself doesn't appear
        // in the direct path, we can't return anything meaningful. This check
        // also ensures that the tree is large enough such that the direct path
        // is never empty, since if there is a second leaf index (that is within
        // the bound of the tree), there is a non-leaf root node that is in the
        // direct path of all leaves.
        if leaf_index_1 == leaf_index_2 {
            return Err(ABinaryTreeDiffError::SameLeafError);
        } else if leaf_index_1 >= self.leaf_count() || leaf_index_2 >= self.leaf_count() {
            return Err(ABinaryTreeDiffError::OutOfBounds);
        }
        let subtree_root_node_index =
            lowest_common_ancestor(to_node_index(leaf_index_1), to_node_index(leaf_index_2));
        let leaf_index_1_direct_path = direct_path(to_node_index(leaf_index_1), self.size())?;

        leaf_index_1_direct_path
            .iter()
            .position(|&direct_path_node_index| direct_path_node_index == subtree_root_node_index)
            // The shared subtree root has to be in the direct path of both nodes.
            .ok_or(ABinaryTreeDiffError::LibraryError)
    }

    /// Returns `NodeReference` to the copath node of the `leaf_index_1` that is
    /// in the direct path of `leaf_index_2`. Returns an error if both leaf
    /// indices are identical or if one of the leaf indices does not correspond
    /// to a leaf in the diff.
    pub(crate) fn subtree_root_copath_node(
        &'a self,
        leaf_index_1: LeafIndex,
        leaf_index_2: LeafIndex,
    ) -> Result<NodeReference, ABinaryTreeDiffError> {
        if leaf_index_1 == leaf_index_2 {
            return Err(ABinaryTreeDiffError::SameLeafError);
        } else if leaf_index_1 >= self.leaf_count() || leaf_index_2 >= self.leaf_count() {
            return Err(ABinaryTreeDiffError::OutOfBounds);
        }

        // We want to return the position of the lowest common ancestor in the
        // direct path of `leaf_index_1` (i.e. the sender_leaf_index).
        let subtree_root_node_index =
            lowest_common_ancestor(to_node_index(leaf_index_1), to_node_index(leaf_index_2));

        // Figure out which child is the relevant copath node.
        let copath_node_index = if leaf_index_2 < leaf_index_1 {
            left(subtree_root_node_index)?
        } else {
            right(subtree_root_node_index, self.size())?
        };

        NodeReference::try_from_node_index(self, copath_node_index)
    }

    /// Returns a vector of `NodeReference`s, where the first reference is to
    /// the root of the shared subtree of the two given leaf indices followed by
    /// references to the nodes in its direct path. Returns an error if either
    /// of the two given leaf indices do not correspond to a leaf in the diff.
    pub(crate) fn subtree_path(
        &self,
        leaf_index_1: LeafIndex,
        leaf_index_2: LeafIndex,
    ) -> Result<Vec<NodeReference>, ABinaryTreeDiffError> {
        if leaf_index_1 >= self.leaf_count() || leaf_index_2 >= self.leaf_count() {
            return Err(ABinaryTreeDiffError::OutOfBounds);
        }

        let node_index_1 = to_node_index(leaf_index_1);
        let node_index_2 = to_node_index(leaf_index_2);
        let lca = lowest_common_ancestor(node_index_1, node_index_2);
        let direct_path_indices = direct_path(lca, self.size())?;
        let mut full_path = vec![NodeReference::try_from_node_index(self, lca)?];
        for node_index in direct_path_indices {
            let node_ref = NodeReference::try_from_node_index(self, node_index)?;
            full_path.push(node_ref);
        }

        Ok(full_path)
    }

    // Functions pertaining to the whole diff
    /////////////////////////////////////////

    /// Returns an iterator over references to the content of all nodes in the
    /// diff.
    pub(crate) fn iter(&'a self) -> DiffIterator<'a, T> {
        DiffIterator {
            diff: self,
            current_index: 0u32,
        }
    }

    /// Returns a vector containing the nodes of the tree in-order, i.e. in the
    /// array representation of the diff. This function should not fail and only
    /// returns a `Result`, because it might throw a
    /// [LibraryError](ABinaryTreeError::LibraryError).
    pub(crate) fn export_nodes(&self) -> Result<Vec<T>, ABinaryTreeDiffError> {
        let mut nodes = Vec::new();
        for node_index in 0..self.size() {
            let node = self
                .node_by_index(node_index)
                // Every node index within size() should point to a node in the
                // diff.
                .ok_or(ABinaryTreeDiffError::LibraryError)?;
            nodes.push(node.clone());
        }
        Ok(nodes)
    }

    /// Returns the size of the diff.
    pub(in crate::binary_tree) fn size(&self) -> NodeIndex {
        self.size
    }

    /// Returns the leaf count of the diff.
    pub(crate) fn leaf_count(&self) -> LeafIndex {
        (self.size() + 1) / 2
    }

    // Functions around individual `NodeReference`s
    ///////////////////////////////////////////////

    /// Returns a reference to the node pointed to by the `NodeReference`.
    /// Returns an Error if the `NodeReference` points to a node outside of the
    /// bounds of the tree. This can happen, for example, if the node was
    /// removed while shrinking the diff after the creation of the
    /// `NodeReference`.
    pub(crate) fn try_deref(&self, node_ref: NodeReference) -> Result<&T, ABinaryTreeDiffError> {
        self.node_by_index(node_ref.node_index)
            .ok_or(ABinaryTreeDiffError::OutOfBounds)
    }

    /// Returns a mutable reference to the node pointed to by the
    /// `NodeReference`. Returns an Error if the `NodeReference` points to a
    /// node outside of the bounds of the tree. This can happen, for example, if
    /// the node was removed while shrinking the diff after the creation of the
    /// `NodeReference`.
    pub(crate) fn try_deref_mut(
        &mut self,
        node_ref: NodeReference,
    ) -> Result<&mut T, ABinaryTreeDiffError> {
        self.node_mut_by_index(node_ref.node_index)
    }

    /// Return a `NodeReference` to the root node of the diff. Since the diff
    /// always consists of at least one node, this operation cannot fail.
    pub(crate) fn root(&self) -> NodeReference {
        let root_index = root(self.size());
        // We create the reference directly instead of via self.new_reference,
        // since due to the minimum tree size of one node, the root is always
        // within bounds.
        NodeReference {
            node_index: root_index,
        }
    }

    /// Returns true if the given `NodeReference` points to a leaf and `false`
    /// otherwise.
    pub(crate) fn is_leaf(&self, node_ref: NodeReference) -> bool {
        node_ref.node_index % 2 == 0
    }

    /// Returns a `NodeReference` to the sibling of the referenced node. Returns
    /// an error when the given `NodeReference` points to the root node or to a
    /// node not in the tree.
    pub(crate) fn sibling(
        &self,
        node_ref: NodeReference,
    ) -> Result<NodeReference, ABinaryTreeDiffError> {
        let sibling_index = sibling(node_ref.node_index, self.size())?;
        NodeReference::try_from_node_index(self, sibling_index)
    }

    /// Returns a `NodeReference` to the left child of the referenced node.
    /// Returns an error when the given `NodeReference` points to a leaf node or
    /// to a node not in the tree.
    pub(crate) fn left_child(
        &self,
        node_ref: NodeReference,
    ) -> Result<NodeReference, ABinaryTreeDiffError> {
        let left_child_index = left(node_ref.node_index)?;
        NodeReference::try_from_node_index(self, left_child_index)
    }

    /// Returns a `NodeReference` to the right child of the referenced node.
    /// Returns an error when the given `NodeReference` points to a leaf node or
    /// to a node not in the tree.
    pub(crate) fn right_child(
        &self,
        node_ref: NodeReference,
    ) -> Result<NodeReference, ABinaryTreeDiffError> {
        let right_child_index = right(node_ref.node_index, self.size())?;
        NodeReference::try_from_node_index(self, right_child_index)
    }

    /// Returns the `LeafIndex` of the referenced node. If the referenced node
    /// is not a leaf, `None` is returned.
    pub(crate) fn leaf_index(&self, node_ref: NodeReference) -> Option<LeafIndex> {
        if self.is_leaf(node_ref) {
            Some(node_ref.node_index / 2)
        } else {
            None
        }
    }

    // Private helper functions below.
    //////////////////////////////////

    // Node access functions

    /// Returns a reference to the node at index `node_index` or `None` if the
    /// node can neither be found in the tree nor in the diff.
    fn node_by_index(&self, node_index: NodeIndex) -> Option<&T> {
        // We first check if the given node_index is within the bounds of the diff.
        if node_index >= self.size() {
            None
            // If it is, check if it's in the diff.
        } else if let Some(node) = self.diff.get(&node_index) {
            Some(node)
            // If it isn't in the diff, it must be in the tree.
        } else if let Some(node) = self.original_tree.node_by_index(node_index) {
            Some(node)
            // If it isn't in the tree either, something has gone wrong.
        } else {
            None
        }
    }

    /// Returns a mutable reference to the node in the diff at index
    /// `node_index`. If the diff doesn't have a node at that index, it clones
    /// the node to the diff and returns a mutable reference to that node.
    /// Returns an error if the node can neither be found in the tree nor in the
    /// diff, or if the index is out of the bounds of the diff.
    fn node_mut_by_index(&mut self, node_index: NodeIndex) -> Result<&mut T, ABinaryTreeDiffError> {
        // We first check if the given node_index is within the bounds of the diff.
        if node_index >= self.size() {
            Err(ABinaryTreeDiffError::OutOfBounds)
            // We then check if the node is already in the diff. (Not using `if let
            // ...` here, because the borrow checker doesn't like that).
        } else if self.diff.contains_key(&node_index) {
            self.diff
                .get_mut(&node_index)
                // We just checked that this index exists, so this must be Some.
                .ok_or(ABinaryTreeDiffError::LibraryError)
            // If not, we take a copy from the original tree and put it in the
            // diff before returning a mutable reference to it.
        } else if let Some(tree_node) = self.original_tree.node_by_index(node_index) {
            self.add_node(node_index, tree_node.clone())?;
            self.diff
                .get_mut(&node_index)
                // We just inserted this into the diff, so this should be Some.
                .ok_or(ABinaryTreeDiffError::LibraryError)
        } else {
            // If the node is neither out of bounds, nor in the diff, nor in the
            // tree, something must have gone wrong somewhere.
            Err(ABinaryTreeDiffError::LibraryError)
        }
    }

    // Helper functions for node addition and removal

    /// Add a node to the diff at the given index. This function can be used
    /// both to extend the diff (by choosing a `node_index` that is equal to the
    /// size of the diff) and to place a node at the given index such that any
    /// previous node in the tree at the same position is replaced upon merging
    /// the diff. Returns an error if adding the node would increase the size of
    /// the diff beyond `NodeIndex::max_value()` or if the given node index is
    /// larger than the current size of the diff.
    fn add_node(&mut self, node_index: NodeIndex, node: T) -> Result<(), ABinaryTreeDiffError> {
        // Prevent the tree from becoming too large.
        if self.size() == NodeIndex::max_value() {
            return Err(ABinaryTreeDiffError::TreeTooLarge);
        }
        // Check that we're extending the tree by at most one.
        if node_index > self.size() {
            return Err(ABinaryTreeDiffError::ExtendingOutOfBounds);
        }
        self.diff.insert(node_index, node);
        // Finally, check if the new node increases the size of the diff.
        if node_index == self.size() {
            self.size = node_index + 1
        }
        Ok(())
    }

    /// Removes a node from the right edge of the diff, thus decreasing the size
    /// of the diff by one. Throws an error if this would make the diff too
    /// small (i.e. < 1 node).
    fn remove_node(&mut self) -> Result<(), ABinaryTreeDiffError> {
        // First make sure that the tree isn't getting too small.
        if self.size() <= 1 {
            return Err(ABinaryTreeDiffError::TreeTooSmall);
        }
        // Then check if the tree was extended before. If so, just remove the
        // last node from the diff.
        if self.size() > self.original_tree.size() {
            let removed = self.diff.remove(&(self.size() - 1));
            // There should be a node here to remove.
            debug_assert!(removed.is_some());
        } else {
            // If that is not the case, either the tree is of the same length as
            // the diff, or the diff is already smaller. In both cases, we check
            // if there is a node at the right edge to remove from the diff.
            self.diff.remove(&(self.size() - 1));
            // Regardless of the result, we decrease the size to signal that a
            // node was removed from the diff.
        }
        self.size -= 1;
        Ok(())
    }

    #[cfg(test)]
    pub fn deref_vec(
        &self,
        node_ref_vec: Vec<NodeReference>,
    ) -> Result<Vec<&T>, ABinaryTreeDiffError> {
        let mut node_vec = Vec::new();
        for node_ref in node_ref_vec {
            let node = self.try_deref(node_ref)?;
            node_vec.push(node);
        }
        Ok(node_vec)
    }
}

/// An iterator over an `AbDiff` instance.
pub(crate) struct DiffIterator<'a, T: Clone + Debug> {
    diff: &'a AbDiff<'a, T>,
    current_index: NodeIndex,
}

impl<'a, T: Clone + Debug> Iterator for DiffIterator<'a, T> {
    type Item = NodeReference;

    fn next(&mut self) -> Option<Self::Item> {
        if self.diff.node_by_index(self.current_index).is_some() {
            let node_ref_option = Some(NodeReference {
                node_index: self.current_index,
            });
            self.current_index += 1;
            node_ref_option
        } else {
            None
        }
    }
}

implement_error! {
    pub enum ABinaryTreeDiffError {
        Simple {
            LibraryError = "An inconsistency in the internal state of the diff was detected.",
            SameLeafError = "Can't compute the copath node of the subtree root of a single leaf.",
            PathModificationError = "Error while trying to modify path.",
            OutOfBounds = "The given leaf index is not within the tree.",
            TreeTooLarge = "Maximum tree size reached.",
            TreeTooSmall = "Minimum tree size reached.",
            PathLengthMismatch = "The given path index is not the same length as the direct path.",
            AddressCollision = "A node with the given address is already part of this diff.",
            NodeNotFound = "Can't find the node with the given address in the diff.",
            HasNoSibling = "Can't compure sibling resolution of the root node, as it has no sibling.",
            ExtendingOutOfBounds = "Trying to write too far outside of the tree.",
            FoldingError = "Error while executing folding function.",
            EmptyDirectPath = "Can't compute subtree root position in an empty direct path.",
        }
        Complex {
            ABinaryTreeError(ABinaryTreeError) = "An Error occurred while accessing the underlying binary tree.",
            TreeError(TreeMathError) = "An error occurred while trying to compute related nodes in the tree.",
        }
    }
}
