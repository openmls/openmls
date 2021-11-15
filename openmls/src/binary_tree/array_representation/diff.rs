use std::collections::HashMap;

use crate::binary_tree::{array_representation::treemath::sibling, LeafIndex};

use super::{
    tree::{to_node_index, ABinaryTree, ABinaryTreeError, NodeIndex, TreeSize},
    treemath::{direct_path, left, lowest_common_ancestor, right, root, TreeMathError},
};

pub(crate) struct StagedAbDiff<T: Clone> {
    diff: HashMap<NodeIndex, T>,
}

impl<'a, T: Clone> From<AbDiff<'a, T>> for StagedAbDiff<T> {
    fn from(diff: AbDiff<'a, T>) -> Self {
        StagedAbDiff { diff: diff.diff }
    }
}

impl<T: Clone> StagedAbDiff<T> {
    pub(super) fn diff(self) -> HashMap<NodeIndex, T> {
        self.diff
    }
}

pub(crate) struct AbDiff<'a, T: Clone> {
    original_tree: &'a ABinaryTree<T>,
    diff: HashMap<NodeIndex, T>,
    size: TreeSize,
}

impl<'a, T: Clone> From<&'a ABinaryTree<T>> for AbDiff<'a, T> {
    fn from(tree: &'a ABinaryTree<T>) -> Self {
        AbDiff {
            original_tree: &tree,
            diff: HashMap::new(),
            size: tree.size(),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct NodeReference<'a, T: Clone> {
    diff: &'a AbDiff<'a, T>,
    node_index: NodeIndex,
}

impl<'a, T: Clone> NodeReference<'a, T> {
    pub(crate) fn try_deref(&self) -> Result<&T, ABinaryTreeDiffError> {
        self.diff
            .node_by_index(self.node_index)
            .ok_or(ABinaryTreeDiffError::LibraryError)
    }

    pub(crate) fn is_leaf(&self) -> bool {
        self.node_index % 2 == 0
    }

    /// Returns a reference to the sibling of the referenced node. Returns an
    /// error when the reference points to the root node or to a node not in the
    /// tree.
    pub(crate) fn sibling(self) -> Result<NodeReference<'a, T>, ABinaryTreeDiffError> {
        let sibling_index = sibling(self.node_index, self.diff.size())?;
        self.diff.new_reference(sibling_index)
    }

    /// Returns a reference to the left child of the referenced node. Returns an
    /// error when the reference points to a leaf node or to a node not in the
    /// tree.
    pub(crate) fn left_child(self) -> Result<NodeReference<'a, T>, ABinaryTreeDiffError> {
        let left_child_index = left(self.node_index)?;
        self.diff.new_reference(left_child_index)
    }

    /// Returns a reference to the right child of the referenced node. Returns an
    /// error when the reference points to a leaf node or to a node not in the
    /// tree.
    pub(crate) fn right_child(self) -> Result<NodeReference<'a, T>, ABinaryTreeDiffError> {
        let right_child_index = right(self.node_index, self.diff.size())?;
        self.diff.new_reference(right_child_index)
    }

    pub(crate) fn leaf_index(&self) -> Option<LeafIndex> {
        if self.is_leaf() {
            Some(self.node_index / 2)
        } else {
            None
        }
    }
}

/// FIXME: Ideally, one would also use node references to write to the tree.
impl<'a, T: Clone> AbDiff<'a, T> {
    pub(crate) fn new(tree: &'a ABinaryTree<T>) -> Self {
        Self {
            original_tree: tree,
            diff: HashMap::new(),
            size: tree.size(),
        }
    }

    pub(crate) fn replace_leaf(
        &mut self,
        leaf_index: LeafIndex,
        new_leaf: T,
    ) -> Result<(), ABinaryTreeDiffError> {
        if leaf_index > self.leaf_count() {
            return Err(ABinaryTreeDiffError::OutOfBounds);
        }
        let node_index = to_node_index(leaf_index);
        self.add_to_diff(node_index, new_leaf)?;
        Ok(())
    }

    pub(crate) fn add_leaf(
        &mut self,
        parent_node: T,
        new_leaf: T,
    ) -> Result<LeafIndex, ABinaryTreeDiffError> {
        self.add_to_diff(self.size(), parent_node)?;
        self.add_to_diff(self.size(), new_leaf)?;
        Ok(self.leaf_count() - 1)
    }

    pub(crate) fn leaf(
        &'a self,
        leaf_index: LeafIndex,
    ) -> Result<NodeReference<'a, T>, ABinaryTreeDiffError> {
        let node_index = to_node_index(leaf_index);
        self.new_reference(node_index)
    }

    /// Returns references to the leaves of the tree in order from left to
    /// right.
    pub(crate) fn leaves(&'a self) -> Result<Vec<NodeReference<'a, T>>, ABinaryTreeDiffError> {
        let mut leaf_references = Vec::new();
        for leaf_index in 0..self.leaf_count() {
            let node_index = to_node_index(leaf_index);
            let node_ref = self.new_reference(node_index)?;
            leaf_references.push(node_ref);
        }
        Ok(leaf_references)
    }

    // FIXME: Come up with a better name.
    /// Sets all nodes in the direct path to a copy of the given node.
    pub(crate) fn set_direct_path_nodes(
        &mut self,
        leaf_index: LeafIndex,
        node: &T,
    ) -> Result<(), ABinaryTreeDiffError> {
        let node_index = to_node_index(leaf_index);
        let direct_path =
            direct_path(node_index, self.size()).map_err(|_| ABinaryTreeError::OutOfBounds)?;
        for node_index in &direct_path {
            self.add_to_diff(*node_index, node.clone())?;
        }
        Ok(())
    }

    /// Sets the nodes in the direct path of the given leaf index to the nodes
    /// given in the `path`. Returns an error if the `leaf_index` is not in the
    /// tree or if the given `path` is longer or shorter than the direct path.
    pub(crate) fn set_direct_path(
        &mut self,
        leaf_index: LeafIndex,
        path: Vec<T>,
    ) -> Result<(), ABinaryTreeDiffError> {
        let node_index = to_node_index(leaf_index);
        let direct_path =
            direct_path(node_index, self.size()).map_err(|_| ABinaryTreeError::OutOfBounds)?;
        if path.len() != direct_path.len() {
            return Err(ABinaryTreeDiffError::PathLengthMismatch);
        }
        for node_index in &direct_path {
            self.add_to_diff(
                *node_index,
                path.get(*node_index as usize)
                    .ok_or(ABinaryTreeDiffError::PathLengthMismatch)?
                    .clone(),
            )?;
        }
        Ok(())
    }

    fn apply_to_node<F, E>(
        &mut self,
        node_index: NodeIndex,
        f: F,
    ) -> Result<Result<Vec<u8>, E>, ABinaryTreeDiffError>
    where
        F: Fn(
                &mut T,
                Option<LeafIndex>,
                Result<Vec<u8>, E>,
                Result<Vec<u8>, E>,
            ) -> Result<Vec<u8>, E>
            + Copy,
    {
        // Check if this is a leaf.
        if node_index % 2 == 0 {
            let leaf = self.node_mut_by_index(node_index)?;
            return Ok(f(leaf, Some(node_index / 2), Ok(vec![]), Ok(vec![])));
        }
        // Compute left hash.
        let left_child_index = left(node_index)?;
        let left_hash = self.apply_to_node(left_child_index, f)?;
        let right_child_index = right(node_index, self.size())?;
        let right_hash = self.apply_to_node(right_child_index, f)?;
        let node = self.node_mut_by_index(node_index)?;
        Ok(f(node, None, left_hash, right_hash))
    }

    /// This function applies the given function to every node in the tree,
    /// starting with the leaves. In addition to the node itself, the function
    /// takes as input the results of the function applied to its children.
    pub(crate) fn fold_tree<F, E>(
        &mut self,
        f: F,
    ) -> Result<Result<Vec<u8>, E>, ABinaryTreeDiffError>
    where
        F: Fn(
                &mut T,
                Option<LeafIndex>,
                Result<Vec<u8>, E>,
                Result<Vec<u8>, E>,
            ) -> Result<Vec<u8>, E>
            + Copy,
    {
        let root_index = root(self.size());
        self.apply_to_node(root_index, f)
    }

    /// This applies the given function to the lowest common ancestor (i.e. the
    /// subtree root), as well as the direct path from that node to the root.
    pub(crate) fn apply_to_subtree_path<F, E>(
        &mut self,
        leaf_index_1: LeafIndex,
        leaf_index_2: LeafIndex,
        mut f: F,
    ) -> Result<(), ABinaryTreeDiffError>
    where
        F: FnMut(&mut T) -> Result<(), E>,
    {
        let node_index_1 = to_node_index(leaf_index_1);
        let node_index_2 = to_node_index(leaf_index_2);
        let lca = lowest_common_ancestor(node_index_1, node_index_2);
        let mut direct_path_indices =
            direct_path(lca, self.size()).map_err(|_| ABinaryTreeDiffError::OutOfBounds)?;
        let mut full_path = vec![lca];
        full_path.append(&mut direct_path_indices);
        for node_index in &full_path {
            let node = self.node_mut_by_index(*node_index)?;
            f(node).map_err(|_| ABinaryTreeDiffError::PathModificationError)?;
        }
        Ok(())
    }

    /// Any Error while applying `f` will be treated as a LibraryError.
    pub(crate) fn apply_to_direct_path<F, E>(
        &mut self,
        leaf_index: LeafIndex,
        f: F,
    ) -> Result<(), ABinaryTreeDiffError>
    where
        F: Fn(&mut T) -> Result<(), E>,
    {
        let node_index = to_node_index(leaf_index);
        let direct_path_indices =
            direct_path(node_index, self.size()).map_err(|_| ABinaryTreeDiffError::OutOfBounds)?;
        for node_index in &direct_path_indices {
            let node = self.node_mut_by_index(*node_index)?;
            f(node).map_err(|_| ABinaryTreeDiffError::LibraryError)?;
        }
        Ok(())
    }

    pub(crate) fn direct_path(
        &'a self,
        leaf_index: LeafIndex,
    ) -> Result<Vec<NodeReference<'a, T>>, ABinaryTreeDiffError> {
        let node_index = to_node_index(leaf_index);
        let direct_path_indices =
            direct_path(node_index, self.size()).map_err(|_| ABinaryTreeError::OutOfBounds)?;
        let mut direct_path = Vec::new();
        for node_index in &direct_path_indices {
            let node_ref = self.new_reference(*node_index)?;
            direct_path.push(node_ref);
        }
        Ok(direct_path)
    }

    pub(crate) fn root(&'a self) -> Result<NodeReference<'a, T>, ABinaryTreeDiffError> {
        let root_index = root(self.size());
        self.new_reference(root_index)
    }

    /// Returns an unordered vector with references to all nodes.
    pub(crate) fn all_nodes(&'a self) -> Vec<NodeReference<'a, T>> {
        let mut node_references = Vec::new();
        for node_index in 0..self.size() {
            let node_ref = NodeReference {
                diff: &self,
                node_index,
            };
            node_references.push(node_ref)
        }
        node_references
    }

    // Private helper functions below.

    /// Returns a reference to the node at index `node_index` or `None` if the
    /// node can neither be found in the tree nor in the diff.
    fn node_by_index(&self, node_index: NodeIndex) -> Option<&T> {
        if let Some(node) = self.diff.get(&node_index) {
            Some(node)
        } else if let Some(node) = self.original_tree.node_by_index(node_index) {
            Some(node)
        } else {
            None
        }
    }

    /// Returns a mutable reference to the node at index `node_index` or `None`
    /// if the node can neither be found in the tree nor in the diff.
    fn node_mut_by_index(&mut self, node_index: NodeIndex) -> Result<&mut T, ABinaryTreeDiffError> {
        if self.diff.contains_key(&node_index) {
            let node = self
                .diff
                .get_mut(&node_index)
                .ok_or(ABinaryTreeDiffError::NodeNotFound)?;
            Ok(node)
        } else if let Some(tree_node) = self.original_tree.node_by_index(node_index) {
            self.add_to_diff(node_index, tree_node.clone())?;
            drop(tree_node);
            self.diff
                .get_mut(&node_index)
                .ok_or(ABinaryTreeDiffError::LibraryError)
        } else {
            Err(ABinaryTreeDiffError::OutOfBounds)
        }
    }

    fn add_to_diff(&mut self, node_index: NodeIndex, node: T) -> Result<(), ABinaryTreeDiffError> {
        // Prevent the tree from becoming too large.
        if self.size() > NodeIndex::max_value() - 2 {
            return Err(ABinaryTreeDiffError::TreeTooLarge);
        } // Make sure that the input node has an address.
          // Check that we're extending the tree by at most one.
        if node_index > self.size() {
            return Err(ABinaryTreeDiffError::ExtendingOutOfBounds);
        }
        // If we are overwriting a node, remove its address from the node_map.
        self.diff.insert(node_index, node);
        // Finally, check if the new node increases the size of the diff.
        if node_index == self.size() {
            self.size = node_index + 1
        }
        Ok(())
    }

    fn size(&self) -> NodeIndex {
        self.size
    }

    fn leaf_count(&self) -> LeafIndex {
        (self.size() + 1) / 2
    }

    fn new_reference(
        &'a self,
        node_index: NodeIndex,
    ) -> Result<NodeReference<'a, T>, ABinaryTreeDiffError> {
        if node_index >= self.size() {
            return Err(ABinaryTreeDiffError::OutOfBounds);
        }
        Ok(NodeReference {
            diff: &self,
            node_index,
        })
    }
}

implement_error! {
    pub enum ABinaryTreeDiffError {
        Simple {
            LibraryError = "An inconsistency in the internal state of the diff was detected.",
            PathModificationError = "Error while trying to modify path.",
            OutOfBounds = "The given leaf index is not within the tree.",
            TreeTooLarge = "Maximum tree size reached.",
            PathLengthMismatch = "The given path index is not the same length as the direct path.",
            AddressCollision = "A node with the given address is already part of this diff.",
            NodeNotFound = "Can't find the node with the given address in the diff.",
            HasNoSibling = "Can't compure sibling resolution of the root node, as it has no sibling.",
            ExtendingOutOfBounds = "Trying to write too far outside of the tree.",
        }
        Complex {
            ABinaryTreeError(ABinaryTreeError) = "An Error occurred while accessing the underlying binary tree.",
            TreeError(TreeMathError) = "An error occurred while trying to compute related nodes in the tree.",
        }
    }
}
