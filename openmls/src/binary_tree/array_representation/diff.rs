use std::collections::{HashMap, HashSet};

use crate::binary_tree::{
    array_representation::treemath::{parent, sibling},
    Addressable, LeafIndex,
};

use super::{
    tree::{to_node_index, ABinaryTree, ABinaryTreeError, NodeIndex, TreeSize},
    treemath::{direct_path, left, right, root, TreeMathError},
};

pub(crate) struct StagedAbDiff<T: Default + Clone> {
    diff: HashMap<NodeIndex, T>,
}

impl<'a, T: Default + Clone> From<AbDiff<'a, T>> for StagedAbDiff<T> {
    fn from(diff: AbDiff<'a, T>) -> Self {
        StagedAbDiff { diff: diff.diff }
    }
}

pub(crate) struct AbDiff<'a, T: Default + Clone> {
    original_tree: &'a ABinaryTree<T>,
    diff: HashMap<NodeIndex, T>,
    size: TreeSize,
}

impl<'a, T: Default + Clone> From<&'a ABinaryTree<T>> for AbDiff<'a, T> {
    fn from(tree: &'a ABinaryTree<T>) -> Self {
        AbDiff {
            original_tree: &tree,
            diff: HashMap::new(),
            size: tree.size(),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct NodeReference<'a, T: Default + Clone> {
    diff: &'a AbDiff<'a, T>,
    node_index: NodeIndex,
}

impl<'a, T: Default + Clone + Addressable> NodeReference<'a, T> {
    pub(crate) fn try_deref(&self) -> Result<&T, ABinaryTreeDiffError> {
        self.diff
            .node_by_index(self.node_index)
            .ok_or(ABinaryTreeDiffError::LibraryError)
    }

    pub(crate) fn is_leaf(&self) -> bool {
        self.node_index % 2 == 0
    }
}

// FIXME: For now, we fail late, i.e. we check if changes to the tree make sense
// when we try to merge. This is because, for example, checking if a leaf is
// within the size of the tree is hard when given only a diff.
impl<'a, T: Default + Clone> AbDiff<'a, T> {
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

    fn add_to_diff(&mut self, node_index: NodeIndex, node: T) -> Result<(), ABinaryTreeDiffError> {
        // Finally, check if the new node increases the size of the diff.
        if node_index >= self.size() {
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

    pub(crate) fn leaf(&'a self, leaf_index: LeafIndex) -> NodeReference<'a, T> {
        NodeReference {
            diff: &self,
            node_index: to_node_index(leaf_index),
        }
    }

    pub(crate) fn leaf_mut(
        &mut self,
        leaf_index: LeafIndex,
    ) -> Result<&mut T, ABinaryTreeDiffError> {
        self.node_mut_by_index(to_node_index(leaf_index))
    }

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

    /// Returns references to the leaves of the tree in order from left to
    /// right.
    pub(crate) fn leaves(&'a self) -> Vec<NodeReference<'a, T>> {
        let mut leaf_references = Vec::new();
        for leaf_index in 0..self.leaf_count() {
            let node_index = to_node_index(leaf_index);
            let node_ref = NodeReference {
                diff: &self,
                node_index,
            };
            leaf_references.push(node_ref);
        }
        leaf_references
    }

    /// Sets the nodes in the direct path of the given leaf index to the nodes
    /// given in the `path_option`. If `path_option` is `None`, it will set the
    /// nodes to `T::default()`. Returns an error if the `leaf_index` is not in
    /// the tree or if the given `path_option` is longer or shorter than the
    /// direct path.
    pub(crate) fn set_direct_path(
        &mut self,
        leaf_index: LeafIndex,
        path_option: Option<Vec<T>>,
    ) -> Result<(), ABinaryTreeDiffError> {
        let node_index = to_node_index(leaf_index);
        let direct_path =
            direct_path(node_index, self.size()).map_err(|_| ABinaryTreeError::OutOfBounds)?;
        if let Some(path) = path_option {
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
        }
        for node_index in &direct_path {
            self.add_to_diff(*node_index, T::default())?;
        }
        Ok(())
    }

    // FIXME: Verify that these two are outdated, as the computation only needs
    // to be performed on the full tree. More up-to-date versions of these
    // functions are implemented for the tree.
    //fn apply_to_node<F>(
    //    &mut self,
    //    node_index: NodeIndex,
    //    f: F,
    //) -> Result<Vec<u8>, ABinaryTreeDiffError>
    //where
    //    F: Fn(&mut T, Vec<u8>, Vec<u8>) -> Vec<u8> + Copy,
    //{
    //    // Check if this is a leaf.
    //    if node_index % 2 == 0 {
    //        let leaf = self.node_mut_by_index(node_index)?;
    //        return Ok(f(leaf, vec![], vec![]));
    //    }
    //    // Compute left hash.
    //    let left_child_index = left(node_index)?;
    //    let left_hash = self.apply_to_node(left_child_index, f)?;
    //    let right_child_index = right(node_index, self.size())?;
    //    let right_hash = self.apply_to_node(right_child_index, f)?;
    //    let node = self.node_mut_by_index(node_index)?;
    //    Ok(f(node, left_hash, right_hash))
    //}

    ///// This function applies the given function to every node in the tree,
    ///// starting with the leaves. In addition to the node itself, the function
    ///// takes as input the results of the function applied to its children.
    //pub(crate) fn fold_tree<F>(&mut self, f: F) -> Result<Vec<u8>, ABinaryTreeDiffError>
    //where
    //    F: Fn(&mut T, Vec<u8>, Vec<u8>) -> Vec<u8> + Copy,
    //{
    //    let root_index = root(self.size());
    //    self.apply_to_node(root_index, f)
    //}

    //pub(crate) fn parent_hash_traverse<F, E>(
    //    &self,
    //    f: F,
    //) -> Result<Result<bool, E>, ABinaryTreeDiffError>
    //where
    //    F: Fn(
    //            &T,
    //            &T,              // child node
    //            Vec<T::Address>, // other child resolution
    //        ) -> Result<bool, E>
    //        + Copy,
    //{
    //    for node_index in 0..self.size() {
    //        let node = self
    //            .node_by_index(node_index)
    //            .ok_or(ABinaryTreeError::LibraryError)?;
    //        let left_child_index = left(node_index)?;
    //        let left_child = self
    //            .node_by_index(left_child_index)
    //            .ok_or(ABinaryTreeError::LibraryError)?;
    //        let mut right_child_index = right(node_index, self.size())?;
    //        let right_child_resolution = self.resolution(right_child_index)?;
    //        let result = f(node, left_child, right_child_resolution);
    //        // If this was successful continue with the next node, otherwise
    //        // proceed with the algorithm on this node. If it threw an error,
    //        // return. FIXME: This is a bit unelegant.
    //        match result {
    //            Ok(success) => {
    //                if success {
    //                    continue;
    //                }
    //            }
    //            Err(e) => return Ok(Err(e)),
    //        }
    //        let mut right_child = self
    //            .node_by_index(right_child_index)
    //            .ok_or(ABinaryTreeError::LibraryError)?;
    //        // While the right child is blank, replace it with its left child
    //        // until it's non-blank or a leaf.
    //        while right_child.address().is_none() && right_child_index % 2 != 0 {
    //            right_child_index = left(right_child_index)?;
    //            right_child = self
    //                .node_by_index(right_child_index)
    //                .ok_or(ABinaryTreeError::LibraryError)?;
    //        }
    //        // If the "right child" is a blank leaf node, the check fails.
    //        if right_child.address().is_none() && right_child_index % 2 == 0 {
    //            return Ok(Ok(false));
    //        };
    //        // Perform the check with the parent hash of the "right child" and
    //        // the left child resolution.
    //        let left_child_resolution = self.resolution(left_child_index)?;
    //        let result = f(node, right_child, left_child_resolution);
    //        // If this was successful continue with the next node, otherwise
    //        // return false. If it threw an error, return. FIXME:
    //        // This is a bit unelegant.
    //        match result {
    //            Ok(success) => {
    //                if success {
    //                    continue;
    //                } else {
    //                    return Ok(Ok(false));
    //                }
    //            }
    //            Err(e) => return Ok(Err(e)),
    //        }
    //    }
    //    Ok(Ok(true))
    //}

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
            let node_ref = NodeReference {
                diff: &self,
                node_index: *node_index,
            };
            direct_path.push(node_ref);
        }
        Ok(direct_path)
    }

    /// Returns a reference to the sibling of the referenced node. Returns an
    /// error when the reference points to the root node or to a node not in the
    /// tree.
    pub(crate) fn sibling(
        &'a self,
        node_ref: NodeReference<'a, T>,
    ) -> Result<NodeReference<'a, T>, ABinaryTreeDiffError> {
        let sibling_index = sibling(node_ref.node_index, self.size())?;
        Ok(NodeReference {
            diff: &self,
            node_index: sibling_index,
        })
    }

    /// Returns a reference to the left child of the referenced node. Returns an
    /// error when the reference points to a leaf node or to a node not in the
    /// tree.
    pub(crate) fn left_child(
        &'a self,
        node_ref: NodeReference<'a, T>,
    ) -> Result<NodeReference<'a, T>, ABinaryTreeDiffError> {
        let left_child_index = left(node_ref.node_index)?;
        Ok(NodeReference {
            diff: &self,
            node_index: left_child_index,
        })
    }

    /// Returns a reference to the right child of the referenced node. Returns an
    /// error when the reference points to a leaf node or to a node not in the
    /// tree.
    pub(crate) fn right_child(
        &'a self,
        node_ref: NodeReference<'a, T>,
    ) -> Result<NodeReference<'a, T>, ABinaryTreeDiffError> {
        let right_child_index = right(node_ref.node_index, self.size())?;
        Ok(NodeReference {
            diff: &self,
            node_index: right_child_index,
        })
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
}

implement_error! {
    pub enum ABinaryTreeDiffError {
        Simple {
            LibraryError = "An inconsistency in the internal state of the diff was detected.",
            OutOfBounds = "The given leaf index is not within the tree.",
            PathLengthMismatch = "The given path index is not the same length as the direct path.",
            AddressCollision = "A node with the given address is already part of this diff.",
            NodeNotFound = "Can't find the node with the given address in the diff.",
            HasNoSibling = "Can't compure sibling resolution of the root node, as it has no sibling.",
        }
        Complex {
            ABinaryTreeError(ABinaryTreeError) = "An Error occurred while accessing the underlying binary tree.",
            TreeError(TreeMathError) = "An error occurred while trying to compute related nodes in the tree.",
        }
    }
}
