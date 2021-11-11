use std::collections::{HashMap, HashSet};

use crate::binary_tree::{
    array_representation::treemath::{parent, sibling},
    Addressable, LeafIndex,
};

use super::{
    tree::{to_node_index, ABinaryTree, ABinaryTreeError, NodeIndex, TreeSize},
    treemath::{direct_path, left, right, root, TreeMathError},
};

pub(crate) struct StagedAbDiff<T: Default + Clone + Addressable> {
    diff: HashMap<NodeIndex, T>,
}

pub(crate) struct AbDiff<'a, T: Default + Clone + Addressable> {
    original_tree: &'a ABinaryTree<T>,
    diff: HashMap<NodeIndex, T>,
    node_map: HashMap<T::Address, NodeIndex>,
    size: TreeSize,
}

// FIXME: For now, we fail late, i.e. we check if changes to the tree make sense
// when we try to merge. This is because, for example, checking if a leaf is
// within the size of the tree is hard when given only a diff.
impl<'a, T: Default + Clone + Addressable> AbDiff<'a, T> {
    pub(crate) fn new(tree: &'a ABinaryTree<T>) -> Self {
        Self {
            original_tree: tree,
            diff: HashMap::new(),
            node_map: HashMap::new(),
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

    pub(crate) fn add_leaf(&mut self, new_leaf: T) -> Result<LeafIndex, ABinaryTreeDiffError> {
        // Make sure that the input node has an address.
        let address = new_leaf.address().ok_or(ABinaryTreeError::InvalidNode)?;
        self.add_to_diff(self.size(), T::default())?;
        self.add_to_diff(self.size(), new_leaf)?;
        Ok(self.leaf_count() - 1)
    }

    fn add_to_diff(&mut self, node_index: NodeIndex, node: T) -> Result<(), ABinaryTreeDiffError> {
        // If the node has an address, check that we don't have a collision.
        if let Some(address) = node.address() {
            if self.node_map.contains_key(&address) {
                return Err(ABinaryTreeDiffError::AddressCollision);
            }
            self.node_map.insert(address, node_index);
        }
        // If we are overwriting a node, remove its address from the node_map.
        if let Some(old_node) = self.diff.insert(node_index, node) {
            if let Some(address) = old_node.address() {
                self.node_map.remove(&address);
            }
        };
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

    fn node(&self, address: &T::Address) -> Option<&T> {
        self.node_map
            .get(address)
            .map(|&node_index| self.node_by_index(node_index))
            .flatten()
    }

    pub(crate) fn leaf(&self, leaf_index: LeafIndex) -> Option<&T> {
        self.node_by_index(to_node_index(leaf_index))
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

    /// Returns the index of the first leaf that does not have an address.
    /// Returns None if no such leaf could be found.
    pub(crate) fn get_empty_leaf(&self) -> Result<Option<LeafIndex>, ABinaryTreeDiffError> {
        for leaf_index in 0..self.leaf_count() {
            let node_index = to_node_index(leaf_index);
            let leaf = self
                .node_by_index(node_index)
                .ok_or(ABinaryTreeDiffError::LibraryError)?;
            if leaf.address().is_none() {
                return Ok(Some(leaf_index));
            }
        }
        // We didn't find a leaf without an address.
        Ok(None)
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

    fn apply_to_node<F>(
        &mut self,
        node_index: NodeIndex,
        f: F,
    ) -> Result<Vec<u8>, ABinaryTreeDiffError>
    where
        F: Fn(&mut T, Vec<u8>, Vec<u8>) -> Vec<u8> + Copy,
    {
        // Check if this is a leaf.
        if node_index % 2 == 0 {
            let leaf = self.node_mut_by_index(node_index)?;
            return Ok(f(leaf, vec![], vec![]));
        }
        // Compute left hash.
        let left_child_index = left(node_index)?;
        let left_hash = self.apply_to_node(left_child_index, f)?;
        let right_child_index = right(node_index, self.size())?;
        let right_hash = self.apply_to_node(right_child_index, f)?;
        let node = self.node_mut_by_index(node_index)?;
        Ok(f(node, left_hash, right_hash))
    }

    /// This function applies the given function to every node in the tree,
    /// starting with the leaves. In addition to the node itself, the function
    /// takes as input the results of the function applied to its children.
    pub(crate) fn fold_tree<F>(&mut self, f: F) -> Result<Vec<u8>, ABinaryTreeDiffError>
    where
        F: Fn(&mut T, Vec<u8>, Vec<u8>) -> Vec<u8> + Copy,
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
            direct_path(node_index, self.size()).map_err(|_| ABinaryTreeError::OutOfBounds)?;
        for node_index in &direct_path_indices {
            let node = self.node_mut_by_index(*node_index)?;
            f(node).map_err(|_| ABinaryTreeError::LibraryError)?;
        }
        Ok(())
    }

    pub(crate) fn direct_path(
        &self,
        leaf_index: LeafIndex,
    ) -> Result<Vec<&T>, ABinaryTreeDiffError> {
        let node_index = to_node_index(leaf_index);
        let direct_path_indices =
            direct_path(node_index, self.size()).map_err(|_| ABinaryTreeError::OutOfBounds)?;
        let mut direct_path = Vec::new();
        for node_index in &direct_path_indices {
            let node = self
                .node_by_index(*node_index)
                .ok_or(ABinaryTreeDiffError::LibraryError)?;
            direct_path.push(node);
        }
        Ok(direct_path)
    }

    /// Helper function computing the resolution of a node with the given index.
    fn resolution(&self, node_index: NodeIndex) -> Result<Vec<T::Address>, ABinaryTreeDiffError> {
        let node = self
            .node_by_index(node_index)
            .ok_or(ABinaryTreeDiffError::LibraryError)?;
        if let Some(address) = node.address() {
            return Ok(vec![address]);
        }
        let mut resolution = Vec::new();
        let left_child_index = left(node_index)?;
        let right_child_index = right(node_index, self.size())?;
        resolution.append(&mut self.resolution(left_child_index)?);
        resolution.append(&mut self.resolution(right_child_index)?);
        Ok(resolution)
    }

    /// Compute the resolution of the copath of the leaf node corresponding to
    /// the given leaf index. This includes the neighbour of the given leaf.
    pub(crate) fn copath_resolutions(
        &self,
        leaf_index: LeafIndex,
    ) -> Result<Vec<Vec<T::Address>>, ABinaryTreeDiffError> {
        let leaf_node_index = to_node_index(leaf_index);
        let mut full_path = vec![leaf_node_index];
        let mut direct_path = direct_path(leaf_node_index, self.size())?;
        full_path.append(&mut direct_path);

        let mut copath_resolutions = Vec::new();
        for node_index in &full_path {
            // If sibling is not a blank, return its HpkePublicKey.
            let sibling_index = sibling(*node_index, self.size())?;
            let resolution = self.resolution(sibling_index)?;
            copath_resolutions.push(resolution);
        }
        Ok(copath_resolutions)
    }

    // Probably obsolete functions below

    pub(crate) fn root(&self) -> Option<&T> {
        let root_index = root(self.size());
        self.node_by_index(root_index)
    }

    /// Returns a reference to the sibling of the node with the given address.
    /// Returns an error when the address points to the root node or to a node
    /// not in the tree.
    pub(crate) fn sibling(&self, address: &T::Address) -> Result<&T, ABinaryTreeDiffError> {
        let node_index = self
            .node_map
            .get(address)
            .ok_or(ABinaryTreeDiffError::NodeNotFound)?;
        let sibling_index = sibling(*node_index, self.size())?;
        self.node_by_index(sibling_index)
            .ok_or(ABinaryTreeDiffError::NodeNotFound)
    }

    /// Returns a reference to the left child of the node with the given
    /// address. Returns an error when the address points to a leaf node or to a
    /// node not in the tree.
    pub(crate) fn left_child(&self, address: &T::Address) -> Result<&T, ABinaryTreeDiffError> {
        let node_index = self
            .node_map
            .get(address)
            .ok_or(ABinaryTreeDiffError::NodeNotFound)?;
        let left_child_index = left(*node_index)?;
        self.node_by_index(left_child_index)
            .ok_or(ABinaryTreeDiffError::NodeNotFound)
    }

    /// Returns a reference to the right child of the node with the given
    /// address. Returns an error when the address points to a leaf node or to a
    /// node not in the tree.
    pub(crate) fn right_child(&self, address: &T::Address) -> Result<&T, ABinaryTreeDiffError> {
        let node_index = self
            .node_map
            .get(address)
            .ok_or(ABinaryTreeDiffError::NodeNotFound)?;
        let right_child_index = right(*node_index, self.size())?;
        self.node_by_index(right_child_index)
            .ok_or(ABinaryTreeDiffError::NodeNotFound)
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
