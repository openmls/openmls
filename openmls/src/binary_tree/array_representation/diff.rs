use std::collections::HashMap;

use std::fmt::Debug;

use crate::binary_tree::{
    array_representation::treemath::sibling, LeafIndex, MlsBinaryTreeDiffError,
};

use super::{
    tree::{to_node_index, ABinaryTree, ABinaryTreeError, NodeIndex, TreeSize},
    treemath::{direct_path, left, lowest_common_ancestor, right, root, TreeMathError},
};

#[derive(Debug)]
pub(crate) struct StagedAbDiff<T: Clone + Debug> {
    diff: HashMap<NodeIndex, T>,
}

impl<'a, T: Clone + Debug> From<AbDiff<'a, T>> for StagedAbDiff<T> {
    fn from(diff: AbDiff<'a, T>) -> Self {
        StagedAbDiff { diff: diff.diff }
    }
}

impl<T: Clone + Debug> StagedAbDiff<T> {
    pub(super) fn diff(self) -> HashMap<NodeIndex, T> {
        self.diff
    }
}

pub(crate) struct AbDiff<'a, T: Clone + Debug> {
    original_tree: &'a ABinaryTree<T>,
    diff: HashMap<NodeIndex, T>,
    size: TreeSize,
}

impl<'a, T: Clone + Debug> From<&'a ABinaryTree<T>> for AbDiff<'a, T> {
    fn from(tree: &'a ABinaryTree<T>) -> Self {
        AbDiff {
            original_tree: tree,
            diff: HashMap::new(),
            size: tree.size(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct NodeReference {
    //diff: &'a AbDiff<'a, T>,
    node_index: NodeIndex,
}

impl<'a, T: Clone + Debug> AbDiff<'a, T> {
    /// Replace the content of the node at the given leaf index with new
    /// content.
    pub(crate) fn replace_leaf(
        &mut self,
        leaf_index: LeafIndex,
        new_leaf: T,
    ) -> Result<(), ABinaryTreeDiffError> {
        if leaf_index >= self.leaf_count() {
            return Err(ABinaryTreeDiffError::OutOfBounds);
        }
        let node_index = to_node_index(leaf_index);
        self.add_to_diff(node_index, new_leaf)?;
        Ok(())
    }

    /// Extend the tree by a leaf and its new parent node.
    pub(crate) fn add_leaf(
        &mut self,
        parent_node: T,
        new_leaf: T,
    ) -> Result<LeafIndex, ABinaryTreeDiffError> {
        self.add_to_diff(self.size(), parent_node)?;
        self.add_to_diff(self.size(), new_leaf)?;
        Ok(self.leaf_count() - 1)
    }

    /// Obtain a `NodeReference` to the leaf with the given `LeafIndex`.
    pub(crate) fn leaf(
        &'a self,
        leaf_index: LeafIndex,
    ) -> Result<NodeReference, ABinaryTreeDiffError> {
        let node_index = to_node_index(leaf_index);
        self.new_reference(node_index)
    }

    /// Returns references to the leaves of the tree in order from left to
    /// right. NOTE: This is used to find blank leaves to place new members
    /// into.
    pub(crate) fn leaves(&'a self) -> Result<Vec<NodeReference>, ABinaryTreeDiffError> {
        let mut leaf_references = Vec::new();
        for leaf_index in 0..self.leaf_count() {
            let node_index = to_node_index(leaf_index);
            let node_ref = self.new_reference(node_index)?;
            leaf_references.push(node_ref);
        }
        Ok(leaf_references)
    }

    // FIXME: Come up with a better name.
    /// Sets all nodes in the direct path to a copy of the given node. NOTE:
    /// This is used to blank a direct path.
    pub(crate) fn set_direct_path_to_node(
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
    /// NOTE: This function is used to replace a direct path with new nodes
    /// (e.g. when performing an own update), or to blank a direct path.
    pub(crate) fn set_direct_path(
        &mut self,
        leaf_index: LeafIndex,
        mut path: Vec<T>,
    ) -> Result<(), ABinaryTreeDiffError> {
        let node_index = to_node_index(leaf_index);
        let direct_path =
            direct_path(node_index, self.size()).map_err(|_| ABinaryTreeError::OutOfBounds)?;
        if path.len() != direct_path.len() {
            return Err(ABinaryTreeDiffError::PathLengthMismatch);
        }
        for (node_index, node) in direct_path.iter().zip(path.drain(..)) {
            self.add_to_diff(*node_index, node)?;
        }
        Ok(())
    }

    /// Given two leaf indices, returns the position of the shared subtree root
    /// in the direct path of the first leaf index. NOTE: This function is
    /// required in the process of finding the right ciphertext to decrypt in a
    /// received `UpdatePathNode`.
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

    /// Returns the copath node of the `leaf_index_1` that is in the direct path
    /// of `leaf_index_2`. Returns an error if both leaf indices are the same.
    /// NOTE: This function is required in the process of finding the private
    /// key to decrypt a received `UpdatePathNode`.
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
        println!("subtree_root_node_index: {:?}", subtree_root_node_index);

        // Figure out which child is the relevant copath node.
        let copath_node_index = if leaf_index_2 < leaf_index_1 {
            left(subtree_root_node_index)?
        } else {
            right(subtree_root_node_index, self.size())?
        };
        println!("copath_node_index: {:?}", copath_node_index);

        let copath_node_ref = self.new_reference(copath_node_index)?;
        Ok(copath_node_ref)
    }

    /// Returns a `NodeReference` to the root of the shared subtree of the two
    /// given leaf indices, as well as `NodeReference`s to its direct path.
    pub(crate) fn subtree_path(
        &self,
        leaf_index_1: LeafIndex,
        leaf_index_2: LeafIndex,
    ) -> Result<Vec<NodeReference>, ABinaryTreeDiffError> {
        let node_index_1 = to_node_index(leaf_index_1);
        let node_index_2 = to_node_index(leaf_index_2);
        let lca = lowest_common_ancestor(node_index_1, node_index_2);
        let direct_path_indices =
            direct_path(lca, self.size()).map_err(|_| ABinaryTreeDiffError::OutOfBounds)?;
        let mut full_path = vec![self.new_reference(lca)?];
        for node_index in direct_path_indices {
            let node_ref = self.new_reference(node_index)?;
            full_path.push(node_ref);
        }

        Ok(full_path)
    }

    /// Returns a vector of `NodeReference` instances, each one referencing a
    /// node in the direct path of the given `LeafIndex`, ordered from the
    /// parent of the corresponding leaf to the root of the tree.
    pub(crate) fn direct_path(
        &'a self,
        leaf_index: LeafIndex,
    ) -> Result<Vec<NodeReference>, ABinaryTreeDiffError> {
        let node_index = to_node_index(leaf_index);
        let direct_path_indices =
            direct_path(node_index, self.size()).map_err(|_| ABinaryTreeError::OutOfBounds)?;
        println!("Direct path indices {:?}", direct_path_indices);
        let mut direct_path = Vec::new();
        for node_index in &direct_path_indices {
            let node_ref = self.new_reference(*node_index)?;
            direct_path.push(node_ref);
        }
        Ok(direct_path)
    }

    /// Returns an iterator over references to the content of all nodes in the
    /// diff. NOTE: This is required for parent hash verification when receiving
    /// a new tree.
    pub(crate) fn iter(&'a self) -> DiffIterator<'a, T> {
        DiffIterator {
            diff: self,
            current_index: 0u32,
        }
    }

    pub(crate) fn export_nodes(&self) -> Result<Vec<T>, ABinaryTreeDiffError> {
        let mut nodes = Vec::new();
        for node_index in 0..self.size() {
            // Every node index within size() should point to a node in the
            // tree.
            let node = self
                .node_by_index(node_index)
                .ok_or(ABinaryTreeDiffError::LibraryError)?;
            nodes.push(node.clone());
        }
        Ok(nodes)
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

    pub(in crate::binary_tree) fn size(&self) -> NodeIndex {
        self.size
    }

    pub(crate) fn leaf_count(&self) -> LeafIndex {
        (self.size() + 1) / 2
    }

    fn new_reference(
        &'a self,
        node_index: NodeIndex,
    ) -> Result<NodeReference, ABinaryTreeDiffError> {
        if node_index >= self.size() {
            return Err(ABinaryTreeDiffError::OutOfBounds);
        }
        Ok(NodeReference { node_index })
    }

    pub(crate) fn try_deref(&self, node_ref: NodeReference) -> Result<&T, ABinaryTreeDiffError> {
        // We only create references for nodes that are within the tree and the
        // tree can't be changed while references are out there, because
        // references include a reference to the diff.
        self.node_by_index(node_ref.node_index)
            .ok_or(ABinaryTreeDiffError::LibraryError)
    }

    pub(crate) fn try_deref_mut(
        &mut self,
        node_ref: NodeReference,
    ) -> Result<&mut T, ABinaryTreeDiffError> {
        // We only create references for nodes that are within the tree and the
        // tree can't be changed while references are out there, because
        // references include a reference to the diff.
        self.node_mut_by_index(node_ref.node_index)
            .map_err(|_| ABinaryTreeDiffError::LibraryError)
    }

    pub(crate) fn root(&self) -> NodeReference {
        let root_index = root(self.size());
        NodeReference {
            node_index: root_index,
        }
    }

    pub(crate) fn is_leaf(&self, node_ref: NodeReference) -> bool {
        node_ref.node_index % 2 == 0
    }

    /// Returns a reference to the sibling of the referenced node. Returns an
    /// error when the reference points to the root node or to a node not in the
    /// tree.
    pub(crate) fn sibling(
        &self,
        node_ref: NodeReference,
    ) -> Result<NodeReference, ABinaryTreeDiffError> {
        let sibling_index = sibling(node_ref.node_index, self.size())?;
        self.new_reference(sibling_index)
    }

    /// Returns a reference to the left child of the referenced node. Returns an
    /// error when the reference points to a leaf node or to a node not in the
    /// tree.
    pub(crate) fn left_child(
        &self,
        node_ref: NodeReference,
    ) -> Result<NodeReference, ABinaryTreeDiffError> {
        let left_child_index = left(node_ref.node_index)?;
        self.new_reference(left_child_index)
    }

    /// Returns a reference to the right child of the referenced node. Returns an
    /// error when the reference points to a leaf node or to a node not in the
    /// tree.
    pub(crate) fn right_child(
        &self,
        node_ref: NodeReference,
    ) -> Result<NodeReference, ABinaryTreeDiffError> {
        let right_child_index = right(node_ref.node_index, self.size())?;
        self.new_reference(right_child_index)
    }

    pub(crate) fn leaf_index(&self, node_ref: NodeReference) -> Option<LeafIndex> {
        if self.is_leaf(node_ref) {
            Some(node_ref.node_index / 2)
        } else {
            None
        }
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
