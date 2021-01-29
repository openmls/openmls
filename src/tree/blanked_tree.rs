#![allow(dead_code)]
//! This module provides a layer of abstraction over a simple binary tree that
//! is "blank-aware".

use super::{
    binary_tree::{errors::BinaryTreeError, BinaryTree},
    index::{LeafIndex, NodeIndex},
};

pub type BlankableTree<T> = BinaryTree<Option<T>>;

impl<T: Clone + PartialEq> BlankableTree<T> {
    /// Returns true if the node at the given index is blank and false
    /// otherwise. Returns an error if the given index is not within the tree.
    pub(crate) fn is_blank(&self, index: NodeIndex) -> Result<bool, BinaryTreeError> {
        Ok(self.node(index)?.is_none())
    }

    /// Given a node index, check if the given predicate evaluates to a
    /// non-empty vector or T-references. If that is the case, return that
    /// vector. If it returns an empty vector, recursively traverse up the left
    /// and right subtree of the node and return the gathered vectors of
    /// T-references. Returns an error if the given index is not within the
    /// tree.
    pub(crate) fn resolve<F>(
        &self,
        node_index: NodeIndex,
        predicate: &F,
    ) -> Result<Vec<NodeIndex>, BinaryTreeError>
    where
        F: Fn(NodeIndex, &T) -> Vec<NodeIndex>,
    {
        let node = self.node(node_index)?;
        if node.is_none() && !node_index.is_leaf() {
            let mut left_resolution = self.resolve(self.left(node_index).unwrap(), predicate)?;
            let right_resolution = self.resolve(self.right(node_index).unwrap(), predicate)?;
            left_resolution.extend(right_resolution);
            Ok(left_resolution)
        } else {
            // We can unwrap here, because we know that the node is not blank.
            Ok(predicate(node_index, &node.as_ref().unwrap()))
        }
    }

    /// Blank the node with the given index. Returns an error if the given index
    /// is not within the tree.
    pub(crate) fn blank(&mut self, index: NodeIndex) -> Result<(), BinaryTreeError> {
        *self.node_mut(index)? = None;
        Ok(())
    }

    /// Blank the direct path starting from the given node. Returns an error if
    /// the given index is not within the tree.
    pub(crate) fn blank_direct_path(
        &mut self,
        node_index: NodeIndex,
    ) -> Result<(), BinaryTreeError> {
        if node_index == self.root() {
            Ok(self.blank(node_index)?)
        } else {
            let parent = self.parent(node_index)?;
            Ok(self.blank_direct_path(parent)?)
        }
    }

    /// Apply the given function `f` to each node in the direct path of the node
    /// with index `node_index`, the result of the function applied to the
    /// parent is used as input to the function applied to the child. When
    /// applying `f` to the root node, the default value of `f`s return type is
    /// provided as input. Returns an error if the given index is not within the
    /// tree.
    pub(crate) fn direct_path_map<F, U: Default>(
        &mut self,
        node_index: NodeIndex,
        f: &F,
    ) -> Result<U, BinaryTreeError>
    where
        F: Fn(&mut Option<T>, U) -> U,
    {
        // If it's the root node, use the defaults as input.
        if node_index == self.root() {
            // If it's a blank, just return the default.
            let node = self.node_mut(node_index)?;
            Ok(f(node, U::default()))
        } else {
            let parent = self.parent(node_index)?;
            let parent_result = self.direct_path_map(parent, f)?;
            Ok(f(self.node_mut(node_index)?, parent_result))
        }
    }

    /// Compute a function f based on the node itself, as well as the result of
    /// the same function computed on the left and right child. Leaves return
    /// the result of the function with their node, as well as the default
    /// values for `U`. Returns an error if the given index is not within the
    /// tree.
    pub(crate) fn fold_tree<F, U: Default>(
        &self,
        node_index: &NodeIndex,
        f: &F,
    ) -> Result<U, BinaryTreeError>
    where
        F: Fn(&NodeIndex, &U, &U) -> U,
    {
        if node_index.is_leaf() {
            Ok(f(node_index, &U::default(), &U::default()))
        } else {
            let left_node = self.left(*node_index)?;
            let left_result = self.fold_tree(&left_node, f)?;
            let right_node = self.right(*node_index)?;
            let right_result = self.fold_tree(&right_node, f)?;
            Ok(f(node_index, &left_result, &right_result))
        }
    }

    /// Returns a vector with leaf indices, where each index corresponds to a
    /// blank leaf. The vector is ordered by the index of the leaf.
    fn free_leaves(&self) -> Vec<LeafIndex> {
        let mut free_leaves = Vec::new();
        for index in 0..self.leaf_count().as_usize() {
            let leaf_index = LeafIndex::from(index);
            // We can unwrap here, because index is scoped to be within the
            // tree.
            if self.leaf(leaf_index).unwrap().is_none() {
                free_leaves.push(leaf_index);
            }
        }
        free_leaves
    }

    /// Remove fully-blank subtrees on the right side.
    pub(crate) fn trim(&mut self) {
        let mut right_most_index = self.size().as_usize() - 1;
        // We can unwrap here, because the right-most index is always within the
        // tree.
        while self.is_blank(NodeIndex::from(right_most_index)).unwrap()
            && self
                .is_blank(NodeIndex::from(right_most_index - 1))
                .unwrap()
            && self.size() > NodeIndex::from(2_usize)
        {
            // We can unwrap here, because we know that the outtermost nodes are
            // blank and the tree is large enough to remove two nodes.
            self.remove(2).unwrap();
            right_most_index -= 2;
        }
    }

    /// Add a number of leaves into the first blank leaves. If not enough blank
    /// leaves exist, the tree is extended using blanks as intermediate nodes.
    /// Finally, the tree is trimmed after the operation. The returned vector
    /// contains the indices of the newly added leaves.
    pub(crate) fn add_leaves(&mut self, mut new_nodes: Vec<T>) -> Vec<LeafIndex> {
        let mut added_members = Vec::with_capacity(new_nodes.len());

        // Add new nodes for key packages into existing free leaves.
        // Note that zip makes it so only the first free_leaves().len() nodes are taken.
        let free_leaves = self.free_leaves();
        let free_leaves_len = free_leaves.len();
        for (new_node, leaf_index) in new_nodes.iter().zip(free_leaves) {
            // We can unwrap here, because `leaf_node_index` is part of
            // `free_leaves`, which in turn only contains indices that are
            // within the tree.
            self.replace(NodeIndex::from(leaf_index), Some(new_node.clone()))
                .unwrap();
            added_members.push(leaf_index);
        }
        // Add the remaining nodes.
        let mut leaf_index = self.size().as_usize() + 1;
        for new_node in new_nodes.drain(free_leaves_len..new_nodes.len()) {
            // We unwrap here, because we're adding two nodes.
            self.add(vec![None, Some(new_node.clone())]).unwrap();
            added_members.push(LeafIndex::from(leaf_index));
            leaf_index += 2;
        }
        self.trim();
        added_members
    }
}
