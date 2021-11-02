//! This module contains an implementation of a binary tree based on an array
//! representation.

use std::collections::HashMap;
use std::hash::Hash;

use super::treemath::*;
use super::NodeIndex;
use super::TreeSize;

/// This trait requires the implementer to provide each instance with an
/// `Address`. The address MUST be unique per instance.
pub trait Addressable {
    type Address: PartialEq + Eq + Hash;

    /// Return the address of this node.
    fn address(&self) -> Self::Address;

    /// Return the address associated with the default node.
    fn default_address() -> Self::Address;
}

#[derive(Clone, Debug)]
/// A representation of a full, left-balanced binary tree that uses a simple
/// vector to store nodes.
pub(crate) struct ABinaryTree<T: Default + Clone + Addressable> {
    nodes: Vec<T>,
    node_map: HashMap<T::Address, NodeIndex>,
}

impl<T: Default + Clone + Addressable> ABinaryTree<T> {
    /// Check if a given index is still within the tree.
    pub(crate) fn node_in_tree(&self, node_index: NodeIndex) -> Result<(), ABinaryTreeError> {
        node_in_tree(node_index, self.size()).map_err(|_| ABinaryTreeError::OutOfBounds)
    }

    /// Create a tree from the given vector of nodes. The nodes are ordered in
    /// the array-representation. Throws a `InvalidNumberOfNodes` error if the
    /// number of nodes does not allow the creation of a full, left-balanced
    /// binary tree and an `OutOfRange` error if the number of given nodes
    /// exceeds the range of `NodeIndex`.
    pub(crate) fn new(nodes: &[T]) -> Result<Self, ABinaryTreeError> {
        if nodes.len() > NodeIndex::max_value() as usize {
            Err(ABinaryTreeError::OutOfRange)
        } else if nodes.len() % 2 != 1 {
            Err(ABinaryTreeError::InvalidNumberOfNodes)
        } else {
            let mut node_map = HashMap::new();
            for (i, node) in nodes.iter().enumerate() {
                if node_map.contains_key(&node.address()) {
                    return Err(ABinaryTreeError::AddressCollision);
                } else if node.address() != T::default_address() {
                    node_map.insert(node.address(), i as u32);
                }
            }
            Ok(ABinaryTree {
                nodes: nodes.to_vec(),
                node_map,
            })
        }
    }

    /// Obtain a reference to the data contained in the `Node` at index
    /// `node_index`, where the indexing corresponds to the array representation
    /// of the underlying binary tree. Returns None if the index is outside of
    /// the tree.
    pub(crate) fn node(&self, node_index: NodeIndex) -> std::option::Option<&T> {
        self.nodes.get(node_index as usize)
    }

    /// Obtain a reference to the data contained in the `Node` with `Address`
    /// `address`. Returns `None` if no node with the given address can be
    /// found.
    pub(crate) fn node_by_address(&self, node_address: &T::Address) -> std::option::Option<&T> {
        self.node_map
            .get(node_address)
            .map(|&node_index| self.nodes.get(node_index as usize))
            .flatten()
    }

    /// Obtain a mutable reference to the data contained in the `Node` at index
    /// `node_index`, where the indexing corresponds to the array representation
    /// of the underlying binary tree. Returns an error if the index is outside
    /// of the tree.
    pub(crate) fn node_mut(&mut self, node_index: NodeIndex) -> std::option::Option<&mut T> {
        self.nodes.get_mut(node_index as usize)
    }

    /// Adds the given node as a new leaf to right side of the tree. To keep
    /// the tree full, a parent node is added using the `Default` constructor.
    /// Returns an `OutOfRange` error if the number of nodes exceeds the range
    /// of `NodeIndex`.
    pub(crate) fn add_leaf(&mut self, node: T) -> Result<(), ABinaryTreeError> {
        // Prevent the tree from becoming too large.
        if self.nodes.len() > NodeIndex::max_value() as usize - 2 {
            Err(ABinaryTreeError::OutOfRange)
        } else if node.address() == T::default_address() {
            return Err(ABinaryTreeError::InvalidNode);
        } else if self.node_map.contains_key(&node.address()) {
            return Err(ABinaryTreeError::AddressCollision);
        } else {
            self.node_map
                .insert(node.address(), (self.nodes.len() + 1) as u32);
            self.nodes.push(T::default());
            self.nodes.push(node);
            Ok(())
        }
    }

    /// Helper function to remove a node from the tree and the map.
    fn remove_node(&mut self) -> Result<(), ABinaryTreeError> {
        let node = self.nodes.pop().ok_or(ABinaryTreeError::NotEnoughNodes)?;
        if node.address() != T::default_address() {
            self.node_map.remove(&node.address());
        }
        Ok(())
    }

    /// Remove the two rightmost nodes of the tree. This will throw a
    /// `NotEnoughNodes` error if there are not enough nodes to remove.
    pub(crate) fn remove(&mut self) -> Result<(), ABinaryTreeError> {
        // Check that there are enough nodes to remove.
        if self.nodes.len() < 2 {
            Err(ABinaryTreeError::NotEnoughNodes)
        } else {
            self.remove_node()?;
            self.remove_node()?;
            Ok(())
        }
    }

    /// Return the number of nodes in the tree.
    pub(crate) fn size(&self) -> NodeIndex {
        let len = self.nodes.len();
        debug_assert!(len <= u32::MAX as usize);
        self.nodes.len() as u32
    }

    /// Return the number of leaves in the tree.
    pub(crate) fn leaf_count(&self) -> TreeSize {
        (self.size() + 1) / 2
    }

    /// Compute the direct path from the node with the given index to the root
    /// node and return the vector of indices of the nodes on the direct path,
    /// where the indexing corresponds to the array representation of the
    /// underlying binary tree.
    pub(crate) fn direct_path(&self, node_index: NodeIndex) -> Result<Vec<&T>, ABinaryTreeError> {
        let direct_path =
            direct_path(node_index, self.size()).map_err(|_| ABinaryTreeError::OutOfBounds)?;
        let mut direct_path_nodes = Vec::new();
        for node_index in direct_path {
            direct_path_nodes.push(self.node(node_index).ok_or(ABinaryTreeError::OutOfBounds)?)
        }
        Ok(direct_path_nodes)
    }

    /// Compute the copath path from the node with the given index to the root
    /// node and return the vector of indices of the nodes on the copath, where
    /// the indexing corresponds to the array representation of the underlying
    /// binary tree.
    pub(crate) fn copath(&self, node_index: NodeIndex) -> Result<Vec<&T>, ABinaryTreeError> {
        let copath = copath(node_index, self.size()).map_err(|_| ABinaryTreeError::OutOfBounds)?;
        let mut copath_nodes = Vec::new();
        for node_index in copath {
            copath_nodes.push(self.node(node_index).ok_or(ABinaryTreeError::OutOfBounds)?)
        }
        Ok(copath_nodes)
    }

    /// Given a node, return the nodes index according to the array
    /// representation as defined in the MLS spec. If the node is not in the
    /// tree, return `None`.
    pub(crate) fn index(&self, node: &T) -> Option<NodeIndex> {
        self.nodes
            .iter()
            .position(|array_node| array_node.address() == node.address())
            .map(|index| index as u32)
    }

    /// Compute the lowest common ancestor of the nodes with the given indices,
    /// where the indexing corresponds to the array representation of the
    /// underlying binary tree. Returns an `OutOfBounds` error if either of the
    /// indices is out of the bounds of the tree.
    pub(crate) fn lowest_common_ancestor(
        &self,
        node_1: &T,
        node_2: &T,
    ) -> Result<&T, ABinaryTreeError> {
        let node_index_1 = self.index(node_1).ok_or(ABinaryTreeError::OutOfBounds)?;
        let node_index_2 = self.index(node_2).ok_or(ABinaryTreeError::OutOfBounds)?;
        self.node_in_tree(node_index_1)?;
        self.node_in_tree(node_index_2)?;
        let lowest_common_ancestor = lowest_common_ancestor(node_index_1, node_index_2);
        self.node(lowest_common_ancestor)
            .ok_or(ABinaryTreeError::OutOfBounds)
    }
}

implement_error! {
    pub enum ABinaryTreeError {
        OutOfRange = "Adding nodes exceeds the maximum possible size of the tree.",
        NotEnoughNodes = "Not enough nodes to remove.",
        InvalidNumberOfNodes = "The given number of nodes does not allow the creation of a full, left-balanced binary tree.",
        OutOfBounds = "The given index is outside of the tree.",
        AddressCollision = "Found two nodes with the same address.",
        InvalidNode = "Can't add the default node to the tree.",
    }
}

#[cfg(test)]
impl PartialEq for ABinaryTree<u32> {
    fn eq(&self, other: &Self) -> bool {
        self.nodes == other.nodes
    }
}
