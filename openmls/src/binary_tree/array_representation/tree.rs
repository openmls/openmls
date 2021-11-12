//! This module contains an implementation of a binary tree based on an array
//! representation.

use std::collections::HashMap;
use std::convert::TryFrom;

use openmls_traits::OpenMlsCryptoProvider;

use super::treemath::{
    copath, direct_path, left, lowest_common_ancestor, right, root, TreeMathError,
};
use crate::{
    binary_tree::{Addressable, LeafIndex},
    ciphersuite::Ciphersuite,
};

/// The `NodeIndex` is used throughout this trait to index nodes as if the
/// underlying binary tree was implementing the array representation.
pub(crate) type NodeIndex = u32;

pub(super) fn to_node_index(leaf_index: LeafIndex) -> NodeIndex {
    leaf_index * 2
}

pub(crate) type TreeSize = NodeIndex;

#[derive(Clone, Debug)]
/// A representation of a full, left-balanced binary tree that uses a simple
/// vector to store nodes.
pub(crate) struct ABinaryTree<T: Default + Clone + Addressable> {
    nodes: Vec<T>,
    node_map: HashMap<T::Address, NodeIndex>,
}

impl<T: Default + Clone + Addressable> TryFrom<Vec<T>> for ABinaryTree<T> {
    type Error = ABinaryTreeError;

    fn try_from(nodes: Vec<T>) -> Result<Self, Self::Error> {
        Self::new(nodes)
    }
}

impl<T: Default + Clone + Addressable> ABinaryTree<T> {
    /// Create a tree from the given vector of nodes. The vector of nodes can't
    /// be empty and has to yield a full, left-balanced binary tree. The nodes
    /// in the tree are ordered in the array-representation. This function
    /// throws a `InvalidNumberOfNodes` error if the number of nodes does not
    /// allow the creation of a full, left-balanced binary tree and an
    /// `OutOfRange` error if the number of given nodes exceeds the range of
    /// `NodeIndex`.
    pub(crate) fn new(nodes: Vec<T>) -> Result<Self, ABinaryTreeError> {
        if nodes.len() > NodeIndex::max_value() as usize {
            return Err(ABinaryTreeError::OutOfRange);
        } else if nodes.len() % 2 != 1 {
            return Err(ABinaryTreeError::InvalidNumberOfNodes);
        }
        let mut node_map = HashMap::new();
        for (i, node) in nodes.iter().enumerate() {
            if let Some(address) = node.address() {
                if node_map.contains_key(&address) {
                    return Err(ABinaryTreeError::AddressCollision);
                }
                node_map.insert(address, i as u32);
            }
        }
        Ok(ABinaryTree { nodes, node_map })
    }

    /// Obtain a reference to the data contained in the `Node` at index
    /// `node_index`, where the indexing corresponds to the array representation
    /// of the underlying binary tree. Returns None if the index is outside of
    /// the tree.
    pub(super) fn node_by_index(&self, node_index: NodeIndex) -> std::option::Option<&T> {
        self.nodes.get(node_index as usize)
    }

    /// Obtain a mutable reference to the data contained in the `Node` at index
    /// `node_index`, where the indexing corresponds to the array representation
    /// of the underlying binary tree. Returns None if the index is outside of
    /// the tree.
    pub(super) fn node_mut_by_index(
        &mut self,
        node_index: NodeIndex,
    ) -> std::option::Option<&mut T> {
        self.nodes.get_mut(node_index as usize)
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

    /// Given a node, return the nodes index according to the array
    /// representation as defined in the MLS spec. If the node is not in the
    /// tree, return `None`.
    pub(crate) fn index(&self, address: &T::Address) -> Option<NodeIndex> {
        self.node_map.get(address).copied()
    }

    /// Compute the lowest common ancestor of the nodes with the given indices,
    /// where the indexing corresponds to the array representation of the
    /// underlying binary tree. Returns an `OutOfBounds` error if either of the
    /// indices is out of the bounds of the tree.
    pub(crate) fn lowest_common_ancestor(
        &self,
        address_1: &T::Address,
        address_2: &T::Address,
    ) -> Result<&T, ABinaryTreeError> {
        let node_index_1 = self
            .index(address_1)
            .ok_or(ABinaryTreeError::NodeNotFound)?;
        let node_index_2 = self
            .index(address_2)
            .ok_or(ABinaryTreeError::NodeNotFound)?;
        let lowest_common_ancestor = lowest_common_ancestor(node_index_1, node_index_2);
        self.node_by_index(lowest_common_ancestor)
            .ok_or(ABinaryTreeError::OutOfBounds)
    }

    /// Return a reference to the root node of the tree.
    pub(crate) fn root(&self) -> Result<&T, ABinaryTreeError> {
        self.nodes
            .get(root(self.size()) as usize)
            .ok_or(ABinaryTreeError::LibraryError)
    }

    /// Return an iterator over all the nodes in the tree.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.nodes.iter()
    }
}

implement_error! {
    pub enum ABinaryTreeError {
        Simple {
            OutOfRange = "Adding nodes exceeds the maximum possible size of the tree.",
            NotEnoughNodes = "Not enough nodes to remove.",
            InvalidNumberOfNodes = "The given number of nodes does not allow the creation of a full, left-balanced binary tree.",
            OutOfBounds = "The given index is outside of the tree.",
            AddressCollision = "Found two nodes with the same address.",
            InvalidNode = "Can't add the default node to the tree.",
            NodeNotFound = "Can't find the node with the given address in the tree.",
            LibraryError = "An inconsistency in the internal state of the tree was detected.",
        }
        Complex {
            TreeMathError(TreeMathError) = "Error while traversing the tree.",
        }
    }
}

#[cfg(test)]
impl PartialEq for ABinaryTree<u32> {
    fn eq(&self, other: &Self) -> bool {
        self.nodes == other.nodes
    }
}
