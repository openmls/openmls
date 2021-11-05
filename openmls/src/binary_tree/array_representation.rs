//! This module contains an implementation of a binary tree based on an array
//! representation.

use std::collections::HashMap;
use std::convert::TryFrom;
use std::hash::Hash;

use super::treemath::*;
use super::NodeIndex;
use super::TreeSize;

/// This trait requires the implementer to provide each instance with an
/// `Address`. The address MUST be unique per instance.
pub trait Addressable {
    type Address: PartialEq + Eq + Hash;

    /// Returns the address of this node. If it's the default node, return `None`
    /// instead.
    fn address(&self) -> Option<Self::Address>;
}

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
        Self::new(&nodes)
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
    pub(crate) fn new(nodes: &[T]) -> Result<Self, ABinaryTreeError> {
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
        Ok(ABinaryTree {
            nodes: nodes.to_vec(),
            node_map,
        })
    }

    /// Obtain a reference to the data contained in the `Node` at index
    /// `node_index`, where the indexing corresponds to the array representation
    /// of the underlying binary tree. Returns None if the index is outside of
    /// the tree.
    fn node_by_index(&self, node_index: NodeIndex) -> std::option::Option<&T> {
        self.nodes.get(node_index as usize)
    }

    /// Obtain a reference to the data contained in the `Node` with `Address`
    /// `address`. Returns `None` if no node with the given address can be
    /// found.
    pub(crate) fn node(&self, node_address: &T::Address) -> std::option::Option<&T> {
        self.node_map
            .get(node_address)
            .map(|&node_index| self.nodes.get(node_index as usize))
            .flatten()
    }

    /// Replaces the node with the given address with the given
    /// `replacement_node`. Upon success, returns the replaced node. Returns an
    /// error if the `node_address can't be found in the tree.`
    pub(crate) fn replace(
        &mut self,
        node_address: &T::Address,
        replacement_node: T,
    ) -> Result<T, ABinaryTreeError> {
        // Remove the old address from the map and retrieve the index.
        let old_node_index = self
            .node_map
            .remove(node_address)
            .ok_or(ABinaryTreeError::NodeNotFound)?;
        // Double-check that the given index is actually inside the tree. This
        // is explicitly to prevent swap_remove from panicking.
        if old_node_index >= self.size() {
            return Err(ABinaryTreeError::LibraryError);
        }
        // Insert the new address to the map
        if let Some(new_address) = replacement_node.address() {
            self.node_map.insert(new_address, old_node_index);
        };
        // Push the new node to the end of the vector, so we can do a
        // `swap_remove`.
        self.nodes.push(replacement_node);
        Ok(self.nodes.swap_remove(old_node_index as usize))
    }

    /// Adds the given node as a new leaf to right side of the tree. To keep the
    /// tree full, a parent node is added using the `Default` constructor.
    /// Returns an `OutOfRange` error if the number of nodes exceeds the range
    /// of `NodeIndex`, an `AddressCollision` error if a node with the same
    /// address already exists in the tree and an `InvalidNode` error if the
    /// node does not have an address.
    pub(crate) fn add_leaf(&mut self, node: T) -> Result<(), ABinaryTreeError> {
        // Prevent the tree from becoming too large.
        if self.nodes.len() > NodeIndex::max_value() as usize - 2 {
            return Err(ABinaryTreeError::OutOfRange);
        } // Make sure that the input node has an address.
        let address = node.address().ok_or(ABinaryTreeError::InvalidNode)?;
        // Check if a node with this address already exists in the tree.
        if self.node_map.contains_key(&address) {
            return Err(ABinaryTreeError::AddressCollision);
        }
        self.node_map.insert(address, (self.nodes.len() + 1) as u32);
        self.nodes.push(T::default());
        self.nodes.push(node);
        Ok(())
    }

    /// Helper function to remove a node from the tree and the map.
    fn remove_node(&mut self) -> Result<(), ABinaryTreeError> {
        let node = self.nodes.pop().ok_or(ABinaryTreeError::NotEnoughNodes)?;
        if let Some(address) = node.address() {
            let removed_node = self.node_map.remove(&address);
            debug_assert!(removed_node.is_some())
        }
        Ok(())
    }

    /// Remove the two rightmost nodes of the tree. This will throw a
    /// `NotEnoughNodes` error if there are not enough nodes to remove.
    pub(crate) fn remove(&mut self) -> Result<(), ABinaryTreeError> {
        // Check that there are enough nodes to remove.
        if self.nodes.len() < 2 {
            return Err(ABinaryTreeError::NotEnoughNodes);
        }
        self.remove_node()?;
        self.remove_node()?;
        Ok(())
    }

    /// Replace the node with the given `Address` with the `default` node and
    /// return the replaced node. Returns an error if the given address doesn't
    /// correspond to a node in the tree.
    pub(crate) fn make_default(
        &mut self,
        node_address: &T::Address,
    ) -> Result<T, ABinaryTreeError> {
        self.replace(node_address, T::default())
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

    /// Compute the direct path from the node with the given `T::Address` to the
    /// root node and return the vector of nodes on the direct path.
    pub(crate) fn direct_path(&self, address: &T::Address) -> Result<Vec<&T>, ABinaryTreeError> {
        let node_index = self.index(address).ok_or(ABinaryTreeError::NodeNotFound)?;
        let direct_path =
            direct_path(node_index, self.size()).map_err(|_| ABinaryTreeError::OutOfBounds)?;
        let mut direct_path_nodes = Vec::new();
        for node_index in direct_path {
            direct_path_nodes.push(
                self.node_by_index(node_index)
                    .ok_or(ABinaryTreeError::OutOfBounds)?,
            )
        }
        Ok(direct_path_nodes)
    }

    /// Compute the copath path from the node with the given index to the root
    /// node and return the vector of indices of the nodes on the copath, where
    /// the indexing corresponds to the array representation of the underlying
    /// binary tree.
    pub(crate) fn copath(&self, address: &T::Address) -> Result<Vec<&T>, ABinaryTreeError> {
        let node_index = self.index(address).ok_or(ABinaryTreeError::NodeNotFound)?;
        let copath = copath(node_index, self.size()).map_err(|_| ABinaryTreeError::OutOfBounds)?;
        let mut copath_nodes = Vec::new();
        for node_index in copath {
            copath_nodes.push(
                self.node_by_index(node_index)
                    .ok_or(ABinaryTreeError::OutOfBounds)?,
            )
        }
        Ok(copath_nodes)
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
}

implement_error! {
    pub enum ABinaryTreeError {
        OutOfRange = "Adding nodes exceeds the maximum possible size of the tree.",
        NotEnoughNodes = "Not enough nodes to remove.",
        InvalidNumberOfNodes = "The given number of nodes does not allow the creation of a full, left-balanced binary tree.",
        OutOfBounds = "The given index is outside of the tree.",
        AddressCollision = "Found two nodes with the same address.",
        InvalidNode = "Can't add the default node to the tree.",
        NodeNotFound = "Can't find the node with the given address in the tree.",
        LibraryError = "An inconsistency in the internal state of the tree was detected.",
    }
}

#[cfg(test)]
impl PartialEq for ABinaryTree<u32> {
    fn eq(&self, other: &Self) -> bool {
        self.nodes == other.nodes
    }
}
