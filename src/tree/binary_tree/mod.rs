#![allow(dead_code)]
use std::{cmp::Ordering, convert::TryFrom};

use crate::{tree::index::LeafIndex, tree::index::NodeIndex};

pub(crate) use serde::{Deserialize, Serialize};

use self::errors::BinaryTreeError;
use self::utils::*;

pub(crate) mod errors;
#[cfg(test)]
pub(crate) mod test_binary_tree;
pub(crate) mod utils;

/// A full binary tree in the array (vector) representation used in the MLS
/// spec. Note, that this is not a full implementation of a binary tree, but
/// rather only enables the operations needed by MLS.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct BinaryTree<T: PartialEq> {
    nodes: Vec<T>,
}

impl<T: PartialEq> TryFrom<Vec<T>> for BinaryTree<T> {
    type Error = BinaryTreeError;

    /// Create a binary tree from a vector of nodes. Throws an error if the
    /// number of given nodes can not be represented as a full tree.
    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        if value.len() % 2 != 1 {
            return Err(BinaryTreeError::TreeNotFull);
        }
        Ok(BinaryTree { nodes: value })
    }
}

impl<T: PartialEq> BinaryTree<T> {
    /// Get the size of the tree.
    pub(crate) fn size(&self) -> NodeIndex {
        NodeIndex::from(self.nodes.len())
    }

    /// Get the number of leaves in the tree.
    pub(crate) fn leaf_count(&self) -> LeafIndex {
        LeafIndex::from((self.size().as_usize() + 1) / 2)
    }

    /// Get the index corresponding to the root of the tree.
    pub(crate) fn root(&self) -> NodeIndex {
        let w = self.size();
        NodeIndex::from((1usize << log2(w.as_usize())) - 1)
    }

    fn is_out_of_bounds(&self, index: NodeIndex) -> Result<(), BinaryTreeError> {
        if index >= self.size() {
            return Err(BinaryTreeError::IndexOutOfBounds);
        };
        Ok(())
    }

    /// Returns the index of the left child of the node corresponding to the
    /// given index. Throws an error if the given node is a leaf node or if the
    /// index is out of bounds.
    pub(crate) fn left(&self, index: NodeIndex) -> Result<NodeIndex, BinaryTreeError> {
        self.is_out_of_bounds(index)?;
        let x = index.as_usize();
        let k = level(NodeIndex::from(x));
        if k == 0 {
            return Err(BinaryTreeError::LeafHasNoChildren);
        }
        Ok(NodeIndex::from(x ^ (0x01 << (k - 1))))
    }

    /// Returns the index of the right child of the node corresponding to the
    /// given index. Throws an error if the given node is a leaf node or if the
    /// index is out of bounds.
    pub(crate) fn right(&self, index: NodeIndex) -> Result<NodeIndex, BinaryTreeError> {
        self.is_out_of_bounds(index)?;
        let size = self.leaf_count();
        let x = index.as_usize();
        let n = size.as_usize();
        let k = level(NodeIndex::from(x));
        if k == 0 {
            return Err(BinaryTreeError::LeafHasNoChildren);
        }
        let mut r = x ^ (0x03 << (k - 1));
        while r >= node_width(n) {
            r = self.left(NodeIndex::from(r))?.as_usize();
        }
        Ok(NodeIndex::from(r))
    }

    /// Returns the index of the parent of the node corresponding to the given
    /// index. Throws an error if the given node is the root node or if the
    /// index is out of bounds.
    pub(crate) fn parent(&self, index: NodeIndex) -> Result<NodeIndex, BinaryTreeError> {
        self.is_out_of_bounds(index)?;
        let size = self.leaf_count();
        let x = index.as_usize();
        let n = size.as_usize();
        if index == self.root() {
            return Err(BinaryTreeError::RootHasNoParent);
        }
        let mut p = parent_step(x);
        while p >= node_width(n) {
            p = parent_step(p)
        }
        Ok(NodeIndex::from(p))
    }

    /// Returns the index of the sibling of the node corresponding to the
    /// given index. Throws an error if the given node is the root node or if
    /// the index is out of bounds.
    pub(crate) fn sibling(&self, index: NodeIndex) -> Result<NodeIndex, BinaryTreeError> {
        let p = self.parent(index)?;
        match index.cmp(&p) {
            Ordering::Less => self.right(p),
            Ordering::Greater => self.left(p),
            Ordering::Equal => self.left(p),
        }
    }

    /// Direct path from a leaf node to the root. Does not include the leaf node
    /// but includes the root. If the given leaf index is also the root index,
    /// it returns the given index. Throws an error if the given leaf index is
    /// out of bounds.
    pub(crate) fn leaf_direct_path(
        &self,
        leaf_index: LeafIndex,
    ) -> Result<Vec<NodeIndex>, BinaryTreeError> {
        let node_index = NodeIndex::from(leaf_index);
        self.is_out_of_bounds(node_index)?;
        let r = self.root();
        if node_index == r {
            return Ok(vec![r]);
        }

        let mut d = vec![];
        let mut x = node_index;
        while x != r {
            x = self.parent(x)?;
            d.push(x);
        }
        Ok(d)
    }

    /// Direct path from a parent node to the root. Includes the parent node and
    /// the root. If the given leaf index is also the root index, it returns the
    /// given index. Returns an error if the `index` is not a parent node or if
    /// it's out of bounds.
    pub(crate) fn parent_direct_path(
        &self,
        node_index: NodeIndex,
    ) -> Result<Vec<NodeIndex>, BinaryTreeError> {
        if !node_index.is_parent() {
            return Err(BinaryTreeError::NotAParentNode);
        }
        self.is_out_of_bounds(node_index)?;
        let r = self.root();
        if node_index == r {
            return Ok(vec![r]);
        }

        let mut x = node_index;
        let mut d = vec![node_index];
        while x != r {
            x = self.parent(x)?;
            d.push(x);
        }
        Ok(d)
    }

    /// Copath of a leaf. Ordered from leaf to root. Throws an error if the
    /// given leaf index is out of bounds.
    pub(crate) fn copath(&self, leaf_index: LeafIndex) -> Result<Vec<NodeIndex>, BinaryTreeError> {
        let node_index = NodeIndex::from(leaf_index);
        // If the tree only has one leaf
        if node_index == self.root() {
            return Ok(vec![]);
        }
        // Add leaf node
        let mut d = vec![node_index];
        // Add direct path
        d.append(&mut self.leaf_direct_path(leaf_index)?);
        // Remove root node
        d.pop();
        // Calculate copath
        d.iter()
            .map(|&node_index| self.sibling(node_index))
            .collect()
    }

    /// Get the index of the common ancestor of the nodes corresponding to the
    /// two given indices. Throws an error if one of the indices is out of
    /// bounds.
    pub(crate) fn common_ancestor(
        &self,
        x: NodeIndex,
        y: NodeIndex,
    ) -> Result<NodeIndex, BinaryTreeError> {
        self.is_out_of_bounds(x)?;
        self.is_out_of_bounds(y)?;
        let (lx, ly) = (level(x) + 1, level(y) + 1);
        if (lx <= ly) && (x.as_usize() >> ly == y.as_usize() >> ly) {
            return Ok(y);
        } else if (ly <= lx) && (x.as_usize() >> lx == y.as_usize() >> lx) {
            return Ok(x);
        }

        let (mut xn, mut yn) = (x.as_usize(), y.as_usize());
        let mut k = 0;
        while xn != yn {
            xn >>= 1;
            yn >>= 1;
            k += 1;
        }
        Ok(NodeIndex::from((xn << k) + (1 << (k - 1)) - 1))
    }

    /// Replace the node at index `index`, consuming the new node and returning
    /// the old one. Throws an error if the given index is out of bounds.
    pub(crate) fn replace(&mut self, node_index: NodeIndex, node: T) -> Result<T, BinaryTreeError> {
        self.is_out_of_bounds(node_index)?;
        // First push the node to the end of the nodes array.
        self.nodes.push(node);
        // Then use `swap_remove`, which replaces the target node with the one
        // at the end of the vector.
        Ok(self.nodes.swap_remove(node_index.as_usize()))
    }

    /// Add nodes to the tree on the right side such that the tree is still
    /// left-balanced. The number of nodes added has to be even, as we want the
    /// tree to remain full. Throws an error if the number of nodes added would
    /// cause the tree to become non-full, i.e. if the number of nodes added
    /// modulo 2 is not zero.
    pub(crate) fn add(&mut self, nodes: Vec<T>) -> Result<(), BinaryTreeError> {
        if nodes.len() % 2 != 0 {
            return Err(BinaryTreeError::TreeNotFull);
        }
        self.nodes.extend(nodes);
        Ok(())
    }

    /// Remove the given number of nodes from the right of the tree. Throws an
    /// error if the number of nodes to remove is either larger than the size of
    /// the tree or if it would cause the tree to become non-full, i.e. if the
    /// number of nodes to remove modulo 2 is not zero.
    pub(crate) fn remove(&mut self, nodes_to_remove: usize) -> Result<(), BinaryTreeError> {
        // We can't have a non-full tree.
        if nodes_to_remove % 2 != 0 {
            return Err(BinaryTreeError::TreeNotFull);
        // The following ensures that we always have at least one node left.
        } else if nodes_to_remove >= self.size().as_usize() {
            return Err(BinaryTreeError::NotEnoughNodes);
        }
        self.nodes
            .drain(self.nodes.len() - nodes_to_remove..self.nodes.len());
        Ok(())
    }

    /// Get a reference to a node of the tree by index. Throws an error if the
    /// given index is out of bounds.
    pub(crate) fn node(&self, node_index: NodeIndex) -> Result<&T, BinaryTreeError> {
        self.nodes
            .get(node_index.as_usize())
            .ok_or(BinaryTreeError::IndexOutOfBounds)
    }

    /// Get a mutable reference to a node of the tree by index. Throws an error
    /// if the given index is out of bounds.
    pub(crate) fn node_mut(&mut self, node_index: NodeIndex) -> Result<&mut T, BinaryTreeError> {
        self.nodes
            .get_mut(node_index.as_usize())
            .ok_or(BinaryTreeError::IndexOutOfBounds)
    }

    /// Get a reference to a leaf of the tree by index. Throws an error if the
    /// given leaf index is out of bounds.
    pub(crate) fn leaf(&self, leaf_index: LeafIndex) -> Result<&T, BinaryTreeError> {
        self.node(NodeIndex::from(leaf_index))
    }

    /// Get a mutable reference to a leaf of the tree by index. Throws an error
    /// if the given leaf index is out of bounds.
    pub(crate) fn leaf_mut(&mut self, leaf_index: LeafIndex) -> Result<&mut T, BinaryTreeError> {
        self.node_mut(NodeIndex::from(leaf_index))
    }

    /// Given two nodes `origin` and `target`, return the index of the node in
    /// the copath of the `origin`, such that the `target` is in the subtree of
    /// the returned node. Throws an error if one of the given leaf indices is
    /// out of bounds.
    pub(crate) fn copath_node(
        &self,
        copath_origin: LeafIndex,
        copath_target: LeafIndex,
    ) -> Result<NodeIndex, BinaryTreeError> {
        let copath = self.copath(copath_origin)?;

        let target_direct_path = self.leaf_direct_path(copath_target).unwrap();
        let copath_node_index = match target_direct_path.iter().find(|&x| copath.contains(x)) {
            Some(index) => index.to_owned(),
            None => NodeIndex::from(copath_target),
        };
        Ok(copath_node_index)
    }

    /// Return a reference to the nodes of the tree as a Vector.
    pub(crate) fn nodes(&self) -> &Vec<T> {
        &self.nodes
    }
}
