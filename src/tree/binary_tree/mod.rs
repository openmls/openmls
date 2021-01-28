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

/// A binary tree in the array (vector) representation used in the MLS spec.
/// Note, that this is not a full implementation of a binary tree, but rather
/// only enables the operations needed by MLS.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct BinaryTree<T: PartialEq> {
    nodes: Vec<T>,
}

impl<T: PartialEq> From<Vec<T>> for BinaryTree<T> {
    fn from(nodes: Vec<T>) -> Self {
        BinaryTree { nodes }
    }
}

impl<T: PartialEq> BinaryTree<T> {
    /// Get the size of the tree.
    pub(crate) fn size(&self) -> NodeIndex {
        NodeIndex::from(self.nodes.len())
    }

    /// Get the number of leaves in the tree.
    pub(crate) fn leaf_count(&self) -> LeafIndex {
        // We unwrap here, because we assume the tree to be full.
        LeafIndex::try_from(self.size()).unwrap()
    }

    pub(crate) fn root(&self) -> NodeIndex {
        let w = self.size();
        NodeIndex::from((1usize << log2(w.as_usize())) - 1)
    }

    fn is_out_of_bounds(&self, index: NodeIndex) -> Result<(), BinaryTreeError> {
        if index > self.size() {
            return Err(BinaryTreeError::IndexOutOfBounds);
        };
        Ok(())
    }

    pub(crate) fn left(&self, index: NodeIndex) -> Result<NodeIndex, BinaryTreeError> {
        self.is_out_of_bounds(index)?;
        let x = index.as_usize();
        let k = level(NodeIndex::from(x));
        if k == 0 {
            return Err(BinaryTreeError::LeafHasNoChildren);
        }
        Ok(NodeIndex::from(x ^ (0x01 << (k - 1))))
    }

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

    pub(crate) fn sibling(&self, index: NodeIndex) -> Result<NodeIndex, BinaryTreeError> {
        let p = self.parent(index)?;
        match index.cmp(&p) {
            Ordering::Less => self.right(p),
            Ordering::Greater => self.left(p),
            Ordering::Equal => self.left(p),
        }
    }

    // Ordered from leaf to root
    // Includes neither leaf nor root
    pub(crate) fn dirpath(&self, index: NodeIndex) -> Result<Vec<NodeIndex>, BinaryTreeError> {
        let r = self.root();
        if index == r {
            return Ok(vec![]);
        }

        let mut d = vec![];
        let mut x = self.parent(index)?;
        while x != r {
            d.push(x);
            x = self.parent(x)?;
        }
        Ok(d)
    }

    // Ordered from leaf to root
    // Includes leaf and root
    pub(crate) fn direct_path(&self, index: NodeIndex) -> Result<Vec<NodeIndex>, BinaryTreeError> {
        let r = self.root();
        if index == r {
            return Ok(vec![r]);
        }

        let mut x = index;
        let mut d = vec![index];
        while x != r {
            x = self.parent(x)?;
            d.push(x);
        }
        Ok(d)
    }

    // Ordered from leaf to root
    // Includes root but not leaf
    pub(crate) fn direct_path_root(
        &self,
        index: NodeIndex,
    ) -> Result<Vec<NodeIndex>, BinaryTreeError> {
        let r = self.root();
        if index == r {
            return Ok(vec![r]);
        }

        let mut d = vec![];
        let mut x = index;
        while x != r {
            x = self.parent(x)?;
            d.push(x);
        }
        Ok(d)
    }

    // Ordered from leaf to root
    pub(crate) fn copath(&self, index: NodeIndex) -> Result<Vec<NodeIndex>, BinaryTreeError> {
        if index == self.root() {
            return Ok(vec![]);
        }
        let mut d = vec![index];
        d.append(&mut self.dirpath(index)?);
        d.iter().map(|&index| self.sibling(index)).collect()
    }

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
    /// the old one.
    pub(crate) fn replace(
        &mut self,
        node_index: &NodeIndex,
        node: T,
    ) -> Result<T, BinaryTreeError> {
        // Check if the index is within bounds to prevent `swap_remove` from
        // panicking.
        if node_index >= &self.size() {
            return Err(BinaryTreeError::IndexOutOfBounds);
        };
        // First push the node to the end of the nodes array.
        self.nodes.push(node);
        // Then use `swap_remove`, which replaces the target node with the one
        // at the end of the vector.
        Ok(self.nodes.swap_remove(node_index.as_usize()))
    }

    /// Add nodes to the tree on the right side such that the tree is still
    /// left-balanced. The number of nodes added has to be even, as we want the
    /// tree to remain full.
    pub(crate) fn add(&mut self, nodes: Vec<T>) -> Result<(), BinaryTreeError> {
        if nodes.len() % 2 != 0 {
            return Err(BinaryTreeError::TreeNotFull);
        }
        self.nodes.extend(nodes);
        Ok(())
    }

    /// Remove the right-most node.
    pub(crate) fn remove(&mut self, nodes_to_remove: usize) -> Result<(), BinaryTreeError> {
        if nodes_to_remove % 2 != 0 {
            return Err(BinaryTreeError::TreeNotFull);
        } else if nodes_to_remove > self.size().as_usize() {
            return Err(BinaryTreeError::NotEnoughNodes);
        }
        self.nodes
            .drain(self.nodes.len() - nodes_to_remove..self.nodes.len());
        Ok(())
    }

    /// Truncate the tree to size `size` by removing nodes on the right until
    /// the tree has reached size `size`.
    #[cfg(test)]
    pub(crate) fn truncate(&mut self, size: usize) {
        self.nodes.truncate(size);
    }

    /// Get a reference to a node of the tree by index.
    pub(crate) fn node(&self, node_index: &NodeIndex) -> Result<&T, BinaryTreeError> {
        self.nodes
            .get(node_index.as_usize())
            .ok_or(BinaryTreeError::IndexOutOfBounds)
    }

    /// Get a mutable reference to a node of the tree by index.
    pub(crate) fn node_mut(&mut self, node_index: &NodeIndex) -> Result<&mut T, BinaryTreeError> {
        self.nodes
            .get_mut(node_index.as_usize())
            .ok_or(BinaryTreeError::IndexOutOfBounds)
    }

    /// Get a reference to a leaf of the tree by index.
    pub(crate) fn leaf(&self, leaf_index: &LeafIndex) -> Result<&T, BinaryTreeError> {
        self.node(&NodeIndex::from(leaf_index))
    }

    /// Get a mutable reference to a leaf of the tree by index.
    pub(crate) fn leaf_mut(&mut self, leaf_index: &LeafIndex) -> Result<&mut T, BinaryTreeError> {
        self.node_mut(&NodeIndex::from(leaf_index))
    }

    /// Given two nodes `origin` and `target`, return the index of the node in
    /// the copath of the `origin`, such that the `target` is in the subtree of
    /// the returned node.
    pub(crate) fn copath_node(
        &self,
        copath_origin: &NodeIndex,
        copath_target: &NodeIndex,
    ) -> Result<NodeIndex, BinaryTreeError> {
        let copath = self.copath(*copath_origin)?;

        let target_direct_path = self.direct_path_root(*copath_target).unwrap();
        let copath_node_index = match target_direct_path.iter().find(|x| copath.contains(x)) {
            Some(index) => index.to_owned(),
            None => copath_target.to_owned(),
        };
        Ok(copath_node_index)
    }

    /// Return a reference to the nodes of the tree as a Vector.
    pub(crate) fn nodes(&self) -> &Vec<T> {
        &self.nodes
    }
}
