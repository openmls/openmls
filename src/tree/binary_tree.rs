use crate::{prelude::LeafIndex, tree::index::NodeIndex};

use super::{treemath, TreeError};

/// A binary tree in the array (vector) representation used in the MLS spec.
/// Note, that this is not a full implementation of a binary tree, but rather
/// only enables the operations needed by MLS.
#[derive(Debug, Clone)]
pub struct BinaryTree<T> {
    pub(crate) nodes: Vec<T>,
}

impl<T> From<Vec<T>> for BinaryTree<T> {
    fn from(nodes: Vec<T>) -> Self {
        BinaryTree { nodes }
    }
}

impl<T> BinaryTree<T> {
    fn check_if_within_bounds(&self, node_index: &NodeIndex) -> Result<(), TreeError> {
        if node_index >= &self.size() {
            return Err(TreeError::InvalidArguments);
        };
        Ok(())
    }

    /// Extend the tree by the given nodes on the right.
    pub(crate) fn add(&mut self, nodes: Vec<T>) {
        self.nodes.extend(nodes)
    }

    /// Extend the tree by the given nodes on the right.
    pub(crate) fn truncate(&mut self, new_length: usize) {
        self.nodes.truncate(new_length)
    }

    /// Replace the node at index `index`, consuming the new node and returning
    /// the old one.
    pub(crate) fn replace(&mut self, node_index: NodeIndex, node: T) -> Result<T, TreeError> {
        self.check_if_within_bounds(&node_index)?;
        self.nodes.push(node);
        Ok(self.nodes.swap_remove(node_index.as_usize()))
    }

    /// Get the size of the tree.
    pub(crate) fn size(&self) -> NodeIndex {
        NodeIndex::from(self.nodes.len())
    }

    /// Get a reference to a node of the tree by index.
    pub(crate) fn node(&self, node_index: &NodeIndex) -> Result<&T, TreeError> {
        self.check_if_within_bounds(node_index)?;
        Ok(&self.nodes[node_index])
    }

    /// Get a mutable reference to a node of the tree by index.
    pub(crate) fn node_mut(&mut self, node_index: &NodeIndex) -> Result<&mut T, TreeError> {
        self.check_if_within_bounds(node_index)?;
        Ok(&mut self.nodes[node_index])
    }

    pub(crate) fn leaf(&self, leaf_index: &LeafIndex) -> Result<&T, TreeError> {
        self.node(&NodeIndex::from(leaf_index.clone()))
    }

    /// Return the nodes in the CoPath of a given node.
    pub(crate) fn copath(&self, node_index: &NodeIndex) -> Result<Vec<&T>, TreeError> {
        let leaf_count = LeafIndex::from(self.size());
        let copath = treemath::copath(*node_index, leaf_count)
            .expect("Treemath error when retrieving copath nodes.");
        let mut copath_nodes = Vec::new();
        for i in copath {
            copath_nodes.push(self.node(&i)?);
        }
        Ok(copath_nodes)
    }

    /// Given a node index, check if the given predicate evaluates to a
    /// non-empty vector or T-references. If that is the case, return that
    /// vector. If it returns an empty vector, recursively traverse up the left
    /// and right subtree of the node and return the gathered vectors of
    /// T-references.
    pub(crate) fn resolve<F>(
        &self,
        node_index: &NodeIndex,
        predicate: &F,
    ) -> Result<Vec<NodeIndex>, TreeError>
    where
        F: Fn(NodeIndex, &T) -> Vec<NodeIndex>,
    {
        self.check_if_within_bounds(node_index)?;
        let node = self.node(node_index)?;
        let predicate_result = predicate(*node_index, node);
        if !predicate_result.is_empty() {
            return Ok(predicate_result);
        } else if node_index.is_leaf() {
            return Ok(vec![]);
        } else {
            let mut left_resolution =
                self.resolve(&treemath::left(*node_index).unwrap(), predicate)?;
            let right_resolution = self.resolve(
                &treemath::right(*node_index, LeafIndex::from(self.size())).unwrap(),
                predicate,
            )?;
            left_resolution.extend(right_resolution);
            return Ok(left_resolution);
        }
    }

    pub(crate) fn copath_resolution<F>(
        &self,
        node_index: &NodeIndex,
        predicate: &F,
    ) -> Result<Vec<NodeIndex>, TreeError>
    where
        F: Fn(NodeIndex, &T) -> Vec<NodeIndex>,
    {
        let leaf_count = LeafIndex::from(self.size());
        let copath = treemath::copath(*node_index, leaf_count)
            .expect("Treemath error when retrieving copath nodes.");
        let mut resolution = Vec::new();
        for copath_index in copath {
            let copath_index_resolution = self.resolve(&copath_index, predicate)?;
            resolution.extend(copath_index_resolution);
        }
        Ok(resolution)
    }

    // Probably a few more functions to manipulate the `BinaryTree`.
}
