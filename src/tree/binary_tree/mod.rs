use crate::{prelude::LeafIndex, tree::index::NodeIndex};

use self::errors::BinaryTreeError;

use super::treemath;

pub(crate) mod errors;
#[cfg(test)]
pub(crate) mod test_binary_tree;

/// A binary tree in the array (vector) representation used in the MLS spec.
/// Note, that this is not a full implementation of a binary tree, but rather
/// only enables the operations needed by MLS.
#[derive(Debug, Clone)]
pub struct BinaryTree<T> {
    nodes: Vec<T>,
}

impl<T> From<Vec<T>> for BinaryTree<T> {
    fn from(nodes: Vec<T>) -> Self {
        BinaryTree { nodes }
    }
}

impl<T> BinaryTree<T> {
    /// Extend the tree by the given nodes on the right.
    pub(crate) fn add(&mut self, nodes: Vec<T>) {
        self.nodes.extend(nodes)
    }

    /// Truncate the tree by removing nodes from the right until the tree has
    /// size `new_length`.
    pub(crate) fn truncate(&mut self, new_length: usize) {
        self.nodes.truncate(new_length)
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

    /// Get the size of the tree.
    pub(crate) fn size(&self) -> NodeIndex {
        NodeIndex::from(self.nodes.len())
    }

    /// Get the number of leaves in the tree.
    pub(crate) fn leaf_count(&self) -> LeafIndex {
        LeafIndex::from(self.size())
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

    /// Return the nodes in the CoPath of a given node.
    pub(crate) fn copath(&self, node_index: &NodeIndex) -> Result<Vec<NodeIndex>, BinaryTreeError> {
        Ok(treemath::copath(*node_index, self.leaf_count()))
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
    ) -> Result<Vec<NodeIndex>, BinaryTreeError>
    where
        F: Fn(NodeIndex, &T) -> Vec<NodeIndex>,
    {
        let node = self.node(node_index)?;
        let predicate_result = predicate(*node_index, node);
        if !predicate_result.is_empty() {
            Ok(predicate_result)
        } else if node_index.is_leaf() {
            Ok(vec![])
        } else {
            let mut left_resolution =
                self.resolve(&treemath::left(*node_index).unwrap(), predicate)?;
            let right_resolution = self.resolve(
                &treemath::right(*node_index, LeafIndex::from(self.size())).unwrap(),
                predicate,
            )?;
            left_resolution.extend(right_resolution);
            Ok(left_resolution)
        }
    }

    /// Apply the given function `f` to each node in the direct path of the node
    /// with index `node_index`, the result of the function applied to the
    /// parent is used as input to the functinon applied to the child. When
    /// applying `f` to the root node, the default value of `f`s return type is
    /// provided as input.
    pub(crate) fn direct_path_map<F, U: Default>(
        &mut self,
        node_index: &NodeIndex,
        f: &F,
    ) -> Result<U, BinaryTreeError>
    where
        F: Fn(&mut T, U) -> U,
    {
        if node_index == &self.root() {
            Ok(f(self.node_mut(node_index)?, U::default()))
        } else {
            let parent = self.parent(node_index)?;
            let parent_result = self.direct_path_map(&parent, f)?;
            Ok(f(self.node_mut(node_index)?, parent_result))
        }
    }

    /// Get the direct path between a given node index and the root.
    pub(crate) fn direct_path(
        &self,
        node_index: &NodeIndex,
    ) -> Result<Vec<NodeIndex>, BinaryTreeError> {
        Ok(treemath::direct_path_root(*node_index, self.leaf_count()))
    }

    /// Given two nodes `origin` and `target`, return the index of the node in
    /// the copath of the `origin`, such that the `target` is in the subtree of
    /// the returned node.
    pub(crate) fn copath_node(
        &self,
        copath_origin: &NodeIndex,
        copath_target: &NodeIndex,
    ) -> NodeIndex {
        let copath = treemath::copath(*copath_origin, self.leaf_count());

        let target_direct_path = self.direct_path(copath_target).unwrap();
        let copath_node_index = match target_direct_path.iter().find(|x| copath.contains(x)) {
            Some(index) => index.to_owned(),
            None => copath_target.to_owned(),
        };
        copath_node_index
    }

    /// Get the parent of a node with the given index.
    pub(crate) fn parent(&self, node_index: &NodeIndex) -> Result<NodeIndex, BinaryTreeError> {
        Ok(treemath::parent(*node_index, self.leaf_count())?)
    }

    /// Get the common ancestor of two nodes.
    pub(crate) fn common_ancestor(
        &self,
        node_index1: &NodeIndex,
        node_index2: &NodeIndex,
    ) -> NodeIndex {
        treemath::common_ancestor_index(*node_index1, *node_index2)
    }

    /// Compute a function f based on the node itself, as well as the result of
    /// the same function computed on the left and right child. Leafs return the
    /// result of the function with their node, as well as the default values
    /// for `U`.
    pub(crate) fn fold_tree<F, U: Default>(
        &self,
        node_index: &NodeIndex,
        f: &F,
    ) -> Result<U, BinaryTreeError>
    where
        F: Fn(&T, &NodeIndex, &U, &U) -> U,
    {
        let node = self.node(node_index)?;
        if node_index.is_leaf() {
            Ok(f(node, node_index, &U::default(), &U::default()))
        } else {
            let left_node = treemath::left(*node_index)?;
            let left_result = self.fold_tree(&left_node, f)?;
            let right_node = treemath::right(*node_index, self.leaf_count())?;
            let right_result = self.fold_tree(&right_node, f)?;
            Ok(f(node, node_index, &left_result, &right_result))
        }
    }

    /// Return a reference to the nodes of the tree.
    pub(crate) fn nodes(&self) -> &Vec<T> {
        &self.nodes
    }

    /// Return the index of the root node.
    pub(crate) fn root(&self) -> NodeIndex {
        treemath::root(self.leaf_count())
    }
}
