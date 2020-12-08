use crate::{prelude::LeafIndex, tree::index::NodeIndex};

use super::{treemath, TreeError};

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

    /// Get the number of leaves in the tree.
    pub(crate) fn leaf_count(&self) -> LeafIndex {
        LeafIndex::from(self.size())
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
    pub(crate) fn copath(&self, node_index: &NodeIndex) -> Result<Vec<NodeIndex>, TreeError> {
        let leaf_count = LeafIndex::from(self.size());
        let copath = treemath::copath(*node_index, leaf_count)?;
        Ok(copath)
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

    /// Apply the given function `f` to each node in the direct path of the node
    /// with index `node_index`, the result of the function applied to the
    /// parent is used as input to the functinon applied to the child.
    pub(crate) fn direct_path_map<F, U: Default>(
        &mut self,
        node_index: &NodeIndex,
        f: &F,
    ) -> Result<U, TreeError>
    where
        F: Fn(&mut T, U) -> Result<U, TreeError>,
    {
        self.check_if_within_bounds(node_index)?;
        if node_index == &treemath::root(self.leaf_count()) {
            return f(self.node_mut(node_index).unwrap(), U::default());
        } else {
            let parent = self.parent(node_index)?;
            let parent_result = self.direct_path_map(&parent, f)?;
            return f(self.node_mut(node_index).unwrap(), parent_result);
        }
        // We can unwrap here, because we know the index is within bounds.
        //let direct_path = treemath::direct_path_root(*node_index,
        // self.leaf_count()).unwrap(); for i in direct_path {
        //    f(self.node_mut(&i)?);
        //}
        //Ok(())
    }

    /// Get given two nodes, get the node in the copath of the first node, such
    /// that the second node is in the subtree of which that node is the root.
    pub(crate) fn copath_node(
        &self,
        copath_origin: &NodeIndex,
        copath_target: &NodeIndex,
    ) -> Result<NodeIndex, TreeError> {
        let copath = treemath::copath(*copath_origin, self.leaf_count())?;

        let target_direct_path =
            treemath::direct_path_root(*copath_target, self.leaf_count()).unwrap();
        let copath_node_index = match target_direct_path.iter().find(|x| copath.contains(x)) {
            Some(index) => index.clone(),
            None => copath_target.clone(),
        };
        Ok(copath_node_index)
    }

    /// Get the direct path between a given node index and the root.
    pub(crate) fn direct_path(&self, node_index: &NodeIndex) -> Result<Vec<NodeIndex>, TreeError> {
        let direct_path = treemath::direct_path_root(*node_index, self.leaf_count())?;
        Ok(direct_path)
    }

    /// Get the parent of a node with the given index.
    pub(crate) fn parent(&self, node_index: &NodeIndex) -> Result<NodeIndex, TreeError> {
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
    ) -> Result<U, TreeError>
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
