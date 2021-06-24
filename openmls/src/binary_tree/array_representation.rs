use super::treemath::*;
use super::FLBBinaryTree;
use super::NodeIndex;

#[derive(Clone, Debug, PartialEq)]
/// A representation of a full, left-balanced binary tree that uses a simple
/// vector to store nodes.
pub(crate) struct ABinaryTree<T: Default + Clone> {
    nodes: Vec<T>,
}

impl<T: Default + Clone> ABinaryTree<T> {
    /// Check if a given index is still within the tree.
    fn node_in_tree(&self, node_index: NodeIndex) -> Result<(), ABinaryTreeError> {
        node_in_tree(node_index, self.size()).map_err(|_| ABinaryTreeError::OutOfBounds)
    }
}

impl<T: Default + Clone> FLBBinaryTree<T> for ABinaryTree<T> {
    type FLBBinaryTreeError = ABinaryTreeError;

    fn new(nodes: &[T]) -> Result<Self, Self::FLBBinaryTreeError> {
        if nodes.len() % 2 != 1 {
            Err(Self::FLBBinaryTreeError::InvalidNumberOfNodes)
        } else if nodes.len() > NodeIndex::max_value() as usize {
            Err(Self::FLBBinaryTreeError::OutOfRange)
        } else {
            Ok(ABinaryTree {
                nodes: nodes.to_vec(),
            })
        }
    }

    fn node(&self, node_index: NodeIndex) -> std::option::Option<&T> {
        self.nodes.get(node_index as usize)
    }

    fn node_mut(&mut self, node_index: NodeIndex) -> std::option::Option<&mut T> {
        self.nodes.get_mut(node_index as usize)
    }

    fn add_leaf(&mut self, node: T) -> Result<(), Self::FLBBinaryTreeError> {
        // Prevent the tree from becoming too large.
        if self.nodes.len() > NodeIndex::max_value() as usize - 2 {
            Err(Self::FLBBinaryTreeError::OutOfRange)
        } else {
            self.nodes.push(T::default());
            self.nodes.push(node);
            Ok(())
        }
    }

    fn remove(&mut self) -> Result<(), Self::FLBBinaryTreeError> {
        // Check that there are enough nodes to remove.
        if self.nodes.len() < 2 {
            Err(Self::FLBBinaryTreeError::NotEnoughNodes)
        } else {
            self.nodes.pop();
            self.nodes.pop();
            Ok(())
        }
    }

    fn size(&self) -> NodeIndex {
        let len = self.nodes.len();
        debug_assert!(len <= u32::MAX as usize);
        self.nodes.len() as u32
    }

    fn direct_path(
        &self,
        node_index: NodeIndex,
    ) -> Result<Vec<NodeIndex>, Self::FLBBinaryTreeError> {
        direct_path(node_index, self.size()).map_err(|_| Self::FLBBinaryTreeError::OutOfBounds)
    }

    fn copath(&self, node_index: NodeIndex) -> Result<Vec<NodeIndex>, Self::FLBBinaryTreeError> {
        copath(node_index, self.size()).map_err(|_| Self::FLBBinaryTreeError::OutOfBounds)
    }

    fn lowest_common_ancestor(
        &self,
        node_index_1: NodeIndex,
        node_index_2: NodeIndex,
    ) -> Result<NodeIndex, Self::FLBBinaryTreeError> {
        self.node_in_tree(node_index_1)?;
        self.node_in_tree(node_index_2)?;
        Ok(lowest_common_ancestor(node_index_1, node_index_2))
    }
}

implement_error! {
    pub enum ABinaryTreeError {
        OutOfRange = "Adding nodes exceeds the maximum possible size of the tree.",
        NotEnoughNodes = "Not enough nodes to remove.",
        InvalidNumberOfNodes = "The given number of nodes does not allow the creation of a full, left-balanced binary tree.",
        OutOfBounds = "The given index is outside of the tree.",
    }
}
