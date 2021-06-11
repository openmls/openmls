use super::treemath::*;
use super::FLBBinaryTree;
use super::FLBBinaryTreeError;
use super::NodeIndex;

pub(crate) struct ABinaryTree<T> {
    nodes: Vec<T>,
}

impl<T> ABinaryTree<T> {
    /// Check if a given index is still within the tree.
    fn node_in_tree(&self, node_index: NodeIndex) -> Result<(), FLBBinaryTreeError> {
        if node_index as usize >= self.nodes.len() {
            Err(FLBBinaryTreeError::OutOfBounds)
        } else {
            Ok(())
        }
    }
}

impl<T> FLBBinaryTree<T> for ABinaryTree<T> {
    fn node(&self, node_index: NodeIndex) -> Result<&T, FLBBinaryTreeError> {
        self.nodes
            .get(node_index as usize)
            .ok_or(FLBBinaryTreeError::OutOfBounds)
    }

    fn node_mut(&mut self, node_index: NodeIndex) -> Result<&mut T, super::FLBBinaryTreeError> {
        self.nodes
            .get_mut(node_index as usize)
            .ok_or(FLBBinaryTreeError::OutOfBounds)
    }

    fn add(&mut self, node_1: T, node_2: T) -> Result<(), FLBBinaryTreeError> {
        // Prevent the tree from becoming too large.
        if self.nodes.len() + 2 > NodeIndex::max_value() as usize {
            return Err(FLBBinaryTreeError::OutOfRange);
        }
        self.nodes.push(node_1);
        self.nodes.push(node_2);
        Ok(())
    }

    fn remove(&mut self) -> Result<(), FLBBinaryTreeError> {
        self.nodes.pop();
        self.nodes.pop();
        Ok(())
    }

    fn size(&self) -> NodeIndex {
        self.nodes.len() as u32
    }

    fn leaf_count(&self) -> NodeIndex {
        node_width(self.nodes.len()) as u32
    }

    fn direct_path(&self, node_index: NodeIndex) -> Result<Vec<NodeIndex>, FLBBinaryTreeError> {
        self.node_in_tree(node_index)?;

        leaf_direct_path(leaf_index, size)
    }

    fn co_path(&self, start_index: NodeIndex) -> Result<Vec<NodeIndex>, FLBBinaryTreeError> {
        todo!()
    }
}
