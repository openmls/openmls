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
        Ok(node_in_tree(node_index, self.size())?)
    }
}

impl<T> FLBBinaryTree<T> for ABinaryTree<T> {
    fn node(&self, node_index: NodeIndex) -> Result<&T, FLBBinaryTreeError> {
        self.node_in_tree(node_index)?;
        Ok(self.nodes.get(node_index as usize).unwrap())
    }

    fn node_mut(&mut self, node_index: NodeIndex) -> Result<&mut T, FLBBinaryTreeError> {
        self.node_in_tree(node_index)?;
        Ok(self.nodes.get_mut(node_index as usize).unwrap())
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

    fn direct_path(&self, node_index: NodeIndex) -> Result<Vec<NodeIndex>, FLBBinaryTreeError> {
        Ok(direct_path(node_index, self.size())?)
    }

    fn co_path(&self, node_index: NodeIndex) -> Result<Vec<NodeIndex>, FLBBinaryTreeError> {
        Ok(copath(node_index, self.size())?)
    }
}
