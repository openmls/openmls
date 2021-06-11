pub(crate) mod array_representation;
pub(crate) mod treemath;

use treemath::TreeMathError;

use self::treemath::leaf_count;

pub(crate) type NodeIndex = u32;

/// A trait for a full, left-balanced binary tree. It uses the indices of the
/// array-based representation of such a tree for indexing of nodes.
pub(crate) trait FLBBinaryTree<Node> {
    /// Obtain a reference to the data contained in the `Node` at index `node_index`.
    /// Returns an error if the index is outside of the tree.
    fn node(&self, node_index: NodeIndex) -> Result<&Node, FLBBinaryTreeError>;

    /// Obtain a mutable reference to the data contained in the `Node` at index `node_index`.
    /// Returns an error if the index is outside of the tree.
    fn node_mut(&mut self, node_index: NodeIndex) -> Result<&mut Node, FLBBinaryTreeError>;

    /// Obtain a reference to the data contained in the leaf node at index
    /// `node_index`. Returns an error if the index is outside of the tree or if
    /// the node at the index is not a leaf.
    fn leaf(&self, node_index: NodeIndex) -> Result<&Node, FLBBinaryTreeError> {
        if node_index % 2 == 0 {
            return self.node(node_index);
        } else {
            Err(FLBBinaryTreeError::IndexError)
        }
    }

    /// Obtain a mutable reference to the data contained in the leaf node at index
    /// `node_index`. Returns an error if the index is outside of the tree or if
    /// the node at the index is not a leaf.
    fn leaf_mut(&mut self, node_index: NodeIndex) -> Result<&mut Node, FLBBinaryTreeError> {
        if node_index % 2 == 0 {
            return self.node_mut(node_index);
        } else {
            Err(FLBBinaryTreeError::IndexError)
        }
    }

    /// Add two nodes to the right side of the tree. Nodes can only be added in
    /// pairs to keep the tree full. Returns an error if the number of nodes
    /// exceeds the range of `NodeIndex`.
    fn add(&mut self, node_1: Node, node_2: Node) -> Result<(), FLBBinaryTreeError>;

    /// Remove the two rightmost nodes of the tree.
    fn remove(&mut self) -> Result<(), FLBBinaryTreeError>;

    /// Return the number of nodes in the tree.
    fn size(&self) -> NodeIndex;

    /// Return the number of leaves in the tree.
    fn leaf_count(&self) -> NodeIndex {
        leaf_count(self.size())
    }

    /// Compute the direct path from the node with the given index to the root
    /// node and return the vector of indices of the nodes on the direct path.
    fn direct_path(&self, start_index: NodeIndex) -> Result<Vec<NodeIndex>, FLBBinaryTreeError>;

    /// Compute the copath path from the node with the given index to the root
    /// node and return the vector of indices of the nodes on the copath.
    fn co_path(&self, start_index: NodeIndex) -> Result<Vec<NodeIndex>, FLBBinaryTreeError>;
}

// Questions:

// * This layer of abstraction relies on the indices of the array-based
// representation. Should it provide treemath functions for index calculations
// directly? Should treemath be detached?
// * What should the type of NodeIndex be?

implement_error! {
    pub enum FLBBinaryTreeError {
        Simple {
            OutOfRange = "Adding nodes exceeds the maximum possible size of the tree.",
            IndexError = "The given index is not a leaf index.",
        }
        Complex {
            OutOfBounds(TreeMathError) = "The given index is outside of the tree.",
        }
    }
}
