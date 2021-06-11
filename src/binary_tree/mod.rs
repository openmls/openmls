pub(crate) mod array_representation;
pub(crate) mod treemath;

type NodeIndex = u32;

/// A trait for a full, left-balanced binary tree. It uses the indices of the
/// array-based representation of such a tree for indexing of nodes.
trait FLBBinaryTree<Node> {
    /// Obtain a reference to the data contained in the `Node` at index `node_index`.
    /// Returns an error if the index is outside of the tree.
    fn node(&self, node_index: NodeIndex) -> Result<&Node, FLBBinaryTreeError>;

    /// Obtain a mutable reference to the data contained in the `Node` at index `node_index`.
    /// Returns an error if the index is outside of the tree.
    fn node_mut(&mut self, node_index: NodeIndex) -> Result<&mut Node, FLBBinaryTreeError>;

    /// Add two nodes to the right side of the tree. Nodes can only be added in
    /// pairs to keep the tree full. Returns an error if the number of nodes
    /// exceeds the range of `NodeIndex`.
    fn add(&mut self, node_1: Node, node_2: Node) -> Result<(), FLBBinaryTreeError>;

    /// Remove the two rightmost nodes of the tree.
    fn remove(&mut self) -> Result<(), FLBBinaryTreeError>;

    /// Return the number of nodes in the tree.
    fn size(&self) -> NodeIndex;

    /// Return the number of leaves in the tree.
    fn leaf_count(&self) -> NodeIndex;

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
        OutOfBounds = "The given index is outside of the tree.",
        OutOfRange = "Adding nodes exceeds the maximum possible size of the tree.",
    }
}
