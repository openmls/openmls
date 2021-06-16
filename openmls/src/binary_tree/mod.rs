pub(crate) mod array_representation;

#[allow(dead_code)]
/// There's some dead code in treemath that will be used in treesync in the
/// future.
pub(crate) mod treemath;

#[cfg(test)]
mod test_binary_tree;

#[cfg(any(feature = "expose-test-vectors", test))]
pub mod kat_treemath;

pub(crate) type NodeIndex = u32;

/// A trait for a full, left-balanced binary tree. It uses the indices of the
/// array-based representation of such a tree for indexing of nodes.
pub(crate) trait FLBBinaryTree<Node> {
    /// Error type for FLBBinaryTree functions.
    type FLBBinaryTreeError;

    /// Create a tree from the given vector of nodes. The nodes are ordered in
    /// the array-representation. Throws a `InvalidNumberOfNodes` error if the
    /// number of nodes does not allow the creation of a full, left-balanced
    /// binary tree and an `OutOfRange` error if the number of given nodes
    /// exceeds the range of `NodeIndex`.
    fn new(nodes: Vec<Node>) -> Result<Self, FLBBinaryTreeError>
    where
        Self: Sized;

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
            self.node(node_index)
        } else {
            Err(FLBBinaryTreeError::IndexError)
        }
    }

    /// Obtain a mutable reference to the data contained in the leaf node at index
    /// `node_index`. Returns an error if the index is outside of the tree or if
    /// the node at the index is not a leaf.
    fn leaf_mut(&mut self, node_index: NodeIndex) -> Result<&mut Node, FLBBinaryTreeError> {
        if node_index % 2 == 0 {
            self.node_mut(node_index)
        } else {
            Err(FLBBinaryTreeError::IndexError)
        }
    }

    /// Add two nodes to the right side of the tree. Nodes can only be added in
    /// pairs to keep the tree full. Returns an `OutOfRange` error if the number
    /// of nodes exceeds the range of `NodeIndex`.
    fn add(&mut self, node_1: Node, node_2: Node) -> Result<(), FLBBinaryTreeError>;

    /// Remove the two rightmost nodes of the tree. This will throw a
    /// `NotEnoughNodes` error if there are not enough nodes to remove.
    fn remove(&mut self) -> Result<(), FLBBinaryTreeError>;

    /// Return the number of nodes in the tree.
    fn size(&self) -> NodeIndex;

    /// Return the number of leaves in the tree.
    fn leaf_count(&self) -> NodeIndex {
        (self.size() + 1) / 2
    }

    /// Compute the direct path from the node with the given index to the root
    /// node and return the vector of indices of the nodes on the direct path.
    fn direct_path(&self, start_index: NodeIndex) -> Result<Vec<NodeIndex>, FLBBinaryTreeError>;

    /// Compute the copath path from the node with the given index to the root
    /// node and return the vector of indices of the nodes on the copath.
    fn copath(&self, start_index: NodeIndex) -> Result<Vec<NodeIndex>, FLBBinaryTreeError>;

    /// Compute the lowest common ancestor of the nodes with the given indices.
    /// Returns an `OutOfBounds` error if either of the indices is out of the
    /// bounds of the tree.
    fn lowest_common_ancestor(
        &self,
        index_1: NodeIndex,
        index_2: NodeIndex,
    ) -> Result<NodeIndex, FLBBinaryTreeError>;
}
