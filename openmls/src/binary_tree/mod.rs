use self::treemath::root;

pub(crate) mod array_representation;

use std::fmt::Debug;

#[allow(dead_code)]
/// FIXME: There's some dead code in treemath that will be used in treesync in
/// the future.
pub(crate) mod treemath;

#[cfg(test)]
mod test_binary_tree;

#[cfg(any(feature = "expose-test-vectors", test))]
pub mod kat_treemath;

/// The `NodeIndex` is used throughout this trait to index nodes as if the
/// underlying binary tree was implementing the array representation.
pub(crate) type NodeIndex = u32;

pub(crate) type TreeSize = NodeIndex;

/// A trait for a full, left-balanced binary tree. It uses the indices of the
/// array-based representation of such a tree for indexing of nodes.
pub(crate) trait FLBBinaryTree<Node: Default> {
    /// Error type for FLBBinaryTree functions.
    type FLBBinaryTreeError: Debug;

    /// Create a tree from the given vector of nodes. The nodes are ordered in
    /// the array-representation. Throws a `InvalidNumberOfNodes` error if the
    /// number of nodes does not allow the creation of a full, left-balanced
    /// binary tree and an `OutOfRange` error if the number of given nodes
    /// exceeds the range of `NodeIndex`.
    fn new(nodes: &[Node]) -> Result<Self, Self::FLBBinaryTreeError>
    where
        Self: Sized;

    fn root(&self) -> &Node {
        // There's always a root node.
        self.node(root(self.size())).unwrap()
    }

    /// Obtain a reference to the data contained in the `Node` at index
    /// `node_index`, where the indexing corresponds to the array representation
    /// of the underlying binary tree. Returns an error if the index is outside
    /// of the tree.
    fn node(&self, node_index: NodeIndex) -> Option<&Node>;

    /// Obtain a mutable reference to the data contained in the `Node` at index
    /// `node_index`, where the indexing corresponds to the array representation
    /// of the underlying binary tree. Returns an error if the index is outside
    /// of the tree.
    fn node_mut(&mut self, node_index: NodeIndex) -> Option<&mut Node>;

    /// Adds the given node as a new leaf to right side of the tree. To keep
    /// the tree full, a parent node is added using the `Default` constructor.
    /// Returns an `OutOfRange` error if the number of nodes exceeds the range
    /// of `NodeIndex`.
    fn add_leaf(&mut self, node: Node) -> Result<(), Self::FLBBinaryTreeError>;

    /// Remove the two rightmost nodes of the tree. This will throw a
    /// `NotEnoughNodes` error if there are not enough nodes to remove.
    fn remove(&mut self) -> Result<(), Self::FLBBinaryTreeError>;

    /// Return the number of nodes in the tree.
    fn size(&self) -> TreeSize;

    /// Return the number of leaves in the tree.
    fn leaf_count(&self) -> TreeSize {
        (self.size() + 1) / 2
    }

    /// Compute the direct path from the node with the given index to the root
    /// node and return the vector of indices of the nodes on the direct path,
    /// where the indexing corresponds to the array representation of the
    /// underlying binary tree.
    fn direct_path(
        &self,
        start_index: NodeIndex,
    ) -> Result<Vec<NodeIndex>, Self::FLBBinaryTreeError>;

    /// Compute the copath path from the node with the given index to the root
    /// node and return the vector of indices of the nodes on the copath, where
    /// the indexing corresponds to the array representation of the underlying
    /// binary tree.
    fn copath(&self, start_index: NodeIndex) -> Result<Vec<NodeIndex>, Self::FLBBinaryTreeError>;

    /// Compute the lowest common ancestor of the nodes with the given indices,
    /// where the indexing corresponds to the array representation of the
    /// underlying binary tree. Returns an `OutOfBounds` error if either of the
    /// indices is out of the bounds of the tree.
    fn lowest_common_ancestor(
        &self,
        index_1: NodeIndex,
        index_2: NodeIndex,
    ) -> Result<NodeIndex, Self::FLBBinaryTreeError>;
}

// TODO:
// * Error as associated type
// * NodeIndex as well if we can hide everything that requires index handling under the abstraction layer
