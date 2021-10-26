pub(crate) mod array_representation;

#[allow(dead_code)]
/// FIXME: There's some dead code in treemath that will be used in treesync in
/// the future.
pub(crate) mod treemath;

#[cfg(test)]
mod test_binary_tree;

#[cfg(any(feature = "test-utils", test))]
pub mod kat_treemath;

use array_representation::ABinaryTree;

/// The `NodeIndex` is used throughout this trait to index nodes as if the
/// underlying binary tree was implementing the array representation.
pub(crate) type NodeIndex = u32;

pub(crate) type TreeSize = NodeIndex;

pub(crate) type MlsBinaryTree<Node: Default> = ABinaryTree<Node>;
