//! This module defines the binary tree implementation used by OpenMLS.

/// FIXME: Allowing dead code until there's an actual consumer for the binary
/// tree API.
#[allow(dead_code)]
pub(crate) mod array_representation;

#[allow(dead_code)]
/// FIXME: There's some dead code in treemath that will be used in treesync in
/// the future.
pub(crate) mod treemath;

#[cfg(test)]
mod test_binary_tree;

#[cfg(any(feature = "test-utils", test))]
pub mod kat_treemath;

use array_representation::{ABinaryTree, ABinaryTreeError};

/// The `NodeIndex` is used throughout this trait to index nodes as if the
/// underlying binary tree was implementing the array representation.
pub(crate) type NodeIndex = u32;

pub(crate) type TreeSize = NodeIndex;

/// We use this type alias as a convenience, so we can later swap out the tree
/// representation with a feature-flag.
pub(crate) type MlsBinaryTree<Node> = ABinaryTree<Node>;

pub(crate) type MlsBinaryTreeError = ABinaryTreeError;
