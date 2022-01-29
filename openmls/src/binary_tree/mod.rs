//! This module defines the binary tree implementation used by OpenMLS.

pub(crate) mod array_representation;

#[cfg(test)]
mod test_binary_tree;

use array_representation::diff::ABinaryTreeDiffError;
use array_representation::tree::{ABinaryTree, ABinaryTreeError};

use self::array_representation::diff::{AbDiff, StagedAbDiff};

/// We use this type alias as a convenience, so we can later swap out the tree
/// representation with a feature-flag.
pub(crate) type MlsBinaryTree<Node> = ABinaryTree<Node>;

pub(crate) type MlsBinaryTreeDiff<'a, Node> = AbDiff<'a, Node>;
pub(crate) type StagedMlsBinaryTreeDiff<Node> = StagedAbDiff<Node>;

pub type MlsBinaryTreeError = ABinaryTreeError;
pub type MlsBinaryTreeDiffError = ABinaryTreeDiffError;

/// Index type to index the leaves in the binary tree
pub type LeafIndex = u32;

/// A tree can be at most `2^32 - 1` nodes big.
pub(crate) type TreeSize = u32;
