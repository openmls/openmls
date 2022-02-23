//! This module defines the binary tree implementation used by OpenMLS.

use array_representation::{
    diff::{ABinaryTreeDiffError, AbDiff, StagedAbDiff},
    tree::{ABinaryTree, ABinaryTreeError},
};

// Crate
pub(crate) use self::array_representation::diff::OutOfBoundsError;

pub(crate) mod array_representation;

// Tests

#[cfg(test)]
mod test_binary_tree;

// Crate types

/// We use this type alias as a convenience, so we can later swap out the tree
/// representation with a feature-flag.
pub(crate) type MlsBinaryTree<Node> = ABinaryTree<Node>;
pub(crate) type MlsBinaryTreeDiff<'a, Node> = AbDiff<'a, Node>;
pub(crate) type StagedMlsBinaryTreeDiff<Node> = StagedAbDiff<Node>;
pub(crate) type MlsBinaryTreeError = ABinaryTreeError;
pub(crate) type MlsBinaryTreeDiffError = ABinaryTreeDiffError;

/// Index type to index the leaves in the binary tree
pub(crate) type LeafIndex = u32;

/// A tree can be at most `2^32 - 1` nodes big.
pub(crate) type TreeSize = u32;
