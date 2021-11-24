//! This module defines the binary tree implementation used by OpenMLS.
use std::hash::Hash;

/// FIXME: Allowing dead code until there's an actual consumer for the binary
/// tree API.
#[allow(dead_code)]
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

pub(crate) type MlsBinaryTreeError = ABinaryTreeError;
pub(crate) type MlsBinaryTreeDiffError = ABinaryTreeDiffError;

pub type LeafIndex = u32;
