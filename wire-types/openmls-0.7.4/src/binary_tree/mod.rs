//! This module defines the binary tree implementation used by OpenMLS.

use array_representation::{diff::StagedAbDiff, tree::ABinaryTree};

// Public
pub use array_representation::LeafNodeIndex;

// Crate
pub(crate) mod array_representation;

// Crate types

/// We use this type alias as a convenience, so we can later swap out the tree
/// representation with a feature-flag.
pub(crate) type MlsBinaryTree<L, P> = ABinaryTree<L, P>;
pub(crate) type StagedMlsBinaryTreeDiff<L, P> = StagedAbDiff<L, P>;
