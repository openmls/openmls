//! This module defines the binary tree implementation used by OpenMLS.
use std::hash::Hash;

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

/// This trait requires the implementer to provide each instance with an
/// `Address`. The address MUST be unique per instance.
pub trait Addressable {
    type Address: PartialEq + Eq + Hash;

    /// Returns the address of this node. If it's the default node, return `None`
    /// instead.
    fn address(&self) -> Option<Self::Address>;
}

/// We use this type alias as a convenience, so we can later swap out the tree
/// representation with a feature-flag.
pub(crate) type MlsBinaryTree<Node> = ABinaryTree<Node>;

pub(crate) type MlsBinaryTreeError = ABinaryTreeError;

pub(crate) type LeafIndex = u32;
