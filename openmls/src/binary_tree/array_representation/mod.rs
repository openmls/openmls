//! This module contains an implementation of a full, left balanced binary tree
//! that uses the array-representation to store and index the individual nodes.
//!
//! # About
//!
//! The implementation is split between a tree implementation and a
//! corresponding diff. While the tree is immutable safe for merging with a
//! diff, the diff provides an API that allows mutation of parts of the tree, as
//! well as its navigation using node references. Please see the documentation
//! of the contained modules (especially [`tree`] and [`diff`]) for more
//! information.

// Public
pub use treemath::LeafNodeIndex;

// Crate
pub(crate) mod diff;
pub(crate) mod sorted_iter;
pub(crate) mod tree;

pub(crate) use treemath::{
    direct_path, is_node_in_tree, left, right, root, ParentNodeIndex, TreeNodeIndex, TreeSize,
    MIN_TREE_SIZE,
};

#[cfg(any(feature = "test-utils", test))]
pub(crate) use treemath::level;

mod treemath;

// Tests
#[cfg(any(feature = "test-utils", test))]
pub mod kat_treemath;
