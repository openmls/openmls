//! This module implements a full, left-balanced binary tree using an array
//! representation for storing and indexing nodes efficiently.
//!
//! # Overview
//!
//! The implementation is divided into a tree and a corresponding diff. The tree
//! is immutable except for merging with a diff. The diff provides an API for
//! mutating parts of the tree and navigating it using node references. See the
//! [`tree`] and [`diff`] modules for detailed documentation.

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
