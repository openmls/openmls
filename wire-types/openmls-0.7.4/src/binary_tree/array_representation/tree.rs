//! A binary tree implementation for use with MLS.
//!
//! # About
//!
//! This module contains an implementation of a binary tree based on an array
//! representation. The main [`ABinaryTree`] struct is generally immutable, but
//! allows the creation of an [`AbDiff`] struct, where changes can be made before
//! merging it back into an existing tree.

use std::fmt::Debug;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
/// A representation of a full, left-balanced binary tree that uses a simple
/// vector to store nodes. Each tree has to consist of at least one node.
pub(crate) struct ABinaryTree<L: Clone + Debug + Default, P: Clone + Debug + Default> {
    leaf_nodes: Vec<L>,
    parent_nodes: Vec<P>,
    default_leaf: L,
    default_parent: P,
}
