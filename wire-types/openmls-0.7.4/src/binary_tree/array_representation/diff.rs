//! An implementation of a diff functionality for the [`ABinaryTree`] struct.
//!
//! # About
//!
//! This module provides the [`AbDiff`] and [`StagedAbDiff`] structs that allow
//! performing changes to an [`ABinaryTree`] instance without immediately applying
//! the them. Instead, the changes can be applied to the diff and the results
//! examined before merging the given diff back into the tree (or not).
//!
//! # Don't Panic!
//!
//! Functions in this module should never panic. However, if there is a bug in
//! the implementation, a function will return an unrecoverable
//! [`LibraryError`](ABinaryTreeDiffError::LibraryError). This means that some
//! functions that are not expected to fail and throw an error, will still
//! return a [`Result`] since they may throw a
//! [`LibraryError`](ABinaryTreeDiffError::LibraryError).

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt::Debug};

use super::treemath::{LeafNodeIndex, ParentNodeIndex, TreeSize};

// Crate types

/// The [`StagedAbDiff`] can be created from an [`AbDiff`] instance. It's sole
/// purpose is to be subsequently merged into an existing [`ABinaryTree`]
/// instance. The difference between [`StagedAbDiff`] and an [`AbDiff`] is that a
/// [`StagedAbDiff`] is immutable and does not contain a reference to the original
/// tree. Since it only contains the actual diff without reference to the
/// original content, it can't provide the same information as the [`AbDiff`] it
/// was created from. However, the lack of the internal reference means that its
/// lifetime is not tied to that of the original tree.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StagedAbDiff<L: Clone + Debug + Default, P: Clone + Debug + Default> {
    leaf_diff: BTreeMap<LeafNodeIndex, L>,
    parent_diff: BTreeMap<ParentNodeIndex, P>,
    size: TreeSize,
}
