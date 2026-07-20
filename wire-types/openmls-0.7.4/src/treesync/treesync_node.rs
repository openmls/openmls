//! This module contains the [`TreeSyncNode`] struct and its implementation.

use serde::{Deserialize, Serialize};

use super::{LeafNode, ParentNode};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
/// This intermediate struct on top of `Option<Node>` allows us to cache tree
/// hash values. Blank nodes are represented by [`TreeSyncNode`] instances where
/// `node = None`.
pub(crate) struct TreeSyncLeafNode {
    node: Option<LeafNode>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
/// This intermediate struct on top of `Option<Node>` allows us to cache tree
/// hash values. Blank nodes are represented by [`TreeSyncNode`] instances where
/// `node = None`.
pub(crate) struct TreeSyncParentNode {
    node: Option<ParentNode>,
}
