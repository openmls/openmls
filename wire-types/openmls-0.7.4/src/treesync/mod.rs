//! This module implements the ratchet tree component of MLS.
//!
//! It exposes the [`Node`] enum that can contain either a [`LeafNode`] or a [`ParentNode`].

// # Internal documentation
//
// This module provides the [`TreeSync`] struct, which contains the state
// shared between a group of MLS clients in the shape of a tree, where each
// non-blank leaf corresponds to one group member. The functions provided by
// its implementation allow the creation of a [`TreeSyncDiff`] instance, which
// in turn can be mutably operated on and merged back into the original
// [`TreeSync`] instance.
//
// The submodules of this module define the nodes of the tree (`nodes`),
// helper functions and structs for the algorithms used to sync the tree across
// the group ([`hashes`]) and the diff functionality ([`diff`]).
//
// Finally, this module contains the [`treekem`] module, which allows the
// encryption and decryption of updates to the tree.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use self::{
    node::NodeIn,
    treesync_node::{TreeSyncLeafNode, TreeSyncParentNode},
};
use crate::binary_tree::MlsBinaryTree;

mod hashes;

// Crate
pub(crate) mod diff;
pub(crate) mod node;
pub(crate) mod treekem;
pub(crate) mod treesync_node;

// Public
pub mod errors;
pub use node::encryption_keys::EncryptionKey;

// Public re-exports
pub use node::{
    leaf_node::{LeafNode, LeafNodeSource},
    parent_node::ParentNode,
    Node,
};

/// An exported ratchet tree as used in, e.g., [`GroupInfo`](crate::messages::group_info::GroupInfo).
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub struct RatchetTree(Vec<Option<Node>>);

/// An error during processing of an incoming ratchet tree.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum RatchetTreeError {
    /// The ratchet tree is empty.
    #[error("The ratchet tree has no nodes.")]
    MissingNodes,
    /// The ratchet tree has a trailing blank node.
    #[error("The ratchet tree has trailing blank nodes.")]
    TrailingBlankNodes,
    /// Invalid node signature.
    #[error("Invalid node signature.")]
    InvalidNodeSignature,
    /// Wrong node type.
    #[error("Wrong node type.")]
    WrongNodeType,
}

/// A ratchet tree made of unverified nodes. This is used for deserialization
/// and verification.
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
pub struct RatchetTreeIn(Vec<Option<NodeIn>>);

/// The [`TreeSync`] struct holds an `MlsBinaryTree` instance, which contains
/// the state that is synced across the group, as well as the [`LeafNodeIndex`]
/// pointing to the leaf of this group member and the current hash of the tree.
///
/// It follows the same pattern of tree and diff as the underlying
/// `MlsBinaryTree`, where the [`TreeSync`] instance is immutable safe for
/// merging a `TreeSyncDiff`, which can be created, staged and merged (see
/// `TreeSyncDiff`).
///
/// [`TreeSync`] instance guarantee a few invariants that are checked upon
/// creating a new instance from an imported set of nodes, as well as when
/// merging a diff.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct TreeSync {
    tree: MlsBinaryTree<TreeSyncLeafNode, TreeSyncParentNode>,
    tree_hash: Vec<u8>,
}
