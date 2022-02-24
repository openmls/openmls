//! This module contains the [`TreeSyncNode`] struct and its implementation.

use openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tls_codec::TlsSliceU8;

use crate::{
    binary_tree::{LeafIndex, MlsBinaryTreeDiffError},
    error::LibraryError,
    treesync::hashes::{LeafNodeHashInput, ParentNodeTreeHashInput},
};

use super::{errors::NodeError, node::leaf_node::LeafNode, Node};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
/// This intermediate struct on top of `Option<Node>` allows us to cache tree
/// hash values. Blank nodes are represented by [`TreeSyncNode`] instances where
/// `node = None`.
pub(crate) struct TreeSyncNode {
    tree_hash: Option<Vec<u8>>,
    node: Option<Node>,
}

impl From<Node> for TreeSyncNode {
    fn from(node: Node) -> Self {
        Self {
            tree_hash: None,
            node: Some(node),
        }
    }
}

impl From<TreeSyncNode> for Option<Node> {
    fn from(tsn: TreeSyncNode) -> Self {
        tsn.node
    }
}

impl From<Option<Node>> for TreeSyncNode {
    fn from(option_node: Option<Node>) -> Self {
        option_node.map(|node| node.into()).unwrap_or_default()
    }
}

impl TreeSyncNode {
    /// Create a blank [`TreeSyncNode`].
    pub(in crate::treesync) fn blank() -> Self {
        Self::default()
    }

    /// Return a reference to the contained `Option<Node>`.
    pub(in crate::treesync) fn node(&self) -> &Option<Node> {
        &self.node
    }

    /// Return a copy of this node, but remove any potential private key
    /// material contained in the `Node`.
    pub(in crate::treesync) fn node_without_private_key(&self) -> Option<Node> {
        if let Some(node) = self.node() {
            match node {
                Node::LeafNode(leaf_node) => Node::LeafNode(LeafNode::new_with_ref(
                    leaf_node.key_package().clone(),
                    leaf_node.key_package_ref().cloned(),
                )),
                Node::ParentNode(parent_node) => {
                    Node::ParentNode(parent_node.clone_without_private_key())
                }
            }
            .into()
        } else {
            None
        }
    }

    /// Return a mutable reference to the contained `Option<Node>`.
    pub(in crate::treesync) fn node_mut(&mut self) -> &mut Option<Node> {
        &mut self.node
    }

    /// Return a reference to the contained optional `tree_hash`.
    pub(in crate::treesync) fn tree_hash(&self) -> &Option<Vec<u8>> {
        &self.tree_hash
    }

    /// Replace the current `tree_hash` with `None`.
    pub(in crate::treesync) fn erase_tree_hash(&mut self) {
        self.tree_hash = None
    }

    /// Compute the tree hash for this node, thus populating the `tree_hash`
    /// field.
    pub(in crate::treesync) fn compute_tree_hash(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        leaf_index_option: Option<LeafIndex>,
        // This is temporary. See below.
        node_index: LeafIndex,
        left_hash: Vec<u8>,
        right_hash: Vec<u8>,
    ) -> Result<Vec<u8>, LibraryError> {
        // If there's a cached tree hash, use that one.
        if let Some(hash) = self.tree_hash() {
            return Ok(hash.clone());
        };
        // Otherwise compute it.
        // Check if I'm a leaf node.
        let hash = if let Some(leaf_index) = leaf_index_option {
            let key_package_option = match self.node.as_ref() {
                Some(node) => Some(
                    node.as_leaf_node()
                        .map_err(|_| LibraryError::custom("Expected a leaf node"))?,
                ),
                None => None,
            }
            .map(|leaf_node| leaf_node.key_package());
            // FIXME: After PR #507 of the spec is merged, this should really be the
            // leaf index. For now, we translate to node index here.
            let leaf_index = leaf_index * 2;
            let hash_input = LeafNodeHashInput::new(&leaf_index, key_package_option);
            hash_input.hash(ciphersuite, backend)?
        } else {
            let parent_node_option = match self.node.as_ref() {
                Some(node) => Some(
                    node.as_parent_node()
                        .map_err(|_| LibraryError::custom("Expected a parent node"))?,
                ),
                None => None,
            };
            // FIXME: After PR #507 of the spec is merged, this not include a
            // NodeIndex. To be able to verify against test vectors, we include
            // it here for now.
            let hash_input = ParentNodeTreeHashInput::new(
                node_index,
                parent_node_option,
                TlsSliceU8(&left_hash),
                TlsSliceU8(&right_hash),
            );
            hash_input.hash(ciphersuite, backend)?
        };
        self.tree_hash = Some(hash.clone());
        Ok(hash)
    }
}

/// Binary Tree error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum TreeSyncNodeError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`NodeError`] for more details.
    #[error(transparent)]
    NodeType(#[from] NodeError),
}

impl From<TreeSyncNodeError> for MlsBinaryTreeDiffError {
    fn from(_: TreeSyncNodeError) -> Self {
        MlsBinaryTreeDiffError::FoldingError
    }
}
