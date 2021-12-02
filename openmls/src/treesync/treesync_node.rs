use openmls_traits::{types::CryptoError, OpenMlsCryptoProvider};
use serde::{Deserialize, Serialize};
use tls_codec::TlsSliceU8;

use crate::{
    binary_tree::{LeafIndex, MlsBinaryTreeDiffError},
    ciphersuite::Ciphersuite,
    treesync::hashes::{LeafNodeHashInput, ParentNodeTreeHashInput},
};

use super::node::NodeError;
use super::Node;
use crate::treesync::hashes::ParentHashError;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
/// This intermediate struct on top of `Option<Node>` allows us to cache tree
/// hash values.
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

impl TreeSyncNode {
    pub(in crate::treesync) fn blank() -> Self {
        Self::default()
    }

    pub(in crate::treesync) fn node(&self) -> &Option<Node> {
        &self.node
    }

    pub(in crate::treesync) fn node_mut(&mut self) -> &mut Option<Node> {
        &mut self.node
    }

    pub(in crate::treesync) fn tree_hash(&self) -> &Option<Vec<u8>> {
        &self.tree_hash
    }

    pub(in crate::treesync) fn erase_tree_hash(&mut self) {
        self.tree_hash = None
    }

    pub(in crate::treesync) fn compute_tree_hash(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        leaf_index_option: Option<LeafIndex>,
        left_hash: Vec<u8>,
        right_hash: Vec<u8>,
    ) -> Result<Vec<u8>, TreeSyncNodeError> {
        // If there's a cached tree hash, use that one.
        if let Some(hash) = self.tree_hash() {
            return Ok(hash.clone());
        };
        // Otherwise compute it.
        // Check if I'm a leaf node.
        let hash = if let Some(leaf_index) = leaf_index_option {
            let key_package_option = match self.node.as_ref() {
                Some(node) => Some(node.as_leaf_node()?),
                None => None,
            }
            .map(|leaf_node| leaf_node.key_package());
            let hash_input = LeafNodeHashInput::new(&leaf_index, key_package_option);
            hash_input.hash(ciphersuite, backend)?
        } else {
            let parent_node_option = match self.node.as_ref() {
                Some(node) => Some(node.as_parent_node()?),
                None => None,
            };
            let hash_input = ParentNodeTreeHashInput::new(
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

implement_error! {
    pub enum TreeSyncNodeError {
        Simple{
            LibraryError = "An unrecoverable error has occurred during a TreeSySyncNode operation.",
        }
        Complex {
            ParentHashError(ParentHashError) = "Error while computing parent hash.",
            NodeTypeError(NodeError) = "We found a node with an unexpected type.",
            HashError(CryptoError) = "Error while hashing payload.",
        }
    }
}

impl From<TreeSyncNodeError> for MlsBinaryTreeDiffError {
    fn from(_: TreeSyncNodeError) -> Self {
        MlsBinaryTreeDiffError::FoldingError
    }
}
