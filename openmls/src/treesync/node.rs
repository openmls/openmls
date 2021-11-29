mod codec;
pub(crate) mod leaf_node;
pub(crate) mod parent_node;

use openmls_traits::OpenMlsCryptoProvider;
use serde::{Deserialize, Serialize};
use tls_codec::TlsSliceU8;

use crate::{
    binary_tree::{LeafIndex, MlsBinaryTreeDiffError},
    ciphersuite::{Ciphersuite, HpkePrivateKey, HpkePublicKey},
    extensions::ExtensionType::ParentHash,
    treesync::hashes::{LeafNodeHashInput, ParentNodeTreeHashInput},
};

use self::{leaf_node::LeafNode, parent_node::ParentNode};

use super::hashes::ParentHashError;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum Node {
    LeafNode(LeafNode),
    ParentNode(ParentNode),
}

impl From<TreeSyncNode> for Option<Node> {
    fn from(tsn: TreeSyncNode) -> Self {
        tsn.node
    }
}

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

impl TreeSyncNode {
    pub(super) fn blank() -> Self {
        Self::default()
    }

    pub(super) fn node(&self) -> &Option<Node> {
        &self.node
    }

    pub(super) fn node_mut(&mut self) -> &mut Option<Node> {
        &mut self.node
    }

    pub(super) fn tree_hash(&self) -> &Option<Vec<u8>> {
        &self.tree_hash
    }

    pub(super) fn erase_tree_hash(&mut self) {
        self.tree_hash = None
    }

    pub(super) fn compute_tree_hash(
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
            hash_input.hash(ciphersuite, backend)
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
            hash_input.hash(ciphersuite, backend)
        };
        self.tree_hash = Some(hash.clone());
        Ok(hash)
    }
}

impl Node {
    pub(crate) fn as_leaf_node(&self) -> Result<&LeafNode, TreeSyncNodeError> {
        if let Node::LeafNode(ln) = self {
            Ok(ln)
        } else {
            Err(TreeSyncNodeError::AsLeafError)
        }
    }

    pub(crate) fn as_parent_node(&self) -> Result<&ParentNode, TreeSyncNodeError> {
        if let Node::ParentNode(ref node) = self {
            Ok(node)
        } else {
            Err(TreeSyncNodeError::AsParentError)
        }
    }

    pub(crate) fn as_parent_node_mut(&mut self) -> Result<&mut ParentNode, TreeSyncNodeError> {
        if let Node::ParentNode(ref mut node) = self {
            Ok(node)
        } else {
            Err(TreeSyncNodeError::AsParentError)
        }
    }

    pub(crate) fn public_key(&self) -> &HpkePublicKey {
        match self {
            Node::LeafNode(ln) => ln.public_key(),
            Node::ParentNode(pn) => pn.public_key(),
        }
    }

    pub(in crate::treesync) fn private_key(&self) -> &Option<HpkePrivateKey> {
        match self {
            Node::LeafNode(ln) => ln.private_key(),
            Node::ParentNode(pn) => pn.private_key(),
        }
    }

    /// Returns the parent hash of a given node. Returns None if the node is a
    /// leaf node without a parent hash extension.
    pub(crate) fn parent_hash(&self) -> Result<&[u8], TreeSyncNodeError> {
        let parent_hash = match self {
            Node::LeafNode(ln) => {
                let kp = ln.key_package();
                let extension = kp
                    .extension_with_type(ParentHash)
                    .ok_or(TreeSyncNodeError::MissingParentHashExtension)?;
                let parent_hash_extension = extension
                    .as_parent_hash_extension()
                    .map_err(|_| TreeSyncNodeError::LibraryError)?;
                parent_hash_extension.parent_hash()
            }
            Node::ParentNode(pn) => pn.parent_hash(),
        };
        Ok(parent_hash)
    }
}

implement_error! {
    pub enum TreeSyncNodeError {
        Simple{
            AsLeafError = "This is not a leaf node.",
            AsParentError = "This is not a parent node.",
            MissingParentHashExtension = "The given key package does not have a parent hash extension.",
            LibraryError = "An unrecoverable error has occurred during a TreeSySyncNode operation.",
        }
        Complex {
            ParentHashError(ParentHashError) = "Error while computing parent hash.",
        }
    }
}

impl From<TreeSyncNodeError> for MlsBinaryTreeDiffError {
    fn from(_: TreeSyncNodeError) -> Self {
        MlsBinaryTreeDiffError::FoldingError
    }
}
