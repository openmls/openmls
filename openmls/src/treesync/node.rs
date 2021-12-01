use serde::{Deserialize, Serialize};

use crate::{
    ciphersuite::{HpkePrivateKey, HpkePublicKey},
    extensions::ExtensionType::ParentHash,
};

use self::{leaf_node::LeafNode, parent_node::ParentNode};
use super::hashes::ParentHashError;

mod codec;
pub(crate) mod leaf_node;
pub(crate) mod parent_node;

#[cfg(test)]
pub mod tests;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum Node {
    LeafNode(LeafNode),
    ParentNode(ParentNode),
}

impl Node {
    pub(crate) fn as_leaf_node(&self) -> Result<&LeafNode, NodeError> {
        if let Node::LeafNode(ln) = self {
            Ok(ln)
        } else {
            Err(NodeError::AsLeafError)
        }
    }

    pub(crate) fn as_parent_node(&self) -> Result<&ParentNode, NodeError> {
        if let Node::ParentNode(ref node) = self {
            Ok(node)
        } else {
            Err(NodeError::AsParentError)
        }
    }

    pub(crate) fn as_parent_node_mut(&mut self) -> Result<&mut ParentNode, NodeError> {
        if let Node::ParentNode(ref mut node) = self {
            Ok(node)
        } else {
            Err(NodeError::AsParentError)
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
    pub(crate) fn parent_hash(&self) -> Result<&[u8], NodeError> {
        let parent_hash = match self {
            Node::LeafNode(ln) => {
                let kp = ln.key_package();
                let extension = kp
                    .extension_with_type(ParentHash)
                    .ok_or(NodeError::MissingParentHashExtension)?;
                let parent_hash_extension = extension
                    .as_parent_hash_extension()
                    .map_err(|_| NodeError::LibraryError)?;
                parent_hash_extension.parent_hash()
            }
            Node::ParentNode(pn) => pn.parent_hash(),
        };
        Ok(parent_hash)
    }
}

implement_error! {
    pub enum NodeError {
        Simple{
            AsLeafError = "This is not a leaf node.",
            AsParentError = "This is not a parent node.",
            MissingParentHashExtension = "The given key package does not have a parent hash extension.",
            LibraryError = "An unrecoverable error has occurred during a [`Node`] operation.",
        }
        Complex {
            ParentHashError(ParentHashError) = "Error while computing parent hash.",
        }
    }
}
