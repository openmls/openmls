//! This module contains types and methods around the [`Node`] enum. The
//! variants of the enum are [`LeafNode`] and [`ParentNode`], both of which are
//! defined in the respective [`leaf_node`] and [`parent_node`] submodules.
use serde::{Deserialize, Serialize};

use crate::{
    ciphersuite::{HpkePrivateKey, HpkePublicKey},
    error::LibraryError,
    extensions::ExtensionType::ParentHash,
};

use self::{leaf_node::LeafNode, parent_node::ParentNode};

use super::NodeError;

mod codec;
pub(crate) mod leaf_node;
pub(crate) mod parent_node;

/// Container enum for leaf and parent nodes.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum Node {
    LeafNode(LeafNode),
    ParentNode(ParentNode),
}

impl Node {
    /// Obtain a reference to the [`LeafNode`] inside this [`Node`] instance.
    ///
    /// Returns an error if this [`Node`] instance is actually a [`ParentNode`].
    pub(crate) fn as_leaf_node(&self) -> Result<&LeafNode, NodeError> {
        if let Node::LeafNode(ln) = self {
            Ok(ln)
        } else {
            Err(NodeError::AsLeafError)
        }
    }

    /// Obtain a reference to the [`ParentNode`] inside this [`Node`] instance.
    ///
    /// Returns an error if this [`Node`] instance is actually a [`LeafNode`].
    pub(crate) fn as_parent_node(&self) -> Result<&ParentNode, NodeError> {
        if let Node::ParentNode(ref node) = self {
            Ok(node)
        } else {
            Err(NodeError::AsParentError)
        }
    }

    /// Obtain a mutable reference to the [`ParentNode`] inside this [`Node`]
    /// instance.
    ///
    /// Returns an error if this [`Node`] instance is actually a [`LeafNode`].
    pub(crate) fn as_parent_node_mut(&mut self) -> Result<&mut ParentNode, NodeError> {
        if let Node::ParentNode(ref mut node) = self {
            Ok(node)
        } else {
            Err(NodeError::AsParentError)
        }
    }

    /// Returns the public key of this node.
    pub(crate) fn public_key(&self) -> &HpkePublicKey {
        match self {
            Node::LeafNode(ln) => ln.public_key(),
            Node::ParentNode(pn) => pn.public_key(),
        }
    }

    /// Returns the private key of this node.
    pub(in crate::treesync) fn private_key(&self) -> Option<&HpkePrivateKey> {
        match self {
            Node::LeafNode(ln) => ln.private_key(),
            Node::ParentNode(pn) => pn.private_key(),
        }
    }

    /// Returns the parent hash of a given node. Returns [`None`] if the node is
    /// a [`LeafNode`] without a [`crate::extensions::ParentHashExtension`].
    pub(crate) fn parent_hash(&self) -> Result<Option<&[u8]>, LibraryError> {
        let parent_hash = match self {
            Node::LeafNode(ln) => {
                let kp = ln.key_package();
                if let Some(extension) = kp.extension_with_type(ParentHash) {
                    let parent_hash_extension = extension
                        .as_parent_hash_extension()
                        .map_err(|_| LibraryError::custom("Wrong extension type"))?;
                    parent_hash_extension.parent_hash()
                } else {
                    return Ok(None);
                }
            }
            Node::ParentNode(pn) => pn.parent_hash(),
        };
        Ok(Some(parent_hash))
    }
}
