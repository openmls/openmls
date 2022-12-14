//! This module contains types and methods around the [`Node`] enum. The
//! variants of the enum are `LeafNode` and [`ParentNode`], both of which are
//! defined in the respective [`leaf_node`] and [`parent_node`] submodules.
use serde::{Deserialize, Serialize};

use crate::ciphersuite::{HpkePrivateKey, HpkePublicKey};

use self::{leaf_node::OpenMlsLeafNode, parent_node::ParentNode};

use super::NodeError;

mod codec;
pub(crate) mod leaf_node;
pub(crate) mod parent_node;

/// Container enum for leaf and parent nodes.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
#[allow(clippy::large_enum_variant)]
pub enum Node {
    LeafNode(OpenMlsLeafNode),
    ParentNode(ParentNode),
}

impl Node {
    /// Obtain a reference to the [`OpenMlsLeafNode`] inside this [`Node`] instance.
    ///
    /// Returns an error if this [`Node`] instance is actually a [`ParentNode`].
    pub(crate) fn as_leaf_node(&self) -> Result<&OpenMlsLeafNode, NodeError> {
        if let Node::LeafNode(ln) = self {
            Ok(ln)
        } else {
            Err(NodeError::AsLeafError)
        }
    }

    /// Obtain a reference to the [`ParentNode`] inside this [`Node`] instance.
    ///
    /// Returns an error if this [`Node`] instance is actually a [`OpenMlsLeafNode`].
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
    /// Returns an error if this [`Node`] instance is actually a [`OpenMlsLeafNode`].
    pub(crate) fn as_parent_node_mut(&mut self) -> Result<&mut ParentNode, NodeError> {
        if let Node::ParentNode(ref mut node) = self {
            Ok(node)
        } else {
            Err(NodeError::AsParentError)
        }
    }

    /// Obtain a mutable reference to the [`OpenMlsLeafNode`] inside this
    /// [`Node`] instance.
    ///
    /// Returns an error if this [`Node`] instance is actually a [`ParentNode`].
    pub(crate) fn as_leaf_node_mut(&mut self) -> Result<&mut OpenMlsLeafNode, NodeError> {
        if let Node::LeafNode(ln) = self {
            Ok(ln)
        } else {
            Err(NodeError::AsLeafError)
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
    /// a [`OpenMlsLeafNode`] without a [`crate::extensions::ParentHashExtension`].
    pub(crate) fn parent_hash(&self) -> Option<&[u8]> {
        match self {
            Node::LeafNode(ln) => ln.leaf_node.parent_hash(),
            Node::ParentNode(pn) => Some(pn.parent_hash()),
        }
    }
}
