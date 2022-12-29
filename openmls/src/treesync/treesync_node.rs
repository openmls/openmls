//! This module contains the [`TreeSyncNode`] struct and its implementation.

use openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};
use serde::{Deserialize, Serialize};
use tls_codec::VLByteSlice;

use crate::{
    binary_tree::array_representation::{tree::TreeNode, LeafNodeIndex},
    error::LibraryError,
};

use super::{hashes::TreeHashInput, node::leaf_node::OpenMlsLeafNode, Node, ParentNode};

pub(crate) enum TreeSyncNode {
    Leaf(TreeSyncLeafNode),
    Parent(TreeSyncParentNode),
}

impl From<Node> for TreeSyncNode {
    fn from(node: Node) -> Self {
        match node {
            Node::LeafNode(leaf) => TreeSyncNode::Leaf(leaf.into()),
            Node::ParentNode(parent) => TreeSyncNode::Parent(parent.into()),
        }
    }
}

impl From<TreeSyncNode> for Option<Node> {
    fn from(tsn: TreeSyncNode) -> Self {
        match tsn {
            TreeSyncNode::Leaf(leaf) => leaf.into(),
            TreeSyncNode::Parent(parent) => parent.into(),
        }
    }
}

impl From<TreeNode<TreeSyncLeafNode, TreeSyncParentNode>> for TreeSyncNode {
    fn from(tree_node: TreeNode<TreeSyncLeafNode, TreeSyncParentNode>) -> Self {
        match tree_node {
            TreeNode::Leaf(leaf) => TreeSyncNode::Leaf(leaf),
            TreeNode::Parent(parent) => TreeSyncNode::Parent(parent),
        }
    }
}

impl From<TreeSyncNode> for TreeNode<TreeSyncLeafNode, TreeSyncParentNode> {
    fn from(tsn: TreeSyncNode) -> Self {
        match tsn {
            TreeSyncNode::Leaf(leaf) => TreeNode::Leaf(leaf),
            TreeSyncNode::Parent(parent) => TreeNode::Parent(parent),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
/// This intermediate struct on top of `Option<Node>` allows us to cache tree
/// hash values. Blank nodes are represented by [`TreeSyncNode`] instances where
/// `node = None`.
pub(crate) struct TreeSyncLeafNode {
    tree_hash: Option<Vec<u8>>,
    node: Option<OpenMlsLeafNode>,
}

impl TreeSyncLeafNode {
    /// Create a blank [`TreeSyncLeafNode`].
    pub(in crate::treesync) fn blank() -> Self {
        Self::default()
    }

    /// Return a reference to the contained `Option<Node>`.
    pub(in crate::treesync) fn node(&self) -> &Option<OpenMlsLeafNode> {
        &self.node
    }

    /// Return a copy of this node, but remove any potential private key
    /// material contained in the `Node`.
    pub(in crate::treesync) fn node_without_private_key(&self) -> Option<OpenMlsLeafNode> {
        self.node.as_ref().map(|node| node.clone_public())
    }

    /// Return a mutable reference to the contained `Option<Node>`.
    pub(in crate::treesync) fn node_mut(&mut self) -> &mut Option<OpenMlsLeafNode> {
        &mut self.node
    }

    /// Return a reference to the cached tree hash.
    pub(in crate::treesync) fn tree_hash(&self) -> Option<&[u8]> {
        self.tree_hash.as_deref()
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
        leaf_index: LeafNodeIndex,
    ) -> Result<Vec<u8>, LibraryError> {
        // If there's a cached tree hash, use that one.
        if let Some(hash) = self.tree_hash() {
            Ok(hash.to_vec())
        } else {
            // Otherwise compute it.
            let hash_input = TreeHashInput::new_leaf(
                &leaf_index,
                self.node.as_ref().map(|node| &node.leaf_node),
            );
            let hash = hash_input.hash(backend, ciphersuite)?;
            self.tree_hash = Some(hash.clone());

            Ok(hash)
        }
    }
}

impl From<OpenMlsLeafNode> for TreeSyncLeafNode {
    fn from(node: OpenMlsLeafNode) -> Self {
        Self {
            tree_hash: None,
            node: Some(node),
        }
    }
}

impl From<TreeSyncLeafNode> for Option<Node> {
    fn from(tsln: TreeSyncLeafNode) -> Self {
        tsln.node.map(Node::LeafNode)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
/// This intermediate struct on top of `Option<Node>` allows us to cache tree
/// hash values. Blank nodes are represented by [`TreeSyncNode`] instances where
/// `node = None`.
pub(crate) struct TreeSyncParentNode {
    tree_hash: Option<Vec<u8>>,
    node: Option<ParentNode>,
}

impl TreeSyncParentNode {
    /// Create a blank [`TreeSyncParentNode`].
    pub(in crate::treesync) fn blank() -> Self {
        Self::default()
    }

    /// Return a reference to the contained `Option<Node>`.
    pub(in crate::treesync) fn node(&self) -> &Option<ParentNode> {
        &self.node
    }

    /// Return a copy of this node, but remove any potential private key
    /// material contained in the `Node`.
    pub(in crate::treesync) fn node_without_private_key(&self) -> Option<ParentNode> {
        self.node
            .as_ref()
            .map(|node| node.clone_without_private_key())
    }

    /// Return a mutable reference to the contained `Option<Node>`.
    pub(in crate::treesync) fn node_mut(&mut self) -> &mut Option<ParentNode> {
        &mut self.node
    }

    /// Return a reference to the cached tree hash.
    pub(in crate::treesync) fn tree_hash(&self) -> Option<&[u8]> {
        self.tree_hash.as_deref()
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
        left_hash: Vec<u8>,
        right_hash: Vec<u8>,
    ) -> Result<Vec<u8>, LibraryError> {
        // If there's a cached tree hash, use that one.
        if let Some(hash) = self.tree_hash() {
            Ok(hash.to_vec())
        } else {
            // Otherwise compute it.
            let hash_input = TreeHashInput::new_parent(
                self.node.as_ref(),
                VLByteSlice(&left_hash),
                VLByteSlice(&right_hash),
            );
            let hash = hash_input.hash(backend, ciphersuite)?;
            self.tree_hash = Some(hash.clone());

            Ok(hash)
        }
    }
}

impl From<ParentNode> for TreeSyncParentNode {
    fn from(node: ParentNode) -> Self {
        Self {
            tree_hash: None,
            node: Some(node),
        }
    }
}

impl From<TreeSyncParentNode> for Option<Node> {
    fn from(tspn: TreeSyncParentNode) -> Self {
        tspn.node.map(Node::ParentNode)
    }
}
