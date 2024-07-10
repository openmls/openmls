//! This module contains the [`TreeSyncNode`] struct and its implementation.

use std::collections::HashSet;

use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::Ciphersuite;
use serde::{Deserialize, Serialize};
use tls_codec::VLByteSlice;

use crate::{
    binary_tree::array_representation::{tree::TreeNode, LeafNodeIndex},
    error::LibraryError,
};

use super::{hashes::TreeHashInput, LeafNode, Node, ParentNode};

#[allow(clippy::large_enum_variant)]
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
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq))]
/// This intermediate struct on top of `Option<Node>` allows us to cache tree
/// hash values. Blank nodes are represented by [`TreeSyncNode`] instances where
/// `node = None`.
pub(crate) struct TreeSyncLeafNode {
    node: Option<LeafNode>,
}

impl TreeSyncLeafNode {
    /// Create a blank [`TreeSyncLeafNode`].
    pub(in crate::treesync) fn blank() -> Self {
        Self::default()
    }

    /// Return a reference to the contained `Option<Node>`.
    pub(in crate::treesync) fn node(&self) -> &Option<LeafNode> {
        &self.node
    }

    /// Compute the tree hash for this node, thus populating the `tree_hash`
    /// field.
    pub(in crate::treesync) fn compute_tree_hash(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        leaf_index: LeafNodeIndex,
    ) -> Result<Vec<u8>, LibraryError> {
        let hash_input = TreeHashInput::new_leaf(&leaf_index, self.node.as_ref());
        let hash = hash_input.hash(crypto, ciphersuite)?;

        Ok(hash)
    }
}

impl From<LeafNode> for TreeSyncLeafNode {
    fn from(node: LeafNode) -> Self {
        Self { node: Some(node) }
    }
}

impl From<TreeSyncLeafNode> for Option<Node> {
    fn from(tsln: TreeSyncLeafNode) -> Self {
        tsln.node.map(Node::LeafNode)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq))]
/// This intermediate struct on top of `Option<Node>` allows us to cache tree
/// hash values. Blank nodes are represented by [`TreeSyncNode`] instances where
/// `node = None`.
pub(crate) struct TreeSyncParentNode {
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

    /// Return a mutable reference to the contained `Option<Node>`.
    pub(in crate::treesync) fn node_mut(&mut self) -> &mut Option<ParentNode> {
        &mut self.node
    }

    /// Compute the tree hash for this node. Leaf nodes from the exclusion list
    /// are filtered out.
    pub(in crate::treesync) fn compute_tree_hash(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        left_hash: Vec<u8>,
        right_hash: Vec<u8>,
        exclusion_list: &HashSet<&LeafNodeIndex>,
    ) -> Result<Vec<u8>, LibraryError> {
        let hash = if exclusion_list.is_empty() {
            // If the exclusion list is empty, we can just use the parent node
            TreeHashInput::new_parent(
                self.node.as_ref(),
                VLByteSlice(&left_hash),
                VLByteSlice(&right_hash),
            )
            .hash(crypto, ciphersuite)?
        } else if let Some(parent_node) = self.node.as_ref() {
            // If the exclusion list is not empty, we need to create a new
            // parent node without the excluded indices in the unmerged leaves.
            let mut new_node = parent_node.clone();
            let unmerged_leaves = new_node
                .unmerged_leaves()
                .iter()
                .filter(|leaf| !exclusion_list.contains(leaf))
                .cloned()
                .collect();
            new_node.set_unmerged_leaves(unmerged_leaves);
            TreeHashInput::new_parent(
                Some(&new_node),
                VLByteSlice(&left_hash),
                VLByteSlice(&right_hash),
            )
            .hash(crypto, ciphersuite)?
        } else {
            // If the node is blank
            TreeHashInput::new_parent(None, VLByteSlice(&left_hash), VLByteSlice(&right_hash))
                .hash(crypto, ciphersuite)?
        };

        Ok(hash)
    }
}

impl From<ParentNode> for TreeSyncParentNode {
    fn from(node: ParentNode) -> Self {
        Self { node: Some(node) }
    }
}

impl From<TreeSyncParentNode> for Option<Node> {
    fn from(tspn: TreeSyncParentNode) -> Self {
        tspn.node.map(Node::ParentNode)
    }
}
