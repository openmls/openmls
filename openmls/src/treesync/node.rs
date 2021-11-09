use hpke::HpkePublicKey;
use tls_codec::{TlsByteVecU8, TlsVecU32};

use crate::{
    binary_tree::{Addressable, LeafIndex},
    prelude::KeyPackage,
};

#[derive(Debug, Clone)]
pub(crate) struct Node {
    public_key: HpkePublicKey,
    parent_hash: TlsByteVecU8,
    unmerged_leaves: TlsVecU32<LeafIndex>,
    tree_hash: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) enum TreeSyncNode {
    LeafNode(KeyPackage),
    ParentNode(Node),
}

impl TreeSyncNode {
    pub(crate) fn as_leaf_node_mut(&mut self) -> Result<&mut KeyPackage, TreeSyncNodeError> {
        match self {
            TreeSyncNode::LeafNode(mut kp) => Ok(&mut kp),
            TreeSyncNode::ParentNode(_) => Err(TreeSyncNodeError::AsLeafError),
        }
    }

    pub(crate) fn as_parent_node_mut(&mut self) -> Result<&mut Node, TreeSyncNodeError> {
        match self {
            TreeSyncNode::LeafNode(_) => Err(TreeSyncNodeError::AsLeafError),
            TreeSyncNode::ParentNode(mut node) => Ok(&mut node),
        }
    }
}

implement_error! {
    pub enum TreeSyncNodeError {
        AsLeafError = "This is not a leaf node.",
        AsParentError = "This is not a parent node.",
    }
}

impl Node {
    /// Return the value of the node relevant for the parent hash and tree hash.
    /// In case of MLS, this would be the node's HPKEPublicKey. TreeSync
    /// can then gather everything necessary to build the `ParentHashInput`,
    /// `LeafNodeHashInput` and `ParentNodeTreeHashInput` structs for a given node.
    fn node_content(&self) -> &[u8] {
        self.public_key.as_slice()
    }

    /// Get the list of unmerged leaves.
    fn unmerged_leaves(&self) -> &[LeafIndex] {
        self.unmerged_leaves.as_slice()
    }

    /// Clear the list of unmerged leaves.
    fn clear_unmerged_leaves(&mut self) {
        self.unmerged_leaves = Vec::new().into()
    }

    /// Add a `LeafIndex` to the node's list of unmerged leaves.
    pub(super) fn add_unmerged_leaf(&mut self, leaf_index: LeafIndex) {
        self.unmerged_leaves.push(leaf_index)
    }

    /// Set the parent hash value of this node. FIXME: Do we really need this
    /// function? Or can we set the parent hash when creating this node?
    fn set_parent_hash(&mut self, parent_hash: Vec<u8>) {
        self.parent_hash = parent_hash.into();
    }

    /// Get the parent hash value of this node.
    fn parent_hash(&self) -> &[u8] {
        self.parent_hash.as_slice()
    }

    /// Set the tree hash value for the given node. This assuming that the node
    /// caches the tree hash. FIXME: Do we really need this function? Or can we
    /// set the hash when creating this node?
    fn set_tree_hash(&mut self, tree_hash: Vec<u8>) {
        self.tree_hash = tree_hash
    }

    /// Get the tree hash value for the given node.
    fn tree_hash(&self) -> &[u8] {
        self.tree_hash.as_slice()
    }
}

impl Addressable for TreeSyncNode {
    type Address = Vec<u8>;

    fn address(&self) -> Option<Self::Address> {
        let address = match self {
            TreeSyncNode::LeafNode(kp) => kp.hpke_init_key().as_slice().to_vec(),
            TreeSyncNode::ParentNode(node) => node.node_content().to_vec(),
        };
        Some(address)
    }
}
