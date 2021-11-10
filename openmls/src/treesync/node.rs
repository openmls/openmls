use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{
    Deserialize, Serialize, Size, TlsByteVecU8, TlsSerialize, TlsSize, TlsSliceU32, TlsSliceU8,
    TlsVecU32,
};

use crate::{
    binary_tree::{Addressable, LeafIndex},
    ciphersuite::{Ciphersuite, HpkePublicKey},
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
    pub(crate) fn as_leaf_node(&self) -> Result<&KeyPackage, TreeSyncNodeError> {
        match self {
            TreeSyncNode::LeafNode(kp) => Ok(&kp),
            TreeSyncNode::ParentNode(_) => Err(TreeSyncNodeError::AsLeafError),
        }
    }

    pub(crate) fn as_leaf_node_mut(&mut self) -> Result<&mut KeyPackage, TreeSyncNodeError> {
        match self {
            TreeSyncNode::LeafNode(ref mut kp) => Ok(kp),
            TreeSyncNode::ParentNode(_) => Err(TreeSyncNodeError::AsLeafError),
        }
    }

    pub(crate) fn as_parent_node_mut(&mut self) -> Result<&mut Node, TreeSyncNodeError> {
        match self {
            TreeSyncNode::LeafNode(_) => Err(TreeSyncNodeError::AsLeafError),
            TreeSyncNode::ParentNode(ref mut node) => Ok(node),
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
    fn node_content(&self) -> &HpkePublicKey {
        &self.public_key
    }

    /// Get the list of unmerged leaves.
    pub(crate) fn unmerged_leaves(&self) -> &[LeafIndex] {
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
    pub(super) fn set_parent_hash(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        parent_hash: &[u8],
        original_child_resolution: &[HpkePublicKey],
    ) {
        let parent_hash_input =
            ParentHashInput::new(&self.public_key, &parent_hash, original_child_resolution);
        self.parent_hash = parent_hash_input.hash(backend, ciphersuite).into()
    }

    /// Get the parent hash value of this node.
    pub(crate) fn parent_hash(&self) -> &[u8] {
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
    type Address = HpkePublicKey;

    fn address(&self) -> Option<Self::Address> {
        let address = match self {
            TreeSyncNode::LeafNode(kp) => kp.hpke_init_key().clone(),
            TreeSyncNode::ParentNode(node) => node.node_content().clone(),
        };
        Some(address)
    }
}

#[derive(TlsSerialize, TlsSize)]
pub(crate) struct ParentHashInput<'a> {
    public_key: &'a HpkePublicKey,
    parent_hash: TlsSliceU8<'a, u8>,
    original_child_resolution: TlsSliceU32<'a, HpkePublicKey>,
}

impl<'a> ParentHashInput<'a> {
    pub(crate) fn new(
        public_key: &'a HpkePublicKey,
        parent_hash: &'a [u8],
        original_child_resolution: &'a [HpkePublicKey],
    ) -> Self {
        Self {
            public_key,
            parent_hash: TlsSliceU8(parent_hash),
            original_child_resolution: TlsSliceU32(original_child_resolution),
        }
    }
    pub(crate) fn hash(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
    ) -> Vec<u8> {
        let payload = self.tls_serialize_detached().unwrap();
        ciphersuite.hash(backend, &payload)
    }
}

implement_error! {
    pub enum ParentHashError {
        EndedWithLeafNode = "The search for a valid child ended with a leaf node.",
        AllChecksFailed = "All checks failed: Neither child has the right parent hash.",
        InputNotParentNode = "The input node is not a parent node.",
        NotAParentNode = "The node is not a parent node.",
        EmptyParentNode = "The parent node was blank.",
    }
}
