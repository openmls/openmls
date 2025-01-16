//! This module implements the ratchet tree component of MLS.
//!
//! It exposes the [`Node`] enum that can contain either a [`LeafNode`] or a [`ParentNode`].

// # Internal documentation
//
// This module provides the [`TreeSync`] struct, which contains the state
// shared between a group of MLS clients in the shape of a tree, where each
// non-blank leaf corresponds to one group member. The functions provided by
// its implementation allow the creation of a [`TreeSyncDiff`] instance, which
// in turn can be mutably operated on and merged back into the original
// [`TreeSync`] instance.
//
// The submodules of this module define the nodes of the tree (`nodes`),
// helper functions and structs for the algorithms used to sync the tree across
// the group ([`hashes`]) and the diff functionality ([`diff`]).
//
// Finally, this module contains the [`treekem`] module, which allows the
// encryption and decryption of updates to the tree.

#[cfg(any(feature = "test-utils", test))]
use std::fmt;

use openmls_traits::{
    crypto::OpenMlsCrypto,
    signatures::Signer,
    types::{Ciphersuite, CryptoError},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use self::{
    diff::{StagedTreeSyncDiff, TreeSyncDiff},
    node::{
        leaf_node::{
            Capabilities, LeafNodeSource, NewLeafNodeParams, TreeInfoTbs, TreePosition,
            VerifiableLeafNode,
        },
        NodeIn,
    },
    treesync_node::{TreeSyncLeafNode, TreeSyncNode, TreeSyncParentNode},
};
use crate::binary_tree::array_representation::ParentNodeIndex;
#[cfg(any(feature = "test-utils", test))]
use crate::{binary_tree::array_representation::level, test_utils::bytes_to_hex};
use crate::{
    binary_tree::{
        array_representation::{is_node_in_tree, tree::TreeNode, LeafNodeIndex, TreeSize},
        MlsBinaryTree, MlsBinaryTreeError,
    },
    ciphersuite::{signable::Verifiable, Secret},
    credentials::CredentialWithKey,
    error::LibraryError,
    extensions::Extensions,
    group::{GroupId, Member},
    key_packages::Lifetime,
    messages::{PathSecret, PathSecretError},
    schedule::CommitSecret,
    storage::OpenMlsProvider,
};

// Private
mod hashes;
use errors::*;

// Crate
pub(crate) mod diff;
pub(crate) mod node;
pub(crate) mod treekem;
pub(crate) mod treesync_node;

use node::encryption_keys::EncryptionKeyPair;

// Public
pub mod errors;
#[cfg(feature = "test-utils")]
pub use node::encryption_keys::test_utils;
pub use node::encryption_keys::EncryptionKey;

// Public re-exports
pub use node::{
    leaf_node::{LeafNode, LeafNodeParameters, LeafNodeParametersBuilder, LeafNodeUpdateError},
    parent_node::ParentNode,
    Node,
};

// Tests
#[cfg(any(feature = "test-utils", test))]
pub mod tests_and_kats;

/// An exported ratchet tree as used in, e.g., [`GroupInfo`](crate::messages::group_info::GroupInfo).
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub struct RatchetTree(Vec<Option<Node>>);

/// An error during processing of an incoming ratchet tree.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum RatchetTreeError {
    /// The ratchet tree is empty.
    #[error("The ratchet tree has no nodes.")]
    MissingNodes,
    /// The ratchet tree has a trailing blank node.
    #[error("The ratchet tree has trailing blank nodes.")]
    TrailingBlankNodes,
    /// Invalid node signature.
    #[error("Invalid node signature.")]
    InvalidNodeSignature,
    /// Wrong node type.
    #[error("Wrong node type.")]
    WrongNodeType,
}

impl RatchetTree {
    /// Create a [`RatchetTree`] from a vector of nodes stripping all trailing blank nodes.
    ///
    /// Note: The caller must ensure to call this with a vector that is *not* empty after removing all trailing blank nodes.
    fn trimmed(mut nodes: Vec<Option<Node>>) -> Self {
        // Remove all trailing blank nodes.
        match nodes.iter().enumerate().rfind(|(_, node)| node.is_some()) {
            Some((rightmost_nonempty_position, _)) => {
                // We need to add 1 to `rightmost_nonempty_position` to keep the rightmost node.
                nodes.resize(rightmost_nonempty_position + 1, None);
            }
            None => {
                // If there is no rightmost non-blank node, the vector consist of blank nodes only.
                nodes.clear();
            }
        }

        debug_assert!(!nodes.is_empty(), "Caller should have ensured that `RatchetTree::trimmed` is not called with a vector that is empty after removing all trailing blank nodes.");
        Self(nodes)
    }

    /// Create a new [`RatchetTree`] from a vector of nodes.
    pub(crate) fn try_from_nodes(
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        nodes: Vec<Option<NodeIn>>,
        group_id: &GroupId,
    ) -> Result<Self, RatchetTreeError> {
        // ValSem300: "Exported ratchet trees must not have trailing blank nodes."
        //
        // We can check this by only looking at the last node (if any).
        match nodes.last() {
            Some(None) => {
                // The ratchet tree is not empty, i.e., has a last node, *but* the last node *is* blank.
                Err(RatchetTreeError::TrailingBlankNodes)
            }
            None => {
                // The ratchet tree is empty.
                Err(RatchetTreeError::MissingNodes)
            }
            Some(Some(_)) => {
                // The ratchet tree is not empty, i.e., has a last node, and the last node is not blank.

                // Verify the nodes.
                // https://validation.openmls.tech/#valn1407
                let mut verified_nodes = Vec::new();
                for (index, node) in nodes.into_iter().enumerate() {
                    let verified_node = match (index % 2, node) {
                        // Even indices must be leaf nodes.
                        (0, Some(NodeIn::LeafNode(leaf_node))) => {
                            let tree_position = TreePosition::new(
                                group_id.clone(),
                                LeafNodeIndex::new((index / 2) as u32),
                            );
                            let verifiable_leaf_node = leaf_node.into_verifiable_leaf_node();
                            let signature_key = verifiable_leaf_node
                                .signature_key()
                                .clone()
                                .into_signature_public_key_enriched(
                                    ciphersuite.signature_algorithm(),
                                );
                            Some(Node::LeafNode(match verifiable_leaf_node {
                                VerifiableLeafNode::KeyPackage(leaf_node) => leaf_node
                                    .verify(crypto, &signature_key)
                                    .map_err(|_| RatchetTreeError::InvalidNodeSignature)?,
                                VerifiableLeafNode::Update(mut leaf_node) => {
                                    leaf_node.add_tree_position(tree_position);
                                    leaf_node
                                        .verify(crypto, &signature_key)
                                        .map_err(|_| RatchetTreeError::InvalidNodeSignature)?
                                }
                                VerifiableLeafNode::Commit(mut leaf_node) => {
                                    leaf_node.add_tree_position(tree_position);
                                    leaf_node
                                        .verify(crypto, &signature_key)
                                        .map_err(|_| RatchetTreeError::InvalidNodeSignature)?
                                }
                            }))
                        }
                        // Odd indices must be parent nodes.
                        (1, Some(NodeIn::ParentNode(parent_node))) => {
                            Some(Node::ParentNode(parent_node))
                        }
                        // Blank nodes.
                        (_, None) => None,
                        // All other cases are invalid.
                        _ => {
                            return Err(RatchetTreeError::WrongNodeType);
                        }
                    };
                    verified_nodes.push(verified_node);
                }
                Ok(Self::trimmed(verified_nodes))
            }
        }
    }
}

/// A ratchet tree made of unverified nodes. This is used for deserialization
/// and verification.
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
pub struct RatchetTreeIn(Vec<Option<NodeIn>>);

impl RatchetTreeIn {
    /// Create a new [`RatchetTreeIn`] from a vector of nodes after verifying
    /// the nodes.
    pub fn into_verified(
        self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        group_id: &GroupId,
    ) -> Result<RatchetTree, RatchetTreeError> {
        RatchetTree::try_from_nodes(ciphersuite, crypto, self.0, group_id)
    }

    fn from_ratchet_tree(ratchet_tree: RatchetTree) -> Self {
        let nodes = ratchet_tree
            .0
            .into_iter()
            .map(|node| node.map(NodeIn::from))
            .collect();
        Self(nodes)
    }

    #[cfg(test)]
    pub(crate) fn from_nodes(nodes: Vec<Option<NodeIn>>) -> Self {
        Self(nodes)
    }
}

impl From<RatchetTree> for RatchetTreeIn {
    fn from(ratchet_tree: RatchetTree) -> Self {
        RatchetTreeIn::from_ratchet_tree(ratchet_tree)
    }
}

// The following `From` implementation breaks abstraction layers and MUST
// NOT be made available outside of tests or "test-utils".
#[cfg(any(feature = "test-utils", test))]
impl From<RatchetTreeIn> for RatchetTree {
    fn from(ratchet_tree_in: RatchetTreeIn) -> Self {
        Self(
            ratchet_tree_in
                .0
                .into_iter()
                .map(|node| node.map(Node::from))
                .collect(),
        )
    }
}

#[cfg(any(feature = "test-utils", test))]
fn log2(x: u32) -> usize {
    if x == 0 {
        return 0;
    }
    (31 - x.leading_zeros()) as usize
}

#[cfg(any(feature = "test-utils", test))]
pub(crate) fn root(size: u32) -> u32 {
    (1 << log2(size)) - 1
}

#[cfg(any(feature = "test-utils", test))]
impl fmt::Display for RatchetTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let factor = 3;
        let nodes = &self.0;
        let tree_size = nodes.len() as u32;

        for (i, node) in nodes.iter().enumerate() {
            let level = level(i as u32);
            write!(f, "{i:04}")?;
            if let Some(node) = node {
                let (key_bytes, parent_hash_bytes) = match node {
                    Node::LeafNode(leaf_node) => {
                        write!(f, "\tL      ")?;
                        let key_bytes = leaf_node.encryption_key().as_slice();
                        let parent_hash_bytes = leaf_node
                            .parent_hash()
                            .map(bytes_to_hex)
                            .unwrap_or_default();
                        (key_bytes, parent_hash_bytes)
                    }
                    Node::ParentNode(parent_node) => {
                        if root(tree_size) == i as u32 {
                            write!(f, "\tP (*)  ")?;
                        } else {
                            write!(f, "\tP      ")?;
                        }
                        let key_bytes = parent_node.public_key().as_slice();
                        let parent_hash_string = bytes_to_hex(parent_node.parent_hash());
                        (key_bytes, parent_hash_string)
                    }
                };
                write!(
                    f,
                    "PK: {}  PH: {} | ",
                    bytes_to_hex(key_bytes),
                    if !parent_hash_bytes.is_empty() {
                        parent_hash_bytes
                    } else {
                        str::repeat("  ", 32)
                    }
                )?;

                write!(f, "{}◼︎", str::repeat(" ", level * factor))?;
            } else {
                if root(tree_size) == i as u32 {
                    write!(
                        f,
                        "\t_ (*)  PK: {}  PH: {} | ",
                        str::repeat("__", 32),
                        str::repeat("__", 32)
                    )?;
                } else {
                    write!(
                        f,
                        "\t_      PK: {}  PH: {} | ",
                        str::repeat("__", 32),
                        str::repeat("__", 32)
                    )?;
                }

                write!(f, "{}❑", str::repeat(" ", level * factor))?;
            }
            writeln!(f)?;
        }

        Ok(())
    }
}

/// The [`TreeSync`] struct holds an `MlsBinaryTree` instance, which contains
/// the state that is synced across the group, as well as the [`LeafNodeIndex`]
/// pointing to the leaf of this group member and the current hash of the tree.
///
/// It follows the same pattern of tree and diff as the underlying
/// `MlsBinaryTree`, where the [`TreeSync`] instance is immutable safe for
/// merging a `TreeSyncDiff`, which can be created, staged and merged (see
/// `TreeSyncDiff`).
///
/// [`TreeSync`] instance guarantee a few invariants that are checked upon
/// creating a new instance from an imported set of nodes, as well as when
/// merging a diff.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq, Clone))]
pub(crate) struct TreeSync {
    tree: MlsBinaryTree<TreeSyncLeafNode, TreeSyncParentNode>,
    tree_hash: Vec<u8>,
}

impl TreeSync {
    /// Create a new tree with an own leaf for the given credential.
    ///
    /// Returns the resulting [`TreeSync`] instance, as well as the
    /// corresponding [`CommitSecret`].
    pub(crate) fn new(
        provider: &impl OpenMlsProvider,
        signer: &impl Signer,
        ciphersuite: Ciphersuite,
        credential_with_key: CredentialWithKey,
        life_time: Lifetime,
        capabilities: Capabilities,
        extensions: Extensions,
    ) -> Result<(Self, CommitSecret, EncryptionKeyPair), LibraryError> {
        let new_leaf_node_params = NewLeafNodeParams {
            ciphersuite,
            credential_with_key,
            // Creation of a group is considered to be from a key package.
            leaf_node_source: LeafNodeSource::KeyPackage(life_time),
            capabilities,
            extensions,
            tree_info_tbs: TreeInfoTbs::KeyPackage,
        };
        let (leaf, encryption_key_pair) = LeafNode::new(provider, signer, new_leaf_node_params)?;

        let node = Node::LeafNode(leaf);
        let path_secret: PathSecret = Secret::random(ciphersuite, provider.rand())
            .map_err(LibraryError::unexpected_crypto_error)?
            .into();
        let commit_secret: CommitSecret = path_secret
            .derive_path_secret(provider.crypto(), ciphersuite)?
            .into();
        let nodes = vec![TreeSyncNode::from(node).into()];
        let tree = MlsBinaryTree::new(nodes)
            .map_err(|_| LibraryError::custom("Unexpected error creating the binary tree."))?;
        let mut tree_sync = Self {
            tree,
            tree_hash: vec![],
        };
        // Populate tree hash caches.
        tree_sync.populate_parent_hashes(provider.crypto(), ciphersuite)?;

        Ok((tree_sync, commit_secret, encryption_key_pair))
    }

    /// Return the tree hash of the root node of the tree.
    pub(crate) fn tree_hash(&self) -> &[u8] {
        self.tree_hash.as_slice()
    }

    /// Merge the given diff into this `TreeSync` instance, refreshing the
    /// `tree_hash` value in the process.
    pub(crate) fn merge_diff(&mut self, tree_sync_diff: StagedTreeSyncDiff) {
        let (diff, new_tree_hash) = tree_sync_diff.into_parts();
        self.tree_hash = new_tree_hash;
        self.tree.merge_diff(diff);
    }

    /// Create an empty diff based on this [`TreeSync`] instance all operations
    /// are created based on an initial, empty [`TreeSyncDiff`].
    pub(crate) fn empty_diff(&self) -> TreeSyncDiff {
        self.into()
    }

    /// A helper function that generates a [`TreeSync`] instance from the given
    /// slice of nodes. It verifies that the provided encryption key is present
    /// in the tree and that the invariants documented in [`TreeSync`] hold.
    pub(crate) fn from_ratchet_tree(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        ratchet_tree: RatchetTree,
    ) -> Result<Self, TreeSyncFromNodesError> {
        // TODO #800: Unmerged leaves should be checked
        let mut ts_nodes: Vec<TreeNode<TreeSyncLeafNode, TreeSyncParentNode>> =
            Vec::with_capacity(ratchet_tree.0.len());

        // Set the leaf indices in all the leaves and convert the node types.
        for (node_index, node_option) in ratchet_tree.0.into_iter().enumerate() {
            let ts_node_option: TreeNode<TreeSyncLeafNode, TreeSyncParentNode> = match node_option {
                Some(node) => TreeSyncNode::from(node).into(),
                None => {
                    if node_index % 2 == 0 {
                        TreeNode::Leaf(TreeSyncLeafNode::blank())
                    } else {
                        TreeNode::Parent(TreeSyncParentNode::blank())
                    }
                }
            };
            ts_nodes.push(ts_node_option);
        }

        let tree = MlsBinaryTree::new(ts_nodes).map_err(|_| PublicTreeError::MalformedTree)?;
        let mut tree_sync = Self {
            tree,
            tree_hash: vec![],
        };

        // Verify all parent hashes.
        tree_sync
            .verify_parent_hashes(crypto, ciphersuite)
            .map_err(|e| match e {
                TreeSyncParentHashError::LibraryError(e) => e.into(),
                TreeSyncParentHashError::InvalidParentHash => {
                    TreeSyncFromNodesError::from(PublicTreeError::InvalidParentHash)
                }
            })?;

        // Populate tree hash caches.
        tree_sync.populate_parent_hashes(crypto, ciphersuite)?;
        Ok(tree_sync)
    }

    /// Find the `LeafNodeIndex` which a new leaf would have if it were added to the
    /// tree. This is either the left-most blank node or, if there are no blank
    /// leaves, the leaf count, since adding a member would extend the tree by
    /// one leaf.
    pub(crate) fn free_leaf_index(&self) -> LeafNodeIndex {
        let diff = self.empty_diff();
        diff.free_leaf_index()
    }

    /// Populate the parent hash caches of all nodes in the tree.
    fn populate_parent_hashes(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<(), LibraryError> {
        let diff = self.empty_diff();
        // Make the diff into a staged diff. This implicitly computes the
        // tree hashes and poulates the tree hash caches.
        let staged_diff = diff.into_staged_diff(crypto, ciphersuite)?;
        // Merge the diff.
        self.merge_diff(staged_diff);
        Ok(())
    }

    /// Verify the parent hashes of all parent nodes in the tree.
    ///
    /// Returns an error if one of the parent nodes in the tree has an invalid
    /// parent hash.
    fn verify_parent_hashes(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<(), TreeSyncParentHashError> {
        // The ability to verify parent hashes is required both for diffs and
        // treesync instances. We choose the computationally slightly more
        // expensive solution of implementing parent hash verification for the
        // diff and creating an empty diff whenever we need to verify parent
        // hashes for a `TreeSync` instance. At the time of writing, this
        // happens only upon construction of a `TreeSync` instance from a vector
        // of nodes. The alternative solution would be to create a `TreeLike`
        // trait, which allows tree navigation and node access. We could then
        // implement `TreeLike` for both `TreeSync` and `TreeSyncDiff` and
        // finally implement parent hash verification for any struct that
        // implements `TreeLike`. We choose the less complex version for now.
        // Should this turn out to cause too much computational overhead, we
        // should reconsider and choose the alternative sketched above
        let diff = self.empty_diff();
        // No need to merge the diff, since we didn't actually modify any state.
        diff.verify_parent_hashes(crypto, ciphersuite)
    }

    /// Returns the tree size
    pub(crate) fn tree_size(&self) -> TreeSize {
        self.tree.tree_size()
    }

    /// Returns an iterator over the (non-blank) [`LeafNode`]s in the tree.
    pub(crate) fn full_leaves(&self) -> impl Iterator<Item = &LeafNode> {
        self.tree
            .leaves()
            .filter_map(|(_, tsn)| tsn.node().as_ref())
    }

    /// Returns an iterator over the (non-blank) [`ParentNode`]s in the tree.
    pub(crate) fn full_parents(&self) -> impl Iterator<Item = (ParentNodeIndex, &ParentNode)> {
        self.tree
            .parents()
            .filter_map(|(index, tsn)| tsn.node().as_ref().map(|pn| (index, pn)))
    }

    /// Returns the index of the last full leaf in the tree.
    fn rightmost_full_leaf(&self) -> LeafNodeIndex {
        let mut index = LeafNodeIndex::new(0);
        for (leaf_index, leaf) in self.tree.leaves() {
            if leaf.node().as_ref().is_some() {
                index = leaf_index;
            }
        }
        index
    }

    /// Returns a list of [`Member`]s containing only full nodes.
    ///
    /// XXX: For performance reasons we probably want to have this in a borrowing
    ///      version as well. But it might well go away again.
    pub(crate) fn full_leave_members(&self) -> impl Iterator<Item = Member> + '_ {
        self.tree
            .leaves()
            // Filter out blank nodes
            .filter_map(|(index, tsn)| tsn.node().as_ref().map(|node| (index, node)))
            // Map to `Member`
            .map(|(index, leaf_node)| {
                Member::new(
                    index,
                    leaf_node.encryption_key().as_slice().to_vec(),
                    leaf_node.signature_key().as_slice().to_vec(),
                    leaf_node.credential().clone(),
                )
            })
    }

    /// Returns the nodes in the tree ordered according to the
    /// array-representation of the underlying binary tree.
    pub fn export_ratchet_tree(&self) -> RatchetTree {
        let mut nodes = Vec::new();

        // Determine the index of the rightmost full leaf.
        let max_length = self.rightmost_full_leaf();

        // We take all the leaves including the rightmost full leaf, blank
        // leaves beyond that are trimmed.
        let mut leaves = self
            .tree
            .leaves()
            .map(|(_, leaf)| leaf)
            .take(max_length.usize() + 1);

        // Get the first leaf.
        if let Some(leaf) = leaves.next() {
            nodes.push(leaf.node().clone().map(Node::LeafNode));
        } else {
            // The tree was empty.
            return RatchetTree::trimmed(vec![]);
        }

        // Blank parent node used for padding
        let default_parent = TreeSyncParentNode::default();

        // Get the parents.
        let parents = self
            .tree
            .parents()
            // Drop the index
            .map(|(_, parent)| parent)
            // Take the parents up to the max length
            .take(max_length.usize())
            // Pad the parents with blank nodes if needed
            .chain(
                (self.tree.parents().count()..self.tree.leaves().count() - 1)
                    .map(|_| &default_parent),
            );

        // Interleave the leaves and parents.
        for (leaf, parent) in leaves.zip(parents) {
            nodes.push(parent.node().clone().map(Node::ParentNode));
            nodes.push(leaf.node().clone().map(Node::LeafNode));
        }

        RatchetTree::trimmed(nodes)
    }

    /// Return a reference to the leaf at the given `LeafNodeIndex` or `None` if the
    /// leaf is blank.
    pub(crate) fn leaf(&self, leaf_index: LeafNodeIndex) -> Option<&LeafNode> {
        let tsn = self.tree.leaf(leaf_index);
        tsn.node().as_ref()
    }

    /// Returns a [`TreeSyncError`] if the `leaf_index` is not a leaf in this
    /// tree or empty.
    pub(crate) fn is_leaf_in_tree(&self, leaf_index: LeafNodeIndex) -> bool {
        is_node_in_tree(leaf_index.into(), self.tree.tree_size())
    }

    /// Return a vector containing all [`EncryptionKey`]s for which the owner of
    /// the given `leaf_index` should have private key material.
    pub(crate) fn owned_encryption_keys(&self, leaf_index: LeafNodeIndex) -> Vec<EncryptionKey> {
        self.empty_diff()
            .encryption_keys(leaf_index)
            .cloned()
            .collect::<Vec<EncryptionKey>>()
    }

    /// Derives [`EncryptionKeyPair`]s for the nodes in the shared direct path
    /// of the leaves with index `leaf_index` and `sender_index`.  This function
    /// also checks that the derived public keys match the existing public keys.
    ///
    /// Returns the `CommitSecret` derived from the path secret of the root
    /// node, as well as the derived [`EncryptionKeyPair`]s. Returns an error if
    /// the target leaf is outside of the tree.
    ///
    /// Returns TreeSyncSetPathError::PublicKeyMismatch if the derived keys don't
    /// match with the existing ones.
    ///
    /// Returns TreeSyncSetPathError::LibraryError if the sender_index is not
    /// in the tree.
    pub(crate) fn derive_path_secrets(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        mut path_secret: PathSecret,
        sender_index: LeafNodeIndex,
        leaf_index: LeafNodeIndex,
    ) -> Result<(Vec<EncryptionKeyPair>, CommitSecret), DerivePathError> {
        // We assume both nodes are in the tree, since the sender_index must be in the tree
        // Skip the nodes in the subtree path for which we are an unmerged leaf.
        let subtree_path = self.tree.subtree_path(leaf_index, sender_index);
        let mut keypairs = Vec::new();
        for parent_index in subtree_path {
            // We know the node is in the tree, since it is in the subtree path
            let tsn = self.tree.parent_by_index(parent_index);
            // We only care about non-blank nodes.
            if let Some(ref parent_node) = tsn.node() {
                // If our own leaf index is not in the list of unmerged leaves
                // then we should have the secret for this node.
                if !parent_node.unmerged_leaves().contains(&leaf_index) {
                    let keypair = path_secret.derive_key_pair(crypto, ciphersuite)?;
                    // The derived public key should match the one in the node.
                    // If not, the tree is corrupt.
                    if parent_node.encryption_key() != keypair.public_key() {
                        return Err(DerivePathError::PublicKeyMismatch);
                    } else {
                        // If everything is ok, set the private key and derive
                        // the next path secret.
                        keypairs.push(keypair);
                        path_secret = path_secret.derive_path_secret(crypto, ciphersuite)?;
                    }
                };
                // If the leaf is blank or our index is in the list of unmerged
                // leaves, go to the next node.
            }
        }
        Ok((keypairs, path_secret.into()))
    }

    /// Return a reference to the parent node at the given `ParentNodeIndex` or
    /// `None` if the node is blank.
    pub(crate) fn parent(&self, node_index: ParentNodeIndex) -> Option<&ParentNode> {
        let tsn = self.tree.parent(node_index);
        tsn.node().as_ref()
    }
}

#[cfg(test)]
impl TreeSync {
    pub(crate) fn leaf_count(&self) -> u32 {
        self.tree.leaf_count()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic]
    /// This should only panic in debug-builds.
    fn test_ratchet_tree_internal_empty() {
        RatchetTree::trimmed(vec![]);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic]
    /// This should only panic in debug-builds.
    fn test_ratchet_tree_internal_empty_after_trim() {
        RatchetTree::trimmed(vec![None]);
    }

    #[openmls_test::openmls_test]
    fn test_ratchet_tree_trailing_blank_nodes(
        ciphersuite: Ciphersuite,
        provider: &impl OpenMlsProvider,
    ) {
        use openmls_traits::OpenMlsProvider;

        let (key_package, _, _) = crate::key_packages::tests::key_package(ciphersuite, provider);
        let node_in = NodeIn::from(Node::LeafNode(LeafNode::from(key_package)));
        let tests = [
            (vec![], false),
            (vec![None], false),
            (vec![None, None], false),
            (vec![None, None, None], false),
            (vec![Some(node_in.clone())], true),
            (vec![Some(node_in.clone()), None], false),
            (
                vec![Some(node_in.clone()), None, Some(node_in.clone())],
                true,
            ),
            (
                vec![Some(node_in.clone()), None, Some(node_in), None],
                false,
            ),
        ];

        for (test, expected) in tests.into_iter() {
            let got = RatchetTree::try_from_nodes(
                ciphersuite,
                provider.crypto(),
                test,
                &GroupId::random(provider.rand()),
            )
            .is_ok();
            assert_eq!(got, expected);
        }
    }

    #[cfg(not(debug_assertions))]
    #[test]
    /// This should not panic in release-builds.
    fn test_ratchet_tree_internal_empty() {
        RatchetTree::trimmed(vec![]);
    }

    #[cfg(not(debug_assertions))]
    #[test]
    /// This should not panic in release-builds.
    fn test_ratchet_tree_internal_empty_after_trim() {
        RatchetTree::trimmed(vec![None]);
    }
}
