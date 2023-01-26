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

use openmls_traits::{
    signatures::Signer,
    types::{Ciphersuite, CryptoError},
    OpenMlsCryptoProvider,
};
use serde::{Deserialize, Serialize};

use crate::{
    binary_tree::{
        array_representation::{is_node_in_tree, tree::TreeNode, LeafNodeIndex},
        MlsBinaryTree, MlsBinaryTreeError,
    },
    ciphersuite::{Secret, SignaturePublicKey},
    credentials::CredentialWithKey,
    error::LibraryError,
    extensions::Extensions,
    framing::SenderError,
    group::{config::CryptoConfig, Member},
    messages::{PathSecret, PathSecretError},
    schedule::CommitSecret,
};

use self::{
    diff::{StagedTreeSyncDiff, TreeSyncDiff},
    node::{
        encryption_keys::{EncryptionKey, EncryptionKeyPair},
        leaf_node::{Capabilities, LeafNodeSource, Lifetime, OpenMlsLeafNode},
    },
    treesync_node::{TreeSyncLeafNode, TreeSyncNode, TreeSyncParentNode},
};

// Private
mod hashes;
use errors::*;

// Crate
pub(crate) mod diff;
pub(crate) mod node;
pub(crate) mod treekem;
pub(crate) mod treesync_node;

// Public
pub mod errors;

// Public re-exports
pub use node::{leaf_node::LeafNode, parent_node::ParentNode, Node};

// Tests
#[cfg(any(feature = "test-utils", test))]
pub mod tests_and_kats;

/// The [`TreeSync`] struct holds an [`MlsBinaryTree`] instance, which contains
/// the state that is synced across the group, as well as the [`LeafNodeIndex`]
/// pointing to the leaf of this group member and the current hash of the tree.
///
/// It follows the same pattern of tree and diff as the underlying
/// [`MlsBinaryTree`], where the [`TreeSync`] instance is immutable safe for
/// merging a [`TreeSyncDiff`], which can be created, staged and merged (see
/// [`TreeSyncDiff`]).
///
/// [`TreeSync`] instance guarantee a few invariants that are checked upon
/// creating a new instance from an imported set of nodes, as well as when
/// merging a diff.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
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
        backend: &impl OpenMlsCryptoProvider,
        signer: &impl Signer,
        config: CryptoConfig,
        credential_with_key: CredentialWithKey,
        life_time: Lifetime,
        capabilities: Capabilities,
        extensions: Extensions,
    ) -> Result<(Self, CommitSecret, EncryptionKeyPair), LibraryError> {
        let (leaf, encryption_key_pair) = OpenMlsLeafNode::new(
            config,
            // Creation of a group is considered to be from a key package.
            LeafNodeSource::KeyPackage(life_time),
            backend,
            signer,
            credential_with_key,
            capabilities,
            extensions,
        )?;

        let node = Node::LeafNode(leaf);
        let path_secret: PathSecret = Secret::random(config.ciphersuite, backend, None)
            .map_err(LibraryError::unexpected_crypto_error)?
            .into();
        let commit_secret: CommitSecret = path_secret
            .derive_path_secret(backend, config.ciphersuite)?
            .into();
        let nodes = vec![TreeSyncNode::from(node).into()];
        let tree = MlsBinaryTree::new(nodes)
            .map_err(|_| LibraryError::custom("Unexpected error creating the binary tree."))?;
        let mut tree_sync = Self {
            tree,
            tree_hash: vec![],
        };
        // Populate tree hash caches.
        tree_sync.populate_parent_hashes(backend, config.ciphersuite)?;

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
    pub(crate) fn from_nodes(
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        node_options: &[Option<Node>],
    ) -> Result<Self, TreeSyncFromNodesError> {
        // TODO #800: Unmerged leaves should be checked
        let mut ts_nodes: Vec<TreeNode<TreeSyncLeafNode, TreeSyncParentNode>> =
            Vec::with_capacity(node_options.len());

        // Set the leaf indices in all the leaves and convert the node types.
        for (node_index, node_option) in node_options.iter().enumerate() {
            let ts_node_option: TreeNode<TreeSyncLeafNode, TreeSyncParentNode> = match node_option {
                Some(node) => {
                    let mut node = node.clone();
                    if let Node::LeafNode(ref mut leaf_node) = node {
                        let leaf_index = LeafNodeIndex::new((node_index / 2) as u32);
                        leaf_node.set_leaf_index(leaf_index);
                    }
                    TreeSyncNode::from(node).into()
                }
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
            .verify_parent_hashes(backend, ciphersuite)
            .map_err(|e| match e {
                TreeSyncParentHashError::LibraryError(e) => e.into(),
                TreeSyncParentHashError::InvalidParentHash => {
                    TreeSyncFromNodesError::from(PublicTreeError::InvalidParentHash)
                }
            })?;
        // Populate tree hash caches.
        tree_sync.populate_parent_hashes(backend, ciphersuite)?;
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
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
    ) -> Result<(), LibraryError> {
        let diff = self.empty_diff();
        // Make the diff into a staged diff. This implicitly computes the
        // tree hashes and poulates the tree hash caches.
        let staged_diff = diff.into_staged_diff(backend, ciphersuite)?;
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
        backend: &impl OpenMlsCryptoProvider,
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
        diff.verify_parent_hashes(backend, ciphersuite)
    }

    /// Returns the number of leaves in the tree.
    ///
    /// This function should not fail and only returns a [`Result`], because it
    /// might throw a [LibraryError](TreeSyncError::LibraryError).
    pub(crate) fn leaf_count(&self) -> u32 {
        self.tree.leaf_count()
    }

    /// Returns a list of [`LeafNodeIndex`]es containing only full nodes.
    pub(crate) fn full_leaves(&self) -> Vec<&OpenMlsLeafNode> {
        self.tree
            .leaves()
            .filter_map(|(_, tsn)| tsn.node().as_ref())
            .collect()
    }

    /// Returns the [`LeafNodeIndex`] of the leaf that contains the given
    /// [`SignaturePublicKey`].
    ///
    /// Returns `None` if no matching leaf can be found.
    pub(crate) fn find_leaf(&self, signature_key: &SignaturePublicKey) -> Option<LeafNodeIndex> {
        self.full_leave_members()
            .filter_map(|m| {
                if m.signature_key == signature_key.as_slice() {
                    Some(m.index)
                } else {
                    None
                }
            })
            .next()
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
                    leaf_node.public_key().as_slice().to_vec(),
                    leaf_node.leaf_node.signature_key().as_slice().to_vec(),
                    leaf_node.leaf_node.credential().identity().to_vec(),
                )
            })
    }

    /// Returns a [`TreeSyncError::UnsupportedExtension`] if an [`ExtensionType`]
    /// in `extensions` is not supported by a leaf in this tree.
    #[cfg(test)]
    pub(crate) fn check_extension_support(
        &self,
        extensions: &[crate::extensions::ExtensionType],
    ) -> Result<(), TreeSyncError> {
        if self.tree.leaves().any(|(_, tsn)| {
            tsn.node()
                .as_ref()
                .map(|node| {
                    node.leaf_node()
                        .check_extension_support(extensions)
                        .map_err(|_| LibraryError::custom("This is never used, so we don't care"))
                })
                .is_none() // Return true if this is none
        }) {
            Err(TreeSyncError::UnsupportedExtension)
        } else {
            Ok(())
        }
    }

    /// Returns the nodes in the tree ordered according to the
    /// array-representation of the underlying binary tree.
    pub fn export_nodes(&self) -> Vec<Option<Node>> {
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
            nodes.push(leaf.node_without_index().map(Node::LeafNode));
        } else {
            // The tree was empty.
            return vec![];
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
            nodes.push(leaf.node_without_index().clone().map(Node::LeafNode));
        }

        nodes
    }

    /// Return a reference to the leaf at the given `LeafNodeIndex` or `None` if the
    /// leaf is blank.
    pub(crate) fn leaf(&self, leaf_index: LeafNodeIndex) -> Option<&OpenMlsLeafNode> {
        let tsn = self.tree.leaf(leaf_index);
        tsn.node().as_ref()
    }

    /// Returns a [`TreeSyncError`] if the `leaf_index` is not a leaf in this
    /// tree or empty.
    pub(crate) fn is_leaf_in_tree(&self, leaf_index: LeafNodeIndex) -> bool {
        is_node_in_tree(leaf_index.into(), self.tree.size())
    }

    /// Return a vector containing all [`EncryptionKey`]s for which the owner of
    /// the given `leaf_index` should have private key material.
    pub(crate) fn owned_encryption_keys(&self, leaf_index: LeafNodeIndex) -> Vec<EncryptionKey> {
        self.empty_diff()
            .encryption_keys(leaf_index)
            .cloned()
            .collect::<Vec<EncryptionKey>>()
    }
}
