//! This module implements the ratchet tree component of MLS.
//!
//! # About
//!
//! This module provides the [`TreeSync`] struct, which contains the state
//! shared between a group of MLS clients in the shape of a tree, where each
//! non-blank leaf corresponds to one group member. The functions provided by
//! its implementation allow the creation of a [`TreeSyncDiff`] instance, which
//! in turn can be mutably operated on and merged back into the original
//! [`TreeSync`] instance.
//!
//! The submodules of this module define the nodes of the tree (`nodes`),
//! helper functions and structs for the algorithms used to sync the tree across
//! the group ([`hashes`]) and the diff functionality ([`diff`]).
//!
//! Finally, this module contains the [`treekem`] module, which allows the
//! encryption and decryption of updates to the tree.
//!
//! # Don't Panic!
//!
//! Functions in this module should never panic. However, if there is a bug in
//! the implementation, a function will return an unrecoverable
//! [`LibraryError`](TreeSyncError::LibraryError). This means that some
//! functions that are not expected to fail and throw an error, will still
//! return a [`Result`] since they may throw a
//! [`LibraryError`](TreeSyncError::LibraryError).

use std::collections::BTreeMap;

use openmls_traits::OpenMlsCryptoProvider;
use serde::{Deserialize, Serialize};

use crate::{
    binary_tree::{MlsBinaryTree, MlsBinaryTreeError},
    ciphersuite::Ciphersuite,
    key_packages::{KeyPackage, KeyPackageBundle},
    messages::{PathSecret, PathSecretError},
    schedule::CommitSecret,
};

use self::{
    diff::{StagedTreeSyncDiff, TreeSyncDiff, TreeSyncDiffError},
    node::{leaf_node::LeafNode, Node, NodeError},
    treesync_node::{TreeSyncNode, TreeSyncNodeError},
};

pub(crate) mod diff;
mod hashes;
pub(crate) mod node;
pub(crate) mod treekem;
pub(crate) mod treesync_node;

pub use crate::binary_tree::LeafIndex;

#[cfg(any(feature = "test-utils", test))]
pub mod tests_and_kats;

/// The [`TreeSync`] struct holds an [`MlsBinaryTree`] instance, which contains
/// the state that is synced across the group, as well as the [`LeafIndex`]
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
pub struct TreeSync {
    tree: MlsBinaryTree<TreeSyncNode>,
    own_leaf_index: LeafIndex,
    tree_hash: Vec<u8>,
}

impl TreeSync {
    /// Create a new tree from a `KeyPackageBundle`.
    ///
    /// Returns the resulting [`TreeSync`] instance, as well as the
    /// corresponding [`CommitSecret`].
    pub(crate) fn new(
        backend: &impl OpenMlsCryptoProvider,
        key_package_bundle: KeyPackageBundle,
    ) -> Result<(Self, CommitSecret), TreeSyncError> {
        let key_package = key_package_bundle.key_package();
        // We generate our own leaf without a private key for now. The private
        // key is set in the `from_nodes` constructor below.
        let node: Node = Node::LeafNode(key_package.clone().into());
        let path_secret: PathSecret = key_package_bundle.leaf_secret().clone().into();
        let commit_secret: CommitSecret = path_secret
            .derive_path_secret(backend, key_package.ciphersuite())?
            .into();
        let node_options = vec![Some(node)];
        Ok((
            Self::from_nodes(
                backend,
                key_package.ciphersuite(),
                &node_options,
                key_package_bundle,
            )?,
            commit_secret,
        ))
    }

    /// Return the tree hash of the root node of the tree.
    pub(crate) fn tree_hash(&self) -> &[u8] {
        self.tree_hash.as_slice()
    }

    /// Merge the given diff into this `TreeSync` instance, refreshing the
    /// `tree_hash` value in the process.
    ///
    /// Returns an error if the merging process of the underlying
    /// [`MlsBinaryTree`] fails.
    pub(crate) fn merge_diff(
        &mut self,
        tree_sync_diff: StagedTreeSyncDiff,
    ) -> Result<(), TreeSyncError> {
        let (diff, new_tree_hash) = tree_sync_diff.into_parts();
        self.tree_hash = new_tree_hash;
        Ok(self.tree.merge_diff(diff)?)
    }

    /// Create an empty diff based on this [`TreeSync`] instance all operations
    /// are created based on an initial, empty [`TreeSyncDiff`].
    ///
    /// This function should not fail and only returns a [`Result`], because it
    /// might throw a [LibraryError](TreeSyncError::LibraryError).
    pub(crate) fn empty_diff(&self) -> Result<TreeSyncDiff, TreeSyncError> {
        Ok(self.try_into()?)
    }

    /// Create a new [`TreeSync`] instance from a given slice of `Option<Node>`,
    /// as well as a `LeafIndex` representing the source of the node slice and
    /// the `KeyPackageBundle` representing this client in the group. If a
    /// [`PathSecret`] is passed via `path_secret_option`, it will derive the
    /// private keys in the nodes of the direct path of the sender that it
    /// shares with this client.
    ///
    /// Returns the new [`TreeSync`] instance or an error if one of the
    /// invariants is not true (see [`TreeSync`]).
    pub(crate) fn from_nodes_with_secrets(
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        node_options: &[Option<Node>],
        sender_index: LeafIndex,
        path_secret_option: impl Into<Option<PathSecret>>,
        key_package_bundle: KeyPackageBundle,
    ) -> Result<(Self, Option<CommitSecret>), TreeSyncError> {
        let mut tree_sync =
            Self::from_nodes(backend, ciphersuite, node_options, key_package_bundle)?;

        // Populate the tree with secrets and derive a commit secret if a path
        // secret is given.
        let commit_secret = if let Some(path_secret) = path_secret_option.into() {
            let mut diff = tree_sync.empty_diff()?;
            let commit_secret =
                diff.set_path_secrets(backend, ciphersuite, path_secret, sender_index)?;
            let staged_diff = diff.into_staged_diff(backend, ciphersuite)?;
            tree_sync.merge_diff(staged_diff)?;
            Some(commit_secret)
        } else {
            None
        };
        Ok((tree_sync, commit_secret))
    }

    /// A helper function that generates a [`TreeSync`] instance from the given
    /// slice of nodes. It verifies that the [`KeyPackage`] of the given
    /// [`KeyPackageBundle`] is present in the tree and that the invariants
    /// documented in [`TreeSync`] hold.
    fn from_nodes(
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        node_options: &[Option<Node>],
        key_package_bundle: KeyPackageBundle,
    ) -> Result<Self, TreeSyncError> {
        // Before we can instantiate the TreeSync instance, we have to figure
        // out what our leaf index is.
        let mut ts_nodes: Vec<TreeSyncNode> = Vec::with_capacity(node_options.len());
        let mut own_index_option = None;
        let own_key_package = key_package_bundle.key_package;
        let mut private_key = Some(key_package_bundle.private_key);
        // Check if our own key package is in the tree.
        for (node_index, node_option) in node_options.iter().enumerate() {
            let ts_node_option: TreeSyncNode = match node_option {
                Some(node) => {
                    let mut node = node.clone();
                    if let Node::LeafNode(ref mut leaf_node) = node {
                        if leaf_node.public_key() == own_key_package.hpke_init_key() {
                            // Check if there's a duplicate
                            if let Some(private_key) = private_key.take() {
                                own_index_option = Some(
                                    u32::try_from(node_index / 2)
                                        .map_err(|_| TreeSyncError::LibraryError)?,
                                );
                                leaf_node.set_private_key(private_key)
                            } else {
                                return Err(TreeSyncError::DuplicateKeyPackage);
                            }
                        }
                    }
                    node.into()
                }
                None => TreeSyncNode::blank(),
            };
            ts_nodes.push(ts_node_option);
        }
        let tree = MlsBinaryTree::new(ts_nodes)?;
        if let Some(leaf_index) = own_index_option {
            let mut tree_sync = Self {
                tree,
                tree_hash: vec![],
                own_leaf_index: leaf_index,
            };
            // Verify all parent hashes.
            tree_sync.verify_parent_hashes(backend, ciphersuite)?;
            // Populate tree hash caches.
            tree_sync.populate_parent_hashes(backend, ciphersuite)?;
            Ok(tree_sync)
        } else {
            Err(TreeSyncError::MissingKeyPackage)
        }
    }

    /// Create a [`TreeSync`] instance from a vector of nodes without expecting
    /// there to be a [`KeyPackage`] that belongs to this particular MLS client.
    /// The `own_leaf_index` is set as follows: If there is a blank leaf in the
    /// tree, the `own_leaf_index` is set to that leaf index. If not, a new,
    /// blank leaf is added and the `own_leaf_index` is set to that leaf index.
    pub(crate) fn from_nodes_without_leaf(
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        node_options: &[Option<Node>],
        key_package_bundle: &KeyPackageBundle,
    ) -> Result<Self, TreeSyncError> {
        let mut ts_nodes: Vec<TreeSyncNode> = Vec::with_capacity(node_options.len());
        let mut own_index_option = None;
        // Check if our own key package is in the tree.
        for (node_index, node_option) in node_options.iter().enumerate() {
            // Check if we're looking at a blank leaf and if we've already found
            // one before.
            let ts_node_option =
                if node_option.is_none() && node_index % 2 == 0 && own_index_option.is_none() {
                    own_index_option = Some(
                        u32::try_from(node_index / 2).map_err(|_| TreeSyncError::LibraryError)?,
                    );
                    let own_leaf_node: LeafNode = key_package_bundle.clone().into();
                    Some(Node::LeafNode(own_leaf_node)).into()
                } else {
                    node_option.clone().into()
                };
            ts_nodes.push(ts_node_option);
        }
        // If there was no blank leaf, we'll create a new one.
        if own_index_option.is_none() {
            ts_nodes.push(TreeSyncNode::blank());
            let own_leaf_node: LeafNode = key_package_bundle.clone().into();
            ts_nodes.push(Some(Node::LeafNode(own_leaf_node)).into());
            own_index_option = Some(
                u32::try_from((ts_nodes.len() - 1) / 2).map_err(|_| TreeSyncError::LibraryError)?,
            );
        }
        let tree = MlsBinaryTree::new(ts_nodes)?;
        if let Some(leaf_index) = own_index_option {
            let mut tree_sync = Self {
                tree,
                tree_hash: vec![],
                own_leaf_index: leaf_index,
            };
            // Verify all parent hashes.
            tree_sync.verify_parent_hashes(backend, ciphersuite)?;
            // Populate tree hash caches.
            tree_sync.populate_parent_hashes(backend, ciphersuite)?;
            Ok(tree_sync)
        } else {
            Err(TreeSyncError::LibraryError)
        }
    }

    /// Populate the parent hash caches of all nodes in the tree.
    fn populate_parent_hashes(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
    ) -> Result<(), TreeSyncError> {
        let diff = self.empty_diff()?;
        // Make the diff into a staged diff. This implicitly computes the
        // tree hashes and poulates the tree hash caches.
        let staged_diff = diff.into_staged_diff(backend, ciphersuite)?;
        // Merge the diff.
        self.merge_diff(staged_diff)
    }

    /// Verify the parent hashes of all parent nodes in the tree.
    ///
    /// Returns an error if one of the parent nodes in the tree has an invalid
    /// parent hash.
    fn verify_parent_hashes(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
    ) -> Result<(), TreeSyncError> {
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
        let diff = self.empty_diff()?;
        // No need to merge the diff, since we didn't actually modify any state.
        Ok(diff.verify_parent_hashes(backend, ciphersuite)?)
    }

    /// Returns the number of leaves in the tree.
    ///
    /// This function should not fail and only returns a [`Result`], because it
    /// might throw a [LibraryError](TreeSyncError::LibraryError).
    pub(crate) fn leaf_count(&self) -> Result<LeafIndex, TreeSyncError> {
        Ok(self.tree.leaf_count()?)
    }

    /// Returns a [`BTreeMap`] mapping leaf indices to the corresponding
    /// [`KeyPackage`] instances in the leaves. The map only contains full
    /// nodes.
    ///
    /// This function should not fail and only returns a [`Result`], because it
    /// might throw a [LibraryError](TreeSyncError::LibraryError).
    pub(crate) fn full_leaves(&self) -> Result<BTreeMap<LeafIndex, &KeyPackage>, TreeSyncError> {
        let tsn_leaves: Vec<(usize, &TreeSyncNode)> = self
            .tree
            .leaves()?
            .drain(..)
            .enumerate()
            .filter(|(_, tsn)| tsn.node().is_some())
            .collect();
        let mut leaves = BTreeMap::new();
        for (index, tsn_leaf) in tsn_leaves {
            let index = u32::try_from(index).map_err(|_| TreeSyncError::LibraryError)?;
            if let Some(ref node) = tsn_leaf.node() {
                let leaf = node.as_leaf_node()?;
                leaves.insert(index, leaf.key_package());
            }
        }
        Ok(leaves)
    }

    /// Returns the nodes in the tree ordered according to the
    /// array-representation of the underlying binary tree.
    pub fn export_nodes(&self) -> Vec<Option<Node>> {
        self.tree
            .nodes()
            .iter()
            .map(|ts_node| ts_node.node_without_private_key())
            .collect()
    }

    /// Returns the leaf index of this client.
    pub(crate) fn own_leaf_index(&self) -> LeafIndex {
        self.own_leaf_index
    }

    /// Returns the [`LeafNode`] of this client.
    ///
    /// This function should not fail and only returns a [`Result`], because it
    /// might throw a [LibraryError](TreeSyncError::LibraryError).
    pub(crate) fn own_leaf_node(&self) -> Result<&LeafNode, TreeSyncError> {
        // Our own leaf should be inside of the tree and never blank.
        self.leaf(self.own_leaf_index)?
            .ok_or(TreeSyncError::LibraryError)
    }

    /// Return a reference to the leaf at the given `LeafIndex` or `None` if the
    /// leaf is blank.
    ///
    /// Returns an error if the leaf is outside of the tree.
    pub(crate) fn leaf(&self, leaf_index: LeafIndex) -> Result<Option<&LeafNode>, TreeSyncError> {
        let tsn = self.tree.leaf(leaf_index)?;
        Ok(match tsn.node() {
            Some(node) => Some(node.as_leaf_node()?),
            None => None,
        })
    }
}

implement_error! {
    pub enum TreeSyncError {
        Simple {
            LibraryError = "An inconsistency in the internal state of the tree was detected.",
            MissingKeyPackage = "Couldn't find our own key package in this tree.",
            DuplicateKeyPackage = "Found two KeyPackages with the same public key.",
            OutOfBounds = "The given `LeafIndex` is outside of the tree.",
        }
        Complex {
            BinaryTreeError(MlsBinaryTreeError) = "An error occurred during an operation on the underlying binary tree.",
            TreeSyncNodeError(TreeSyncNodeError) = "An error occurred during an operation on the underlying binary tree.",
            NodeTypeError(NodeError) = "We found a node with an unexpected type.",
            TreeSyncDiffError(TreeSyncDiffError) = "An error while trying to apply a diff.",
            DerivationError(PathSecretError) = "Error while deriving commit secret for new tree.",
        }
    }
}
