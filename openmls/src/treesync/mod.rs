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
    types::{Ciphersuite, CryptoError},
    OpenMlsCryptoProvider,
};
use serde::{Deserialize, Serialize};

use crate::{
    binary_tree::{
        array_representation::{is_node_in_tree, tree::TreeNode, LeafNodeIndex},
        MlsBinaryTree, MlsBinaryTreeError,
    },
    ciphersuite::Secret,
    credentials::CredentialBundle,
    error::LibraryError,
    extensions::Extension,
    framing::SenderError,
    group::Member,
    key_packages::KeyPackageBundle,
    messages::{PathSecret, PathSecretError},
    schedule::CommitSecret,
};

use self::{
    diff::{StagedTreeSyncDiff, TreeSyncDiff},
    node::leaf_node::{Capabilities, LeafNodeSource, Lifetime, OpenMlsLeafNode},
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
    own_leaf_index: LeafNodeIndex,
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
        credential_bundle: &CredentialBundle,
        life_time: Lifetime,
        capabilities: Capabilities,
        extensions: Vec<Extension>,
    ) -> Result<(Self, CommitSecret), LibraryError> {
        let key_package = key_package_bundle.key_package();
        // We generate our own leaf without a private key for now. The private
        // key is set in the `from_nodes` constructor below.
        let mut leaf = OpenMlsLeafNode::new(
            key_package_bundle.key_package().hpke_init_key().clone(),
            credential_bundle.credential().signature_key().clone(),
            credential_bundle.credential().clone(),
            // Creation of a group is considered to be from a key package.
            LeafNodeSource::KeyPackage(life_time),
            backend,
            credential_bundle,
        )?;
        leaf.set_leaf_index(LeafNodeIndex::new(0));
        leaf.add_capabilities(capabilities);
        extensions
            .into_iter()
            .for_each(|extension| leaf.add_extensions(extension));

        let node = Node::LeafNode(leaf);
        let path_secret: PathSecret = Secret::random(key_package.ciphersuite(), backend, None)
            .map_err(LibraryError::unexpected_crypto_error)?
            .into();
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
            )
            .map_err(|_| LibraryError::custom("Malformed empty tree"))?,
            commit_secret,
        ))
    }

    /// Return the tree hash of the root node of the tree.
    pub(crate) fn tree_hash(&self) -> &[u8] {
        self.tree_hash.as_slice()
    }

    /// Merge the given diff into this `TreeSync` instance, refreshing the
    /// `tree_hash` value in the process.
    pub(crate) fn merge_diff(&mut self, tree_sync_diff: StagedTreeSyncDiff) {
        let (own_leaf_index, diff, new_tree_hash) = tree_sync_diff.into_parts();
        self.own_leaf_index = own_leaf_index;
        self.tree_hash = new_tree_hash;
        self.tree.merge_diff(diff);
    }

    /// Create an empty diff based on this [`TreeSync`] instance all operations
    /// are created based on an initial, empty [`TreeSyncDiff`].
    pub(crate) fn empty_diff(&self) -> TreeSyncDiff {
        self.into()
    }

    /// Create a new [`TreeSync`] instance from a given slice of `Option<Node>`,
    /// as well as a `LeafNodeIndex` representing the source of the node slice and
    /// the `KeyPackageBundle` representing this client in the group. If a
    /// [`PathSecret`] is passed via `path_secret_option`, it will derive the
    /// private keys in the nodes of the direct path of the sender that it
    /// shares with this client.
    ///
    /// Returns the new [`TreeSync`] instance or an error if one of the
    /// invariants is not true (see [`TreeSync`]).
    ///
    /// Returns TreeSyncFromNodesError::LibraryError if the input parameters are
    /// malformed.
    pub(crate) fn from_nodes_with_secrets(
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        node_options: &[Option<Node>],
        sender_index: LeafNodeIndex,
        path_secret_option: impl Into<Option<PathSecret>>,
        key_package_bundle: KeyPackageBundle,
    ) -> Result<(Self, Option<CommitSecret>), TreeSyncFromNodesError> {
        let mut tree_sync =
            Self::from_nodes(backend, ciphersuite, node_options, key_package_bundle)?;

        // Populate the tree with secrets and derive a commit secret if a path
        // secret is given.
        let commit_secret = if let Some(path_secret) = path_secret_option.into() {
            let mut diff = tree_sync.empty_diff();
            let commit_secret = diff
                .set_path_secrets(backend, ciphersuite, path_secret, sender_index)
                .map_err(|e| match e {
                    TreeSyncSetPathError::LibraryError(e) => e.into(),
                    TreeSyncSetPathError::PublicKeyMismatch => {
                        TreeSyncFromNodesError::from(PublicTreeError::PublicKeyMismatch)
                    }
                })?;
            let staged_diff = diff.into_staged_diff(backend, ciphersuite)?;
            tree_sync.merge_diff(staged_diff);
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
        ciphersuite: Ciphersuite,
        node_options: &[Option<Node>],
        key_package_bundle: KeyPackageBundle,
    ) -> Result<Self, TreeSyncFromNodesError> {
        // TODO #800: Unmerged leaves should be checked
        // Before we can instantiate the TreeSync instance, we have to figure
        // out what our leaf index is.
        let mut ts_nodes: Vec<TreeNode<TreeSyncLeafNode, TreeSyncParentNode>> =
            Vec::with_capacity(node_options.len());
        let mut own_index_option = None;
        let own_key_package = key_package_bundle.key_package;
        let mut private_key = Some(key_package_bundle.private_key);
        // Check if our own key package is in the tree.
        for (node_index, node_option) in node_options.iter().enumerate() {
            let ts_node_option: TreeNode<TreeSyncLeafNode, TreeSyncParentNode> = match node_option {
                Some(node) => {
                    let mut node = node.clone();
                    if let Node::LeafNode(ref mut leaf_node) = node {
                        let leaf_index = LeafNodeIndex::new((node_index / 2) as u32);
                        if leaf_node.public_key() == own_key_package.hpke_init_key() {
                            // Check if there's a duplicate
                            if let Some(private_key) = private_key.take() {
                                own_index_option = Some(leaf_index);
                                leaf_node.set_private_key(private_key);
                            } else {
                                return Err(PublicTreeError::DuplicateKeyPackage.into());
                            }
                        }
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
        if let Some(leaf_index) = own_index_option {
            let mut tree_sync = Self {
                tree,
                tree_hash: vec![],
                own_leaf_index: leaf_index,
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
        } else {
            Err(PublicTreeError::MissingKeyPackage.into())
        }
    }

    /// Create a [`TreeSync`] instance from a vector of nodes without expecting
    /// there to be a [`KeyPackage`] that belongs to this particular MLS client.
    /// WARNING: Some of the [`TreeSync`] invariants will not hold for this
    /// tree, as the `own_leaf_index` does not point to a leaf with private key
    /// material in it.
    pub(crate) fn from_nodes_without_leaf(
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        nodes: Vec<Option<Node>>,
    ) -> Result<Self, TreeSyncFromNodesError> {
        let mut tree_nodes: Vec<TreeNode<TreeSyncLeafNode, TreeSyncParentNode>> = Vec::new();
        for (index, node_option) in nodes.into_iter().enumerate() {
            let node = match node_option {
                Some(node) => match node {
                    Node::LeafNode(leaf) => TreeNode::Leaf(TreeSyncLeafNode::from(leaf)),
                    Node::ParentNode(parent) => TreeNode::Parent(TreeSyncParentNode::from(parent)),
                },
                None => {
                    if index % 2 == 0 {
                        TreeNode::Leaf(TreeSyncLeafNode::blank())
                    } else {
                        TreeNode::Parent(TreeSyncParentNode::blank())
                    }
                }
            };
            tree_nodes.push(node);
        }

        let tree = MlsBinaryTree::new(tree_nodes).map_err(|_| PublicTreeError::MalformedTree)?;
        let mut tree_sync = Self {
            tree,
            tree_hash: vec![],
            own_leaf_index: LeafNodeIndex::new(0),
        };
        // Verify all parent hashes.
        tree_sync
            .verify_parent_hashes(backend, ciphersuite)
            .map_err(|_| PublicTreeError::InvalidParentHash)?;
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
                    leaf_node
                        .leaf_node
                        .credential()
                        .signature_key()
                        .as_slice()
                        .to_vec(),
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
        self.tree
            .export_nodes()
            .iter()
            // Filter out private keys
            .map(|node| match node {
                TreeNode::Leaf(leaf) => leaf.node_without_private_key().map(Node::LeafNode),
                TreeNode::Parent(parent) => parent.node_without_private_key().map(Node::ParentNode),
            })
            .collect()
    }

    /// Returns the leaf index of this client.
    pub(crate) fn own_leaf_index(&self) -> LeafNodeIndex {
        self.own_leaf_index
    }

    /// Returns the [`LeafNode`] of this client.
    ///
    /// This function should not fail and only returns a [`Result`], because it
    /// might throw a [LibraryError](TreeSyncError::LibraryError).
    pub(crate) fn own_leaf_node(&self) -> Option<&OpenMlsLeafNode> {
        // Our own leaf should be inside of the tree and never blank.
        self.leaf(self.own_leaf_index)
    }

    /// Return a reference to the leaf at the given `LeafNodeIndex` or `None` if the
    /// leaf is blank.
    ///
    /// Returns an error if the leaf is outside of the tree.
    pub(crate) fn leaf(&self, leaf_index: LeafNodeIndex) -> Option<&OpenMlsLeafNode> {
        let tsn = self.tree.leaf(leaf_index);
        tsn.node().as_ref()
    }

    /// Returns a [`TreeSyncError`] if the `leaf_index` is not a leaf in this
    /// tree or empty.
    pub(crate) fn is_leaf_in_tree(&self, leaf_index: LeafNodeIndex) -> bool {
        is_node_in_tree(leaf_index.into(), self.tree.size())
    }
}
