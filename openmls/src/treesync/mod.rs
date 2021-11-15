//! This module contains the functionality required to synchronize a tree across
//! multiple parties.

use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    binary_tree::{LeafIndex, MlsBinaryTree, MlsBinaryTreeError},
    ciphersuite::Ciphersuite,
    messages::PathSecret,
    prelude::{KeyPackage, KeyPackageBundle},
};

use self::{
    diff::{StagedTreeSyncDiff, TreeSyncDiff, TreeSyncDiffError},
    node::{Node, TreeSyncNode, TreeSyncNodeError},
};

mod diff;
mod hashes;
mod mls_node;
mod node;
pub(crate) mod treekem;

pub(crate) struct TreeSync {
    tree: MlsBinaryTree<TreeSyncNode>,
    own_leaf_index: LeafIndex,
    tree_hash: Vec<u8>,
}

impl TreeSync {
    /// Return the tree hash of the root node.
    pub(crate) fn tree_hash(&self) -> &[u8] {
        self.tree_hash.as_slice()
    }

    /// Merge the given diff into the `TreeSync` instance, refreshing the
    /// `tree_has` value in the process. FIXME: Right now, we are storing no
    /// private values in the diff. Shoud we decide to do so in the future, we'd
    /// need to merge them here as well.
    pub(crate) fn merge_diff(
        &mut self,
        tree_sync_diff: StagedTreeSyncDiff,
    ) -> Result<(), TreeSyncError> {
        let (diff, new_tree_hash) = tree_sync_diff.into_parts();
        self.tree_hash = new_tree_hash;
        Ok(self.tree.merge_diff(diff)?)
    }

    /// Create an empty diff based on this TreeSync instance all operations
    /// are created based on an initial, empty diff.
    pub(crate) fn empty_diff(&self) -> TreeSyncDiff {
        self.into()
    }

    /// For use with a Welcome message.
    pub(crate) fn from_nodes_with_secrets(
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        node_options: &[Option<Node>],
        sender_index: LeafIndex,
        path_secret_option: Option<PathSecret>,
        key_package_bundle: KeyPackageBundle,
    ) -> Result<Self, TreeSyncError> {
        let mut tree_sync =
            Self::from_nodes(backend, ciphersuite, node_options, key_package_bundle)?;

        // If there is no path secret, the direct path has to be blank. FIXME:
        // Return error if a given path secret doesn't imply that the direct
        // path isn't blank.
        if let Some(path_secret) = path_secret_option {
            let mut diff = tree_sync.empty_diff();
            diff.set_path_secrets(backend, ciphersuite, path_secret, sender_index)?;
            let staged_diff = diff.to_staged_diff(backend, ciphersuite)?;
            tree_sync.merge_diff(staged_diff)?;
        }
        Ok(tree_sync)
    }

    /// FIXME: When implementing external commits, we will probably have to
    /// enable a state, where we have a tree without secrets.
    pub(crate) fn from_nodes(
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        node_options: &[Option<Node>],
        key_package_bundle: KeyPackageBundle,
    ) -> Result<Self, TreeSyncError> {
        // FIXME: We might want to verify some more things here, such as the
        // validity of the leaf indices in the unmerged leaves or the uniqueness
        // of public keys in the tree. We are building on those properties in
        // other functions.
        let mut ts_nodes: Vec<TreeSyncNode> = Vec::new();
        let mut own_index_option = None;
        let own_key_package = key_package_bundle.key_package;
        let mut private_key = Some(key_package_bundle.private_key);
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
        // Check if our own key package is in the tree.
        if let Some(leaf_index) = own_index_option {
            let mut tree_sync = Self {
                tree,
                tree_hash: vec![],
                own_leaf_index: leaf_index,
            };
            let diff = tree_sync.empty_diff();
            // Verify all parent hashes.
            diff.verify_parent_hashes(backend, ciphersuite)?;
            // Make the diff into a staged diff.
            let staged_diff = diff.to_staged_diff(backend, ciphersuite)?;
            // Merge the diff.
            tree_sync.merge_diff(staged_diff)?;
            Ok(tree_sync)
        } else {
            return Err(TreeSyncError::MissingKeyPackage);
        }
    }

    pub(crate) fn leaves(&self) -> Result<Vec<(LeafIndex, &KeyPackage)>, TreeSyncError> {
        let tsn_leaves: Vec<(usize, &TreeSyncNode)> = self
            .tree
            .leaves()?
            .drain(..)
            .enumerate()
            .filter(|(_, tsn)| tsn.node().is_some())
            .collect();
        let mut leaves = Vec::new();
        for (index, tsn_leaf) in tsn_leaves {
            let index = u32::try_from(index).map_err(|_| TreeSyncError::LibraryError)?;
            if let Some(ref node) = tsn_leaf.node() {
                let leaf = node.as_leaf_node()?;
                leaves.push((index, leaf.key_package()))
            }
        }
        Ok(leaves)
    }
}

implement_error! {
    pub enum TreeSyncError {
        Simple {
            LibraryError = "An inconsistency in the internal state of the tree was detected.",
            MissingKeyPackage = "Couldn't find our own key package in this tree.",
            DuplicateKeyPackage = "Found two KeyPackages with the same public key.",
        }
        Complex {
            BinaryTreeError(MlsBinaryTreeError) = "An error occurred during an operation on the underlying binary tree.",
            TreeSyncNodeError(TreeSyncNodeError) = "An error occurred during an operation on the underlying binary tree.",
            TreeSyncDiffError(TreeSyncDiffError) = "An error while trying to apply a diff.",
        }
    }
}
