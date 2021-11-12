//! This module contains the functionality required to synchronize a tree across
//! multiple parties.

use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    binary_tree::{MlsBinaryTree, MlsBinaryTreeError},
    ciphersuite::Ciphersuite,
};

use self::{
    diff::{StagedTreeSyncDiff, TreeSyncDiff, TreeSyncDiffError},
    mls_node::MlsNode,
    node::{Node, TreeSyncNode, TreeSyncNodeError},
};

mod diff;
mod hashes;
mod mls_node;
mod node;

pub(crate) struct TreeSync {
    tree: MlsBinaryTree<TreeSyncNode>,
    tree_hash: Vec<u8>,
}

impl TreeSync {
    /// Return the tree hash of the root node.
    pub(crate) fn tree_hash(&self) -> &[u8] {
        self.tree_hash.as_slice()
    }

    /// Merge the given diff into the `TreeSync` instance. This operation
    /// re-computes all necessary tree hashes.
    /// Note, that the private values corresponding to the ones in the
    /// TreeSync should be committed at the same time.
    pub(crate) fn merge_diff(
        &mut self,
        tree_sync_diff: StagedTreeSyncDiff,
    ) -> Result<(), TreeSyncError> {
        // TODO: Implement.
        todo!()
    }

    /// Create an empty diff based on this TreeSync instance all operations
    /// are created based on an initial, empty diff.
    pub(crate) fn empty_diff(&self) -> TreeSyncDiff {
        self.into()
    }

    pub(crate) fn from_nodes(
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        node_options: &[Option<MlsNode>],
    ) -> Result<Self, TreeSyncError> {
        // FIXME: We might want to verify some more things here, such as the
        // validity of the leaf indices in the unmerged leaves or the uniqueness
        // of public keys in the tree. We are building on those properties in
        // other functions.
        let mut ts_nodes: Vec<TreeSyncNode> = Vec::new();
        for node_option in node_options {
            let ts_node_option: TreeSyncNode = match node_option {
                Some(mls_node) => {
                    let node: Node = mls_node.into();
                    node.into()
                }
                None => TreeSyncNode::blank(),
            };
            ts_nodes.push(ts_node_option);
        }
        let tree = MlsBinaryTree::new(ts_nodes)?;
        let mut tree_sync = Self {
            tree,
            tree_hash: vec![],
        };
        let diff = tree_sync.empty_diff();
        // Verify all parent hashes.
        diff.verify_parent_hashes(backend, ciphersuite)?;
        // Make the diff into a staged diff.
        let staged_diff = diff.to_staged_diff(backend, ciphersuite)?;
        // Merge the diff.
        tree_sync.merge_diff(staged_diff)?;
        Ok(tree_sync)
    }
}

implement_error! {
    pub enum TreeSyncError {
        Simple {
            LibraryError = "An inconsistency in the internal state of the tree was detected.",
        }
        Complex {
            BinaryTreeError(MlsBinaryTreeError) = "An error occurred during an operation on the underlying binary tree.",
            TreeSyncNodeError(TreeSyncNodeError) = "An error occurred during an operation on the underlying binary tree.",
            TreeSyncDiffError(TreeSyncDiffError) = "An error while trying to apply a diff.",
        }
    }
}
