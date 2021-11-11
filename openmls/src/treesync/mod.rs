//! This module contains the functionality required to synchronize a tree across
//! multiple parties.

use std::convert::{TryFrom, TryInto};

use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    binary_tree::{Addressable, LeafIndex, MlsBinaryTree, MlsBinaryTreeError},
    ciphersuite::{Ciphersuite, HpkePublicKey},
};

use self::{
    diff::TreeSyncDiff,
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

    fn compute_tree_hash(&mut self) -> Result<(), TreeSyncError> {
        todo!()
    }

    /// Verify the parent hash of every parent node in the tree. FIXME: Do this
    /// when importing a tree from a vector of nodes.
    fn verify_parent_hashes(
        &self,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<(), TreeSyncError> {
        todo!()
    }

    /// Merge the given diff into the `TreeSync` instance. This operation
    /// re-computes all necessary tree hashes.
    /// Note, that the private values corresponding to the ones in the
    /// TreeSync should be committed at the same time.
    fn merge_diff(&mut self, tree_sync_diff: TreeSyncDiff) -> Result<(), TreeSyncError> {
        todo!()
    }

    /// Create an empty diff based on this TreeSync instance all operations
    /// are created based on an initial, empty diff.
    fn empty_diff(&self) -> TreeSyncDiff {
        todo!()
    }

    fn from_nodes(
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        node_options: &[Option<MlsNode>],
    ) -> Result<Self, TreeSyncError> {
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
        let cth = |node: &mut TreeSyncNode,
                   leaf_index_option: Option<LeafIndex>,
                   left_hash_result: Result<Vec<u8>, TreeSyncNodeError>,
                   right_hash_result: Result<Vec<u8>, TreeSyncNodeError>|
         -> Result<Vec<u8>, TreeSyncNodeError> {
            node.compute_tree_hash(
                backend,
                ciphersuite,
                leaf_index_option,
                left_hash_result,
                right_hash_result,
            )
        };
        let tree_hash = tree_sync.tree.fold_tree(cth);
        // TODO: Verify Parent Hash
        todo!()
    }
}

implement_error! {
    pub enum TreeSyncError {
        Simple {
            LibraryError = "An inconsistency in the internal state of the tree was detected.",
        }
        Complex {
            BinaryTreeError(MlsBinaryTreeError) = "An error occurred during an operation on the underlying binary tree.",
        }
    }
}
