//! This module contains the functionality required to synchronize a tree across
//! multiple parties.

use openmls_traits::OpenMlsCryptoProvider;

use crate::binary_tree::{Addressable, MlsBinaryTree, MlsBinaryTreeError};

use self::{diff::TreeSyncDiff, node::TreeSyncNode};

mod diff;
mod node;

pub(crate) struct TreeSync {
    tree: MlsBinaryTree<Option<TreeSyncNode>>,
    tree_hash: Vec<u8>,
}

impl Addressable for Option<TreeSyncNode> {
    type Address = Vec<u8>;

    fn address(&self) -> Option<Self::Address> {
        self.map(|node| node.address()).flatten()
    }
}

impl TreeSync {
    /// Return the tree hash of the root node.
    pub(crate) fn tree_hash(&self) -> &[u8] {
        self.tree_hash.as_slice()
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
