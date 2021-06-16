use std::collections::HashMap;

use crate::binary_tree::{FLBBinaryTree, NodeIndex};

use self::treesyncnode::TreeSyncNode;

pub(crate) mod mls_node;
pub(crate) mod treesyncnode;

struct TreeSync<T: TreeSyncNode> {
    tree: dyn FLBBinaryTree<Option<T>>,
}

impl<T: TreeSyncNode> TreeSync<T> {
    /// Return the tree hash of the root node.
    fn tree_hash(&self) -> Vec<u8> {
        todo!()
    }

    /// Verify the parent hash of every parent node in the tree.
    fn verify_parent_hashes(&self) -> Result<(), TreeSyncError> {
        todo!()
    }

    /// Merge the given diff into the `TreeSync` instance. This operation
    /// re-computes all necessary tree hashes.
    /// Note, that the private values corresponding to the ones in the
    /// TreeSync should be committed at the same time.
    fn merge_diff(&mut self, tree_sync_diff: TreeSyncDiff<T>) -> Result<(), TreeSyncError> {
        todo!()
    }

    /// Create an empty diff based on this TreeSync instance all operations
    /// are created based on an initial, empty diff.
    fn empty_diff(&self) -> TreeSyncDiff<T> {
        todo!()
    }
}

struct TreeSyncDiff<T: TreeSyncNode> {
    nodes: HashMap<NodeIndex, Option<T>>,
}

impl<T: TreeSyncNode> TreeSyncDiff<T> {
    /// Update a leaf node and blank the nodes in the updated leaf's direct path.
    fn update_leaf(&mut self, leaf_node: T, leaf_index: NodeIndex) -> TreeSyncDiff<T> {
        todo!()
    }

    /// Adds a new leaf to the tree either by filling a blank leaf or by creating a new leaf,
    /// inserting intermediate blanks as necessary. This also adds the leaf_index of the new
    /// leaf to the `unmerged_leaves` state of the parent nodes in its direct path.
    fn add_leaf(&mut self, leaf_node: T) -> Result<TreeSyncDiff<T>, TreeSyncError> {
        todo!()
    }

    /// Remove a group member by blanking the target leaf and its direct path.
    fn remove_leaf(&mut self, leaf_index: NodeIndex) -> Result<TreeSyncDiff<T>, TreeSyncError> {
        todo!()
    }

    /// Process a given update path, consisting of a vector of `Node`. This
    /// function
    /// * replaces the nodes in the direct path of the given `leaf_node` with the
    ///   the ones in `path` and
    /// * computes the `parent_hash` of all nodes in the path and compares it to the one in
    ///   the `leaf_node`.
    fn update_path(&mut self, leaf_node: T, path: Vec<Box<T>>) -> TreeSyncDiff<T> {
        todo!()
    }

    /// Compute the tree hash of the TreeSync instance we would get when merging the diff.
    fn tree_hash(&self) -> Vec<u8> {
        todo!()
    }
}

implement_error! {
    pub enum TreeSyncError {
        NodeVerificationError = "Could not verify this node.",
        NodeTypeError = "The given node is of the wrong type.",
    }
}
