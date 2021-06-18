use std::collections::HashMap;

use crate::binary_tree::{FLBBinaryTree, NodeIndex};

use self::{
    treesync_update::{TreeSyncUpdate, UnsignedTreeSyncUpdate},
    treesyncable::{TreeSyncLeaf, TreeSyncParent},
};

pub(crate) mod mls_node;
pub(crate) mod treesync_update;
pub(crate) mod treesyncable;

pub(crate) enum TreeSyncNode<P, L> {
    Parent(P),
    Leaf(L),
}

struct TreeSync<
    P, // Parent Node
    L, // (Verified) Leaf (lives in the tree)
       //LP, // Leaf Payload (unsigned)
       //SL, // Signed Leaf
> where
    P: TreeSyncParent,
    L: TreeSyncLeaf,
{
    tree: dyn FLBBinaryTree<Option<TreeSyncNode<P, L>>>,
}

impl<P, L> TreeSync<P, L>
where
    P: TreeSyncParent,
    L: TreeSyncLeaf,
{
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
    fn merge_diff(&mut self, tree_sync_diff: TreeSyncDiff<P, L>) -> Result<(), TreeSyncError> {
        todo!()
    }

    /// Create an empty diff based on this TreeSync instance all operations
    /// are created based on an initial, empty diff.
    fn empty_diff(&self) -> TreeSyncDiff<P, L> {
        todo!()
    }
}

struct TreeSyncDiff<
    P, // Parent Node
    L, // (Verified) Leaf (lives in the tree)
> where
    P: TreeSyncParent,
    L: TreeSyncLeaf,
{
    nodes: HashMap<NodeIndex, Option<TreeSyncNode<P::TreeSyncParentMut, L::UnsignedLeaf>>>,
}

impl<P: TreeSyncParent, L: TreeSyncLeaf> TreeSyncDiff<P, L> {
    /// Update a leaf node and blank the nodes in the updated leaf's direct path.
    fn update_leaf(&mut self, leaf_node: L, leaf_index: NodeIndex) -> Self {
        todo!()
    }

    /// Adds a new leaf to the tree either by filling a blank leaf or by
    /// creating a new leaf, inserting intermediate blanks as necessary. This
    /// also adds the leaf_index of the new leaf to the `unmerged_leaves` state
    /// of the parent nodes in its direct path.
    fn add_leaf(&mut self, leaf_node: L) -> Result<Self, TreeSyncError> {
        todo!()
    }

    /// Remove a group member by blanking the target leaf and its direct path.
    fn remove_leaf(&mut self, leaf_index: NodeIndex) -> Result<Self, TreeSyncError> {
        todo!()
    }

    /// Process a given update path, consisting of a vector of `Node`. This
    /// function
    /// * replaces the nodes in the direct path of the given `leaf_node` with
    ///   the the ones in `path` and
    /// * computes the `parent_hash` of all nodes in the path and compares it to
    ///   the one in the `leaf_node`.
    fn process_update_path(&mut self, update: TreeSyncUpdate<P, L>) -> Self {
        todo!()
    }

    /// Take a given path and leaf node and integrate them into the tree. This
    /// function
    /// * computes the `tree_hash` and sets it in all nodes
    /// * computes the `parent_hash` and sets it in all nodes
    /// * (re-)signs the leaf node (after setting the parent hash)
    /// * and returns a `TreeSyncUpdate`.
    fn create_update_path(
        &mut self,
        update: UnsignedTreeSyncUpdate<P, L>,
    ) -> Result<(Self, TreeSyncUpdate<P, L>), TreeSyncError> {
        todo!()
    }

    /// Compute the tree hash of the TreeSync instance we would get when merging
    /// the diff.
    fn tree_hash(&self) -> Vec<u8> {
        todo!()
    }
}

trait TreeSyncKeyStore {
    type SignatureKeyHandle;

    fn credential_bundle(&self, handle: Self::SignatureKeyHandle);
}

implement_error! {
    pub enum TreeSyncError {
        NodeVerificationError = "Could not verify this node.",
        NodeTypeError = "The given node is of the wrong type.",
    }
}
