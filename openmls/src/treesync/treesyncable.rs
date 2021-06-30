use crate::{
    binary_tree::NodeIndex,
    ciphersuite::signable::{Signable, SignedStruct, Verifiable, VerifiedStruct},
};

pub(crate) trait TreeSyncNode {
    /// Get the tree hash value for the given node.
    fn tree_hash(&self) -> &[u8];

    /// Get the contents of the node.
    fn node_content(&self) -> Option<&dyn TreeSyncable>;

    /// Set the tree hash value for the given node.
    /// This assuming that the node caches the tree hash.
    fn set_tree_hash(&mut self, tree_hash: Vec<u8>);
}

pub(crate) trait TreeSyncable {
    /// Return the value of the node relevant for the parent hash and tree hash.
    /// In case of MLS, this would be the node's HPKEPublicKey. TreeSync
    /// can then gather everything necessary to build the `ParentHashInput`,
    /// `LeafNodeHashInput` and `ParentNodeTreeHashInput` structs for a given node.
    fn node_content(&self) -> &[u8];

    /// Get the parent hash value of this node.
    fn parent_hash(&self) -> &[u8];
}

pub(crate) trait TreeSyncableMut {
    /// Set the parent hash value of this node.
    fn set_parent_hash(&mut self, parent_hash: Vec<u8>);
}

pub(crate) trait TreeSyncParent: TreeSyncable {
    type TreeSyncParentMut: TreeSyncParentMut;

    /// Get the list of unmerged leaves.
    fn unmerged_leaves(&self) -> &[NodeIndex];

    /// Create a mutable copy of the TreeSyncable.
    fn to_mut(self) -> Self::TreeSyncParentMut;

    /// Create a mutable copy of the TreeSyncable.
    fn to_immut(tsp_mut: Self::TreeSyncParentMut) -> Self;
}

pub(crate) trait TreeSyncParentMut: TreeSyncableMut {
    /// Clear the list of unmerged leaves.
    fn clear_unmerged_leaves(&mut self);

    /// Add a `NodeIndex` to the node's list of unmerged leaves.
    fn add_unmerged_leaf(&mut self, node_index: NodeIndex);
}

pub(crate) trait TreeSyncLeaf: VerifiedStruct<Self::UnverifiedLeaf> + TreeSyncable {
    type UnverifiedLeaf: Verifiable;
    type UnsignedLeaf: Signable + TreeSyncableMut;
    type SignedLeaf: SignedStruct<Self::UnsignedLeaf>;
}
