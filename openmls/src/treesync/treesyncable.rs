use crate::{
    binary_tree::NodeIndex,
    ciphersuite::signable::{Signable, SignedStruct, Verifiable, VerifiedStruct},
};

pub(crate) trait TreeSyncable: Sized {
    type TreeSyncableError;
    type TreeSyncableMut: TreeSyncableMut<Self::TreeSyncableError>;

    /// Return the value of the node relevant for the parent hash and tree hash.
    /// In case of MLS, this would be the node's HPKEPublicKey. TreeSync
    /// can then gather everything necessary to build the `ParentHashInput`,
    /// `LeafNodeHashInput` and `ParentNodeTreeHashInput` structs for a given node.
    fn node_content(&self) -> &[u8];

    /// Get the list of unmerged leaves. Returns a `NodeTypeError` when the
    /// target node is a leaf node.
    fn unmerged_leaves(&self) -> Result<&[NodeIndex], Self::TreeSyncableError>;

    /// Get the parent hash value of this node.
    fn parent_hash(&self) -> &[u8];

    /// Get the tree hash value for the given node.
    fn tree_hash(&self) -> &[u8];

    /// Verify the signature on a given leaf node. Returns an `NodeTypeError` if
    /// called on a non-leaf node and a `NodeVerificationError` if the
    /// verification fails.
    fn verify(&self) -> Result<(), Self::TreeSyncableError>;
}

pub(crate) trait TreeSyncableMut<TreeSyncableError> {
    /// Set the tree hash value for the given node.
    /// This assuming that the node caches the tree hash.
    fn set_tree_hash(&mut self, tree_hash: Vec<u8>);

    /// Clear the list of unmerged leaves. Returns a `NodeTypeError` when the
    /// target node is a leaf node.
    fn clear_unmerged_leaves(&mut self) -> Result<(), TreeSyncableError>;

    /// Add a `NodeIndex` to the node's list of unmerged leaves.
    fn add_unmerged_leaf(&mut self, node_index: NodeIndex) -> Result<(), TreeSyncableError>;

    /// Set the parent hash value of this node.
    fn set_parent_hash(&mut self, parent_hash: Vec<u8>);
}

pub(crate) trait TreeSyncParent: TreeSyncable {
    /// Create a mutable copy of the TreeSyncable.
    fn to_mut(&self) -> Self::TreeSyncableMut;

    /// Make a mutable copy immutable.
    fn from_mut(mutable: Self::TreeSyncableMut) -> Self;
}

pub(crate) trait TreeSyncLeaf: VerifiedStruct<Self::UnverifiedLeaf> + TreeSyncable {
    type UnverifiedLeaf: Verifiable;
    type UnsignedLeaf: Signable;
    type SignedLeaf: SignedStruct<Self::UnsignedLeaf>;
}

// How to connenct UnsignedLeaf and TreeSyncableMut?
