use crate::{
    ciphersuite::{
        signable::{Signable, SignedStruct, Verifiable, VerifiedStruct},
        Signature,
    },
    codec::CodecError,
};

use super::treesyncable::{TreeSyncLeaf, TreeSyncParent};

/// This is what the receiver receives from the wire.
pub(crate) struct UnverifiedTreeSyncUpdate<P: TreeSyncParent, L: TreeSyncLeaf> {
    unverified_leaf: L::UnverifiedLeaf,
    path: Vec<P>,
}

/// This is what treesync will accept for processing an update.
pub(crate) struct TreeSyncUpdate<P: TreeSyncParent, L: TreeSyncLeaf> {
    leaf: L,
    path: Vec<P>,
}

/// This is what treesync requires to prepare an update.
pub(crate) struct UnsignedTreeSyncUpdate<P: TreeSyncParent, L: TreeSyncLeaf> {
    unsigned_leaf: L::UnsignedLeaf,
    path: Vec<P>,
}

/// This is what create_update outputs and what goes over the wire to the
/// receiver.
pub(crate) struct SignedTreeSyncUpdate<P: TreeSyncParent, L: TreeSyncLeaf> {
    leaf: L::SignedLeaf,
    path: Vec<P>,
}

impl<P, L> Verifiable for UnverifiedTreeSyncUpdate<P, L>
where
    P: TreeSyncParent,
    L: TreeSyncLeaf,
{
    fn unsigned_payload(&self) -> Result<Vec<u8>, CodecError> {
        self.unverified_leaf.unsigned_payload()
    }

    fn signature(&self) -> &Signature {
        &self.unverified_leaf.signature()
    }
}

impl<P, L> VerifiedStruct<UnverifiedTreeSyncUpdate<P, L>> for TreeSyncUpdate<P, L>
where
    P: TreeSyncParent,
    L: TreeSyncLeaf,
{
    fn from_verifiable(verifiable: UnverifiedTreeSyncUpdate<P, L>) -> Self {
        Self {
            leaf: L::from_verifiable(verifiable.unverified_leaf),
            path: verifiable.path,
        }
    }
}

impl<P, L> Signable for UnsignedTreeSyncUpdate<P, L>
where
    P: TreeSyncParent,
    L: TreeSyncLeaf,
{
    type SignedOutput = SignedTreeSyncUpdate<P, L>;

    fn unsigned_payload(&self) -> Result<Vec<u8>, CodecError> {
        self.unsigned_leaf.unsigned_payload()
    }
}

impl<P, L> SignedStruct<UnsignedTreeSyncUpdate<P, L>> for SignedTreeSyncUpdate<P, L>
where
    P: TreeSyncParent,
    L: TreeSyncLeaf,
{
    fn from_payload(payload: UnsignedTreeSyncUpdate<P, L>, signature: Signature) -> Self {
        SignedTreeSyncUpdate {
            leaf: L::SignedLeaf::from_payload(payload.unsigned_leaf, signature),
            path: payload.path,
        }
    }
}
