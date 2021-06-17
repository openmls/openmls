use crate::{
    ciphersuite::{
        signable::{Signable, SignedStruct, Verifiable, VerifiedStruct},
        Signature,
    },
    codec::CodecError,
};

use super::treesyncable::TreeSyncable;

/// This is what the receiver receives from the wire.
pub(crate) struct UnverifiedTreeSyncUpdate<P: TreeSyncable, UL: Verifiable> {
    unverified_leaf: UL,
    path: Vec<P>,
}

/// This is what treesync will accept for processing an update.
pub(crate) struct TreeSyncUpdate<
    P: TreeSyncable,
    UL: Verifiable,
    L: TreeSyncable + VerifiedStruct<UL>,
> {
    leaf: L,
    path: Vec<P>,
}

/// This is what treesync requires to prepare an update.
pub(crate) struct TreeSyncUpdatePayload<P: TreeSyncable, LP: Signable> {
    unsigned_leaf: LP,
    path: Vec<P>,
}

/// This is what create_update outputs and what goes over the wire to the
/// receiver.
pub(crate) struct SignedTreeSyncUpdate<P: TreeSyncable, LP: Signable, SL: SignedStruct<LP>> {
    leaf: SL,
    path: Vec<P>,
}

impl<P, UL> Verifiable for UnverifiedTreeSyncUpdate<P, UL>
where
    P: TreeSyncable,
    UL: Verifiable,
{
    fn unsigned_payload(&self) -> Result<Vec<u8>, CodecError> {
        Ok(self.leaf_payload.encoded.clone())
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl<P: TreeSyncable, LP: Signable, SL: SignedStruct<LP>> Signable
    for TreeSyncUpdatePayload<P, LP>
{
    type SignedOutput = SignedTreeSyncUpdate<P, LP, SL>;

    fn unsigned_payload(&self) -> Result<Vec<u8>, CodecError> {
        self.leaf_node.encode_detached()
    }
}

impl<P, LP, SL> SignedStruct<TreeSyncUpdatePayload<P, LP>> for SignedTreeSyncUpdate<P, LP, SL>
where
    P: TreeSyncable,
    LP: Signable,
    SL: SignedStruct<LP>,
{
    fn from_payload(payload: TreeSyncUpdatePayload<P, LP>, signature: Signature) -> Self {
        SignedTreeSyncUpdate {
            leaf: payload.unsigned_leaf,
            path: payload.path,
        }
    }
}
