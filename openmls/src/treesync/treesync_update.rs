use crate::ciphersuite::{
    signable::{Signable, SignedStruct, Verifiable},
    Signature,
};

use super::treesync_node::TreeSyncable;

pub(crate) struct TreeSyncUpdate<P: TreeSyncable, L: TreeSyncable + Verifiable + SignedStruct> {
    leaf_payload: L,
    signature: Signature,
    encoded: Vec<u8>,
    path: Vec<P>,
}

pub(crate) struct TreeSyncUpdatePayload<P: TreeSyncable, LP: TreeSyncable + Signable> {
    unsigned_leaf_node: LP,
    path: Vec<P>,
}

impl<P: TreeSyncable, L: TreeSyncable + Verifiable + SignedStruct, LP: TreeSyncable + Signable>
    Signable for TreeSyncUpdatePayload<P, LP>
{
    type SignedOutput = TreeSyncUpdate;

    fn unsigned_payload(&self) -> Result<Vec<u8>, crate::codec::CodecError> {
        self.leaf_node.encode_detached()
    }
}

impl<P, LP, L> SignedStruct<TreeSyncUpdatePayload<P, LP>> for TreeSyncUpdate<P, L>
where
    P: TreeSyncable,
    LP: TreeSyncable + Signable,
    L: TreeSyncable + Verifiable + SignedStruct,
{
    fn from_payload(payload: TreeSyncUpdatePayload<P, LP>, signature: Signature) -> Self {
        TreeSyncUpdate {
            leaf_payload: payload.unsigned_leaf_node,
            signature,
            encoded: payload.unsigned_payload().unwrap(),
            path: payload.path,
        }
    }
}

impl<P, L> Verifiable for TreeSyncUpdate<P, L>
where
    P: TreeSyncable,
    L: TreeSyncable + Verifiable + SignedStruct,
{
    fn unsigned_payload(&self) -> Result<Vec<u8>, crate::codec::CodecError> {
        Ok(self.leaf_payload.encoded.clone())
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }
}
