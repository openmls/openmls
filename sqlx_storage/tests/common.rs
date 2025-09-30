use openmls_sqlx_storage::Codec;
use openmls_traits::storage::{CURRENT_VERSION, Entity, Key, traits};
use serde::{Deserialize, Serialize};

#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct TestGroupId(pub Vec<u8>);
impl Key<CURRENT_VERSION> for TestGroupId {}
impl traits::GroupId<CURRENT_VERSION> for TestGroupId {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
pub struct TestProposalRef(pub usize);
impl Key<CURRENT_VERSION> for TestProposalRef {}
impl Entity<CURRENT_VERSION> for TestProposalRef {}
impl traits::ProposalRef<CURRENT_VERSION> for TestProposalRef {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct TestProposal(pub Vec<u8>);
impl Entity<CURRENT_VERSION> for TestProposal {}
impl traits::QueuedProposal<CURRENT_VERSION> for TestProposal {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct TestBlob(pub Vec<u8>);
impl Entity<CURRENT_VERSION> for TestBlob {}
impl traits::TreeSync<CURRENT_VERSION> for TestBlob {}
impl traits::GroupContext<CURRENT_VERSION> for TestBlob {}
impl traits::InterimTranscriptHash<CURRENT_VERSION> for TestBlob {}
impl traits::ConfirmationTag<CURRENT_VERSION> for TestBlob {}
impl traits::GroupState<CURRENT_VERSION> for TestBlob {}
impl traits::GroupEpochSecrets<CURRENT_VERSION> for TestBlob {}
impl traits::MessageSecrets<CURRENT_VERSION> for TestBlob {}
impl traits::ResumptionPskStore<CURRENT_VERSION> for TestBlob {}
impl traits::MlsGroupJoinConfig<CURRENT_VERSION> for TestBlob {}
impl traits::LeafNode<CURRENT_VERSION> for TestBlob {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct TestLeafIndex(pub u32);
impl Entity<CURRENT_VERSION> for TestLeafIndex {}
impl traits::LeafNodeIndex<CURRENT_VERSION> for TestLeafIndex {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct TestSignaturePublicKey(pub Vec<u8>);
impl Key<CURRENT_VERSION> for TestSignaturePublicKey {}
impl traits::SignaturePublicKey<CURRENT_VERSION> for TestSignaturePublicKey {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct TestSignatureKeyPair(pub Vec<u8>);
impl Entity<CURRENT_VERSION> for TestSignatureKeyPair {}
impl traits::SignatureKeyPair<CURRENT_VERSION> for TestSignatureKeyPair {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct TestEncryptionKey(pub Vec<u8>);
impl Key<CURRENT_VERSION> for TestEncryptionKey {}
impl traits::EncryptionKey<CURRENT_VERSION> for TestEncryptionKey {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct TestHpkeKeyPair(pub Vec<u8>);
impl Entity<CURRENT_VERSION> for TestHpkeKeyPair {}
impl traits::HpkeKeyPair<CURRENT_VERSION> for TestHpkeKeyPair {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct TestEpochKey(pub Vec<u8>);
impl Key<CURRENT_VERSION> for TestEpochKey {}
impl traits::EpochKey<CURRENT_VERSION> for TestEpochKey {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct TestHashRef(pub Vec<u8>);
impl Key<CURRENT_VERSION> for TestHashRef {}
impl traits::HashReference<CURRENT_VERSION> for TestHashRef {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct TestKeyPackage(pub Vec<u8>);
impl Entity<CURRENT_VERSION> for TestKeyPackage {}
impl traits::KeyPackage<CURRENT_VERSION> for TestKeyPackage {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct TestPskId(pub Vec<u8>);
impl Key<CURRENT_VERSION> for TestPskId {}
impl traits::PskId<CURRENT_VERSION> for TestPskId {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct TestPskBundle(pub Vec<u8>);
impl Entity<CURRENT_VERSION> for TestPskBundle {}
impl traits::PskBundle<CURRENT_VERSION> for TestPskBundle {}
