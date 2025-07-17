use openmls_sqlite_storage::Codec;
use openmls_traits::storage::{
    traits::{self},
    Entity, Key, StorageProvider,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

// Test types
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestGroupId(Vec<u8>);
impl traits::GroupId<1> for TestGroupId {}
impl Key<1> for TestGroupId {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
struct ProposalRef(usize);
impl traits::ProposalRef<1> for ProposalRef {}
impl Key<1> for ProposalRef {}
impl Entity<1> for ProposalRef {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct Proposal(Vec<u8>);
impl traits::QueuedProposal<1> for Proposal {}
impl Entity<1> for Proposal {}

/// Write and read some proposals
#[test]
fn read_write_delete() {
    let group_id = TestGroupId(b"TestGroupId".to_vec());
    let proposals = (0..10)
        .map(|i| Proposal(format!("TestProposal{i}").as_bytes().to_vec()))
        .collect::<Vec<_>>();
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    let mut storage =
        openmls_sqlite_storage::SqliteStorageProvider::<JsonCodec, Connection>::new(connection);

    storage.run_migrations().unwrap();

    // Store proposals
    for (i, proposal) in proposals.iter().enumerate() {
        storage
            .queue_proposal(&group_id, &ProposalRef(i), proposal)
            .unwrap();
    }

    // Read proposal refs
    let proposal_refs_read: Vec<ProposalRef> = storage.queued_proposal_refs(&group_id).unwrap();
    assert_eq!(
        (0..10).map(ProposalRef).collect::<Vec<_>>(),
        proposal_refs_read
    );

    // Read proposals
    let proposals_read: Vec<(ProposalRef, Proposal)> = storage.queued_proposals(&group_id).unwrap();
    let proposals_expected: Vec<(ProposalRef, Proposal)> =
        (0..10).map(ProposalRef).zip(proposals.clone()).collect();
    assert_eq!(proposals_expected, proposals_read);

    // Remove proposal 5
    storage.remove_proposal(&group_id, &ProposalRef(5)).unwrap();

    let proposal_refs_read: Vec<ProposalRef> = storage.queued_proposal_refs(&group_id).unwrap();
    let mut expected = (0..10).map(ProposalRef).collect::<Vec<_>>();
    expected.remove(5);
    assert_eq!(expected, proposal_refs_read);

    let proposals_read: Vec<(ProposalRef, Proposal)> = storage.queued_proposals(&group_id).unwrap();
    let mut proposals_expected: Vec<(ProposalRef, Proposal)> =
        (0..10).map(ProposalRef).zip(proposals.clone()).collect();
    proposals_expected.remove(5);
    assert_eq!(proposals_expected, proposals_read);

    // Clear all proposals
    storage
        .clear_proposal_queue::<TestGroupId, ProposalRef>(&group_id)
        .unwrap();
    let proposal_refs_read: Vec<ProposalRef> = storage.queued_proposal_refs(&group_id).unwrap();
    assert!(proposal_refs_read.is_empty());

    let proposals_read: Vec<(ProposalRef, Proposal)> = storage.queued_proposals(&group_id).unwrap();
    assert!(proposals_read.is_empty());
}
