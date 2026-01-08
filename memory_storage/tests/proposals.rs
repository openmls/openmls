use openmls_memory_storage::{MemoryStorageGuard, MemoryStorageManager};
use openmls_traits::storage::{
    traits::{self},
    Entity, Key, StorageProvider, CURRENT_VERSION,
};
use serde::{Deserialize, Serialize};

// Test types
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestGroupId(Vec<u8>);
impl traits::GroupId<CURRENT_VERSION> for TestGroupId {}
impl Key<CURRENT_VERSION> for TestGroupId {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
struct ProposalRef(usize);
impl traits::ProposalRef<CURRENT_VERSION> for ProposalRef {}
impl Key<CURRENT_VERSION> for ProposalRef {}
impl Entity<CURRENT_VERSION> for ProposalRef {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct Proposal(Vec<u8>);
impl traits::QueuedProposal<CURRENT_VERSION> for Proposal {}
impl Entity<CURRENT_VERSION> for Proposal {}

/// Write and read some proposals
#[tokio::test]
async fn read_write_delete() {
    use openmls_traits::storage::*;

    let group_id = TestGroupId(b"TestGroupId".to_vec());
    let proposals = (0..10)
        .map(|i| Proposal(format!("TestProposal{i}").as_bytes().to_vec()))
        .collect::<Vec<_>>();
    let storage_manager = MemoryStorageManager::default();
    let handle = storage_manager.get_handle(&group_id).unwrap();
    let storage = handle.lock().await;

    // Store proposals
    for (i, proposal) in proposals.iter().enumerate() {
        storage.queue_proposal(&ProposalRef(i), proposal).unwrap();
    }

    // Read proposal refs
    let proposal_refs_read: Vec<ProposalRef> = storage.queued_proposal_refs().unwrap();
    assert_eq!(
        (0..10).map(ProposalRef).collect::<Vec<_>>(),
        proposal_refs_read
    );

    // Read proposals
    let proposals_read: Vec<(ProposalRef, Proposal)> = storage.queued_proposals().unwrap();
    let proposals_expected: Vec<(ProposalRef, Proposal)> =
        (0..10).map(ProposalRef).zip(proposals.clone()).collect();
    assert_eq!(proposals_expected, proposals_read);

    // Remove proposal 5
    storage.remove_proposal(&ProposalRef(5)).unwrap();

    let proposal_refs_read: Vec<ProposalRef> = storage.queued_proposal_refs().unwrap();
    let mut expected = (0..10).map(ProposalRef).collect::<Vec<_>>();
    expected.remove(5);
    assert_eq!(expected, proposal_refs_read);

    let proposals_read: Vec<(ProposalRef, Proposal)> = storage.queued_proposals().unwrap();
    let mut proposals_expected: Vec<(ProposalRef, Proposal)> =
        (0..10).map(ProposalRef).zip(proposals.clone()).collect();
    proposals_expected.remove(5);
    assert_eq!(proposals_expected, proposals_read);

    // Clear all proposals
    storage.clear_proposal_queue::<ProposalRef>().unwrap();
    let proposal_refs_read: Vec<ProposalRef> = storage.queued_proposal_refs().unwrap();
    assert!(proposal_refs_read.is_empty());

    let proposals_read: Vec<(ProposalRef, Proposal)> = storage.queued_proposals().unwrap();
    assert!(proposals_read.is_empty());
}
