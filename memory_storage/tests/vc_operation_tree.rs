#![cfg(feature = "virtual-clients-draft")]

use openmls_memory_storage::MemoryStorage;
use openmls_traits::storage::{
    traits::{self},
    Entity, Key, StorageProvider, CURRENT_VERSION,
};
use serde::{Deserialize, Serialize};

// Test types
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestEpochId(Vec<u8>);
impl traits::VcEpochId<CURRENT_VERSION> for TestEpochId {}
impl Key<CURRENT_VERSION> for TestEpochId {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestOperationTree(Vec<u8>);
impl traits::VcOperationTree<CURRENT_VERSION> for TestOperationTree {}
impl Entity<CURRENT_VERSION> for TestOperationTree {}

/// Write, read back, overwrite, and delete an operation secret tree.
#[test]
fn operation_tree_read_write_delete() {
    let storage = MemoryStorage::default();
    let epoch_id = TestEpochId(b"TestEpochId".to_vec());

    // Nothing is stored initially.
    let read: Option<TestOperationTree> = storage.vc_operation_tree(&epoch_id).unwrap();
    assert_eq!(read, None);

    // Write and read back.
    let tree = TestOperationTree(b"TestOperationTree".to_vec());
    storage.write_vc_operation_tree(&epoch_id, &tree).unwrap();
    let read: Option<TestOperationTree> = storage.vc_operation_tree(&epoch_id).unwrap();
    assert_eq!(read, Some(tree));

    // A second write replaces the stored tree (write-back after a ratchet
    // advance).
    let advanced_tree = TestOperationTree(b"AdvancedOperationTree".to_vec());
    storage
        .write_vc_operation_tree(&epoch_id, &advanced_tree)
        .unwrap();
    let read: Option<TestOperationTree> = storage.vc_operation_tree(&epoch_id).unwrap();
    assert_eq!(read, Some(advanced_tree));

    // A different epoch id reads nothing.
    let other_epoch_id = TestEpochId(b"OtherEpochId".to_vec());
    let read: Option<TestOperationTree> = storage.vc_operation_tree(&other_epoch_id).unwrap();
    assert_eq!(read, None);

    // Deleting the emulation state removes the operation tree too.
    storage.delete_vc_emulation_state(&epoch_id).unwrap();
    let read: Option<TestOperationTree> = storage.vc_operation_tree(&epoch_id).unwrap();
    assert_eq!(read, None);
}
